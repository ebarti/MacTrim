"""Isolated native FSEvents reception with bounded, lossless invalidation."""
from collections import deque
import json
import os
from pathlib import Path
import select
import subprocess
import sys
import threading
import time

from .regions import check_cancel
from .safety import SafetyError, clean, within

# At most one second of delivery delay is acceptable for interval-based storage
# measurements. Explicit drains settle this window before flushing the stream.
DELIVERY_LATENCY = 1.0
# Memory allowances, not scan limits. Coarsening to the watched root retains
# every required invalidation instead of silently losing paths at these bounds.
PENDING_BYTES = 2 * 1024 * 1024
DIRTY_BYTES = 2 * 1024 * 1024
LOSS_FLAGS = 2 | 4 | 8 | 32 | 64 | 128  # SDK User/KernelDropped, wrapped, root, mounts
HISTORY_DONE = 16


class EventCollector:
    """Child-only collector. The native callback does no path processing or IO."""
    def __init__(self, root, since=0, exclusions=()):
        self.root, self.since = str(root), int(since)
        self.exclusions = tuple(str(path) for path in exclusions)
        self.lock, self.processing = threading.Lock(), threading.Lock()
        self.ready, self.history_done, self.stop = threading.Event(), threading.Event(), threading.Event()
        self.pending_ready = threading.Event()
        self.pending, self.pending_bytes = deque(), 0
        self.paths, self.issues, self.dirty_bytes = set(), [], 0
        self.failure, self.stream = None, None
        self.latest = self.since
        self.diagnostics = dict(callbacks=0, events=0, callback_max_ms=0.0,
                                pending_peak_bytes=0, dirty_peak_regions=0,
                                coarsened_batches=0, coarsened_regions=0,
                                drop_signals=0, last_drop_flags=0,
                                latency_seconds=DELIVERY_LATENCY)
        self.thread = threading.Thread(target=self._run, name='mactrim-fsevents', daemon=True)
        self.processor = threading.Thread(target=self._process_loop, name='mactrim-event-processing', daemon=True)

    def __enter__(self):
        self.processor.start()
        self.thread.start()
        if not self.ready.wait(5) or self.failure or not self.stream:
            self.__exit__(None, None, None)
            raise SafetyError('Native FSEvents unavailable: ' + '; '.join(self.issues))
        if not self.history_done.wait(5) or self.failure:
            self.__exit__(None, None, None)
            raise SafetyError('Native FSEvents replay did not establish HistoryDone')
        return self

    def _run(self):
        try:
            import FSEvents as F
            import CoreFoundation as C
            def callback(stream, info, count, paths, flags, ids):
                self._record(paths, flags, ids)
            flags = F.kFSEventStreamCreateFlagUseCFTypes | F.kFSEventStreamCreateFlagWatchRoot
            self.stream = F.FSEventStreamCreate(None, callback, None, [self.root], self.since,
                                               DELIVERY_LATENCY, flags)
            if not self.stream:
                raise SafetyError('Cannot create FSEvents stream')
            F.FSEventStreamScheduleWithRunLoop(self.stream, C.CFRunLoopGetCurrent(), C.kCFRunLoopDefaultMode)
            if not F.FSEventStreamStart(self.stream):
                raise SafetyError('Cannot start FSEvents stream')
            self.ready.set()
            while not self.stop.is_set():
                C.CFRunLoopRunInMode(C.kCFRunLoopDefaultMode, .05, False)
        except Exception as exc:
            self.failure = clean(exc)
            self.issues.append(self.failure)
            self.ready.set()
        finally:
            if self.stream:
                F.FSEventStreamStop(self.stream)
                F.FSEventStreamInvalidate(self.stream)
                F.FSEventStreamRelease(self.stream)
                self.stream = None

    def _record(self, paths, flags, ids):
        started = time.monotonic()
        # Copy callback-owned arrays before returning; defer normalization,
        # exclusions, invalidation and diagnostics interpretation to processor.
        paths, flags, ids = tuple(paths), tuple(flags), tuple(ids)
        size = sum(len(path) * 4 + 128 for path in paths)
        with self.lock:
            self.diagnostics['callbacks'] += 1
            self.diagnostics['events'] += len(paths)
            if self.pending_bytes + size > PENDING_BYTES:
                # Preserve control/loss flags and highest ID when collapsing
                # queued batches, including a historical replay sentinel.
                combined, latest = 0, self.latest
                for batch in (*self.pending, (paths, flags, ids)):
                    for flag in batch[1]: combined |= flag
                    latest = max(latest, max(batch[2], default=latest))
                self.pending.clear()
                paths, flags, ids = (self.root,), (combined | 1,), (latest,)
                size = len(self.root) * 4 + 128
                self.pending_bytes = 0
                self.diagnostics['coarsened_batches'] += 1
            self.pending.append((paths, flags, ids))
            self.pending_bytes += size
            self.diagnostics['pending_peak_bytes'] = max(self.diagnostics['pending_peak_bytes'], self.pending_bytes)
            self.diagnostics['callback_max_ms'] = max(self.diagnostics['callback_max_ms'], (time.monotonic() - started) * 1000)
        self.pending_ready.set()

    def _process_loop(self):
        try:
            while not self.stop.is_set():
                self.pending_ready.wait(.1)
                self._process_pending()
        except Exception as exc:
            self.failure = clean(exc)
            self.ready.set()
            self.history_done.set()

    def _process_pending(self):
        with self.processing:
            with self.lock:
                batches = self.pending
                self.pending, self.pending_bytes = deque(), 0
                self.pending_ready.clear()
            for paths, flags, ids in batches:
                for path, flag, event_id in zip(paths, flags, ids):
                    with self.lock:
                        self.latest = max(self.latest, int(event_id))
                        if flag & HISTORY_DONE:
                            self.history_done.set()
                        if flag & LOSS_FLAGS:
                            self.diagnostics['drop_signals'] += 1
                            self.diagnostics['last_drop_flags'] = int(flag)
                            if len(self.issues) < 16:
                                self.issues.append('FSEvents continuity lost (flags %s); full reconciliation required' % flag)
                            continue
                    # A coarsened batch can include both a sentinel and changes.
                    if flag == HISTORY_DONE:
                        continue
                    path = str(Path(path))
                    if not within(path, self.root):
                        with self.lock:
                            if len(self.issues) < 16: self.issues.append('FSEvents path escaped watched scope')
                        continue
                    if any(within(path, excluded) for excluded in self.exclusions):
                        continue
                    # Ordinary directory events have flag 0. File item flags
                    # remain understood for API/test compatibility.
                    directory = not flag & (0x10000 | 0x40000) or bool(flag & (0x20000 | 1))
                    dirty = path if directory else str(Path(path).parent)
                    with self.lock:
                        self._add_dirty(dirty)
                        if flag & (0x100 | 0x200 | 0x800): self._add_dirty(str(Path(path).parent))

    def _add_dirty(self, path):
        if self.root in self.paths or path in self.paths:
            return
        self.paths.add(path)
        self.dirty_bytes += len(path) * 4 + 128
        if self.dirty_bytes > DIRTY_BYTES:
            self.paths = {self.root}
            self.dirty_bytes = len(self.root) * 4 + 128
            self.diagnostics['coarsened_regions'] += 1
        self.diagnostics['dirty_peak_regions'] = max(self.diagnostics['dirty_peak_regions'], len(self.paths))

    def drain(self):
        import FSEvents as F
        if self.failure or self.stream is None:
            raise SafetyError('Native FSEvents stream unavailable: ' + (self.failure or 'stream stopped'))
        self.stop.wait(DELIVERY_LATENCY + .1)
        F.FSEventStreamFlushSync(self.stream)
        self._process_pending()
        if self.failure:
            raise SafetyError('Native event processing failed: ' + self.failure)
        with self.lock:
            paths, issues, latest = self.paths, self.issues, self.latest
            self.paths, self.issues, self.dirty_bytes = set(), [], 0
            self.diagnostics['pending_regions'] = len(paths)
            return paths, issues, latest

    def __exit__(self, *args):
        self.stop.set(); self.pending_ready.set()
        for thread in (self.thread, self.processor):
            if thread.ident is not None: thread.join(2)
        if self.thread.is_alive() or self.processor.is_alive():
            raise SafetyError('FSEvents worker did not stop; cache checkpoint not trusted')


class NativeEvents:
    """Scan-facing process client. No interpreter/GIL shared with reception."""
    def __init__(self, root, since=0, exclusions=()):
        self.root, self.since, self.exclusions = str(root), int(since), tuple(map(str, exclusions))
        self.process, self.cancel = None, None
        self.diagnostics, self.buffer = {}, bytearray()

    def _request(self, message, timeout=15):
        check_cancel(self.cancel)
        try:
            payload = json.dumps(message).encode() + b'\n'
            offset = 0
            while offset < len(payload):
                offset += self.process.stdin.write(payload[offset:])
            self.process.stdin.flush()
            deadline = time.monotonic() + timeout
            while b'\n' not in self.buffer:
                check_cancel(self.cancel)
                if time.monotonic() >= deadline:
                    raise SafetyError('Native event receiver response timed out')
                if select.select([self.process.stdout], [], [], .1)[0]:
                    chunk = os.read(self.process.stdout.fileno(), 65536)
                    if not chunk: raise SafetyError('Native event receiver exited before responding')
                    self.buffer.extend(chunk)
                    if len(self.buffer) > 16 * 1024 * 1024:
                        raise SafetyError('Native event receiver response exceeded memory allowance')
            line, _, rest = self.buffer.partition(b'\n')
            self.buffer = bytearray(rest)
            response = json.loads(line)
            if not isinstance(response, dict):
                raise SafetyError('Malformed native event receiver response')
            self.diagnostics = response.get('diagnostics', self.diagnostics)
            if 'error' in response: raise SafetyError(response['error'])
            return response
        except (OSError, ValueError) as exc:
            raise SafetyError('Native event receiver communication failed: ' + clean(exc)) from exc

    def __enter__(self):
        if getattr(sys, 'frozen', False):
            command = [sys.executable, '--mactrim-event-receiver']
        else:
            command = [sys.executable, '-m', 'mactrim.event_receiver']
        try:
            self.process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                            stderr=subprocess.DEVNULL, bufsize=0, close_fds=True)
            self._request({'root': self.root, 'since': self.since, 'exclusions': self.exclusions})
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def drain(self):
        response = self._request({'command': 'drain'})
        if (not isinstance(response.get('paths'), list) or not all(isinstance(path, str) for path in response['paths']) or
                not isinstance(response.get('issues'), list) or not all(isinstance(issue, str) for issue in response['issues']) or
                type(response.get('latest')) is not int):
            raise SafetyError('Malformed native event receiver drain')
        return set(response['paths']), response['issues'], response['latest']

    def __exit__(self, *args):
        if self.process is None: return
        # EOF tells the helper to stop; deadlines ensure cancellation never
        # waits forever on a stalled OS flush or native run loop.
        self.process.stdin.close()
        try:
            self.process.wait(timeout=.5)
        except subprocess.TimeoutExpired:
            self.process.terminate()
            try: self.process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait(timeout=2)
        finally:
            self.process.stdout.close()


def current_id():
    import FSEvents
    return int(FSEvents.FSEventsGetCurrentEventId())
