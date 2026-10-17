"""Native, persistent FSEvents replay. No daemon or application event log."""
import os
from pathlib import Path
import threading
import time
from .safety import SafetyError, clean, within

class NativeEvents:
    def __init__(self, root, since=0, exclusions=()):
        self.root, self.since = str(root), int(since)
        self.exclusions = tuple(str(path) for path in exclusions)
        self.lock = threading.Lock()
        self.ready, self.history_done, self.stop = threading.Event(), threading.Event(), threading.Event()
        self.paths, self.issues = set(), []
        self.stream = None
        self.latest = self.since
        self.thread = threading.Thread(target=self._run, name='mactrim-fsevents', daemon=True)

    def __enter__(self):
        self.thread.start()
        if not self.ready.wait(5) or self.issues or not self.stream:
            self.__exit__(None, None, None)
            raise SafetyError('Native FSEvents unavailable: ' + '; '.join(self.issues))
        if not self.history_done.wait(5):
            self.__exit__(None, None, None)
            raise SafetyError('Native FSEvents replay did not establish HistoryDone')
        return self

    def _run(self):
        try:
            import FSEvents as F
            import CoreFoundation as C
            loss = (F.kFSEventStreamEventFlagMustScanSubDirs | F.kFSEventStreamEventFlagUserDropped |
                    F.kFSEventStreamEventFlagKernelDropped | F.kFSEventStreamEventFlagEventIdsWrapped |
                    F.kFSEventStreamEventFlagRootChanged | F.kFSEventStreamEventFlagMount |
                    F.kFSEventStreamEventFlagUnmount)
            def callback(stream, info, count, paths, flags, ids):
                with self.lock:
                    for path, flag, event_id in zip(paths, flags, ids):
                        self.latest = max(self.latest, int(event_id))
                        if flag & F.kFSEventStreamEventFlagHistoryDone:
                            self.history_done.set()
                            continue
                        if flag & loss:
                            if len(self.issues) < 16:
                                self.issues.append('FSEvents continuity lost (flags %s); full reconciliation required' % flag)
                            continue
                        path = str(Path(path))
                        if not within(path, self.root):
                            if len(self.issues) < 16:
                                self.issues.append('FSEvents path escaped watched scope')
                            continue
                        if any(within(path, excluded) for excluded in self.exclusions):
                            continue
                        # Directory events include its direct content; file events
                        # invalidate their parent. Never infer changes from mtimes.
                        dirty = path if flag & F.kFSEventStreamEventFlagItemIsDir else str(Path(path).parent)
                        if flag & (F.kFSEventStreamEventFlagItemCreated | F.kFSEventStreamEventFlagItemRemoved | F.kFSEventStreamEventFlagItemRenamed):
                            self.paths.add(str(Path(path).parent))
                        if len(self.paths) >= 50000:
                            if len(self.issues) < 16:
                                self.issues.append('Dirty-region memory bound exceeded; full reconciliation required')
                            self.paths.clear()
                        elif not self.issues:
                            self.paths.add(dirty)
            flags = (F.kFSEventStreamCreateFlagUseCFTypes | F.kFSEventStreamCreateFlagFileEvents |
                     F.kFSEventStreamCreateFlagWatchRoot | F.kFSEventStreamCreateFlagNoDefer)
            self.stream = F.FSEventStreamCreate(None, callback, None, [self.root], self.since, .1, flags)
            if not self.stream:
                raise SafetyError('Cannot create FSEvents stream')
            F.FSEventStreamScheduleWithRunLoop(self.stream, C.CFRunLoopGetCurrent(), C.kCFRunLoopDefaultMode)
            if not F.FSEventStreamStart(self.stream):
                raise SafetyError('Cannot start FSEvents stream')
            self.ready.set()
            while not self.stop.is_set():
                C.CFRunLoopRunInMode(C.kCFRunLoopDefaultMode, .05, False)
        except Exception as exc:
            self.issues.append(clean(exc))
            self.ready.set()
        finally:
            if self.stream:
                F.FSEventStreamStop(self.stream)
                F.FSEventStreamInvalidate(self.stream)
                F.FSEventStreamRelease(self.stream)
                self.stream = None

    def drain(self):
        import FSEvents as F
        # Run loop is on a dedicated thread. FlushSync waits for delivery there;
        # it is never invoked from the stream's own callback/run-loop thread.
        # Filesystem notifications can still be in the kernel's batching
        # window when historical replay reports HistoryDone. Allow that window
        # to reach this live stream before flushing; HistoryDone alone is not
        # evidence that a just-written existing file is unchanged. This remains
        # an interval observation, not an atomic filesystem snapshot.
        self.stop.wait(1.1)
        F.FSEventStreamFlushSync(self.stream)
        with self.lock:
            paths, issues, latest = set(self.paths), list(self.issues), self.latest
            self.paths.clear()
            return paths, issues, latest

    def __exit__(self, *args):
        self.stop.set()
        self.thread.join(5)
        if self.thread.is_alive():
            raise SafetyError('FSEvents worker did not stop; cache checkpoint not trusted')

def current_id():
    import FSEvents
    return int(FSEvents.FSEventsGetCurrentEventId())
