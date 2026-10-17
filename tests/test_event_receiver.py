import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from mactrim.events import EventCollector, NativeEvents
from mactrim.regions import Cancelled
from mactrim.safety import SafetyError


class ReceiverQueueTests(unittest.TestCase):
    def test_callback_defers_path_processing(self):
        collector = EventCollector('/fixture')
        with patch('mactrim.events.within', side_effect=AssertionError('callback normalized path')):
            collector._record(['/fixture/child'], [0], [42])
        self.assertFalse(collector.paths)
        collector._process_pending()
        self.assertEqual(collector.paths, {'/fixture/child'})
        self.assertEqual(collector.diagnostics['events'], 1)

    def test_pending_pressure_coarsens_without_losing_invalidation(self):
        collector = EventCollector('/fixture')
        with patch('mactrim.events.PENDING_BYTES', 256):
            collector._record(['/fixture/a'], [0], [1])
            collector._record(['/fixture/b'], [0], [2])
        collector._process_pending()
        self.assertEqual(collector.paths, {'/fixture'})
        self.assertFalse(collector.issues)
        self.assertEqual(collector.latest, 2)
        self.assertEqual(collector.diagnostics['coarsened_batches'], 1)

    def test_coarsening_preserves_drop_and_history_sentinel(self):
        collector = EventCollector('/fixture')
        with patch('mactrim.events.PENDING_BYTES', 256):
            collector._record(['/fixture/a'], [3], [1])
            collector._record(['/fixture/b'], [16], [2])
        collector._process_pending()
        self.assertTrue(collector.history_done.is_set())
        self.assertTrue(collector.issues)
        self.assertTrue(collector.diagnostics['last_drop_flags'] & 2)

    def test_dirty_pressure_coarsens_instead_of_discarding(self):
        collector = EventCollector('/fixture')
        with patch('mactrim.events.DIRTY_BYTES', 256):
            collector._record(['/fixture/a', '/fixture/b'], [0, 0], [1, 2])
            collector._process_pending()
        self.assertEqual(collector.paths, {'/fixture'})
        self.assertFalse(collector.issues)
        self.assertEqual(collector.diagnostics['coarsened_regions'], 1)

    def test_excluded_paths_filtered_outside_callback(self):
        collector = EventCollector('/fixture', exclusions=['/fixture/state'])
        collector._record(['/fixture/state', '/fixture/data'], [0, 0], [1, 2])
        collector._process_pending()
        self.assertEqual(collector.paths, {'/fixture/data'})


@unittest.skipUnless(sys.platform == 'darwin', 'native macOS FSEvents')
class IsolatedNativeTests(unittest.TestCase):
    def test_native_process_detects_in_place_file_edit_and_exits(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            child = root / 'child'; child.mkdir()
            file = child / 'file'; file.write_bytes(b'original')
            from mactrim.events import current_id
            with NativeEvents(root, current_id()) as receiver:
                receiver.drain()
                before = child.stat().st_mtime_ns
                file.write_bytes(b'changed')
                paths, issues, latest = receiver.drain()
                self.assertEqual(child.stat().st_mtime_ns, before)
                self.assertIn(str(child), paths)
                self.assertFalse(issues)
                self.assertNotEqual(receiver.diagnostics['receiver_pid'], os.getpid())
                self.assertEqual(receiver.diagnostics['latency_seconds'], 1.0)
                self.assertGreater(receiver.diagnostics['callbacks'], 0)
                process = receiver.process
            self.assertIsNotNone(process.poll())

    def test_dead_receiver_is_reported_and_reaped(self):
        from mactrim.events import current_id
        with tempfile.TemporaryDirectory() as temporary:
            with NativeEvents(Path(temporary).resolve(), current_id()) as receiver:
                receiver.process.kill(); receiver.process.wait(timeout=2)
                with self.assertRaises(SafetyError): receiver.drain()
            self.assertIsNotNone(receiver.process.poll())

    def test_cancel_interrupts_waiting_request_and_reaps_receiver(self):
        from mactrim.events import current_id
        with tempfile.TemporaryDirectory() as temporary:
            with NativeEvents(Path(temporary).resolve(), current_id()) as receiver:
                receiver.cancel = threading.Event(); receiver.cancel.set()
                with self.assertRaises(Cancelled): receiver.drain()
            self.assertIsNotNone(receiver.process.poll())

    def test_parent_pipe_closure_stops_helper(self):
        from mactrim.events import current_id
        process = subprocess.Popen([sys.executable, '-m', 'mactrim.event_receiver'], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            with tempfile.TemporaryDirectory() as temporary:
                process.stdin.write(json.dumps({'root': str(Path(temporary).resolve()), 'since': current_id(), 'exclusions': []}).encode()+b'\n')
                process.stdin.flush()
                self.assertTrue(json.loads(process.stdout.readline())['ready'])
                process.stdin.close()
                self.assertEqual(process.wait(timeout=5), 0)
        finally:
            if process.poll() is None: process.kill(); process.wait()
            for stream in (process.stdout, process.stderr): stream.close()

class ProtocolDeadlineTests(unittest.TestCase):
    def test_partial_response_cannot_block_past_deadline(self):
        receiver = NativeEvents('/fixture')
        receiver.process = subprocess.Popen([sys.executable, '-c',
            "import sys,time; sys.stdin.buffer.readline(); sys.stdout.write('{'); sys.stdout.flush(); time.sleep(30)"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        try:
            with self.assertRaisesRegex(SafetyError, 'timed out'):
                receiver._request({'command': 'drain'}, timeout=.1)
        finally:
            receiver.__exit__()
        self.assertIsNotNone(receiver.process.poll())

    def test_cancel_interrupts_an_in_flight_response(self):
        receiver = NativeEvents('/fixture')
        receiver.process = subprocess.Popen([sys.executable, '-c',
            'import sys,time; sys.stdin.buffer.readline(); time.sleep(30)'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, bufsize=0)
        receiver.cancel = threading.Event()
        timer = threading.Timer(.1, receiver.cancel.set)
        timer.start()
        try:
            with self.assertRaises(Cancelled): receiver._request({'command': 'drain'})
        finally:
            timer.cancel(); receiver.__exit__()
        self.assertIsNotNone(receiver.process.poll())

    def test_actual_receiver_death_after_measurement_preserves_saved_tree(self):
        if sys.platform != 'darwin': self.skipTest('native macOS FSEvents')
        from mactrim.incremental import inventory
        from mactrim.config import defaults
        from mactrim.state import State
        from mactrim.storage import complete
        from mactrim.storage_cache import Cache
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            data = root / 'data'; data.mkdir()
            (data / 'file').write_bytes(b'saved measurement')
            state = State(root / 'state').prepare()
            receiver = None
            def backend(*args):
                nonlocal receiver
                receiver = NativeEvents(*args)
                return receiver
            def progress(snapshot, _):
                if snapshot.progress['phase'] == 'Checking filesystem events':
                    receiver.process.kill(); receiver.process.wait(timeout=2)
            with patch('mactrim.incremental.complete', wraps=complete) as walker:
                observed = inventory(data, state, defaults(), backend=backend, progress=progress)
            self.assertEqual(walker.call_count, 1)
            self.assertEqual(observed.logical, complete(data).logical)
            self.assertEqual(observed.status, 'partial')
            self.assertTrue(observed.refresh['cache']['stored'])
            self.assertFalse(observed.refresh['cache']['reusable'])
            self.assertEqual(Cache(state, defaults()['storage_cache']).read()[1].logical, observed.logical)
            self.assertIsNotNone(receiver.process.poll())

    def test_eof_reaps_helper_even_when_native_drain_stalls(self):
        program = '''
import sys,time
import mactrim.event_receiver as receiver
class Stalled:
    diagnostics = {}
    def __init__(self,*args): pass
    def __enter__(self): return self
    def __exit__(self,*args): pass
    def drain(self):
        print('draining', flush=True)
        time.sleep(30)
receiver.EventCollector = Stalled
raise SystemExit(receiver.main())
'''
        process = subprocess.Popen([sys.executable, '-c', program], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            process.stdin.write(b'{"root":"/fixture","since":1,"exclusions":[]}\n'); process.stdin.flush()
            self.assertTrue(json.loads(process.stdout.readline())['ready'])
            process.stdin.write(b'{"command":"drain"}\n'); process.stdin.flush()
            self.assertEqual(process.stdout.readline().strip(), b'draining')
            process.stdin.close()
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            if process.poll() is None: process.kill(); process.wait()
            for stream in (process.stdout, process.stderr): stream.close()
