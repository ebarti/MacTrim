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
