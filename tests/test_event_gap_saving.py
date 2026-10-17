import copy
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from mactrim.config import defaults
from mactrim.events import NativeEvents
from mactrim.incremental import inventory
from mactrim.state import State
from mactrim.storage import complete
from mactrim.storage_cache import Cache


try:
    import FSEvents as F
except ImportError:
    F = None


@unittest.skipIf(F is None, 'Native events require the isolated macOS project environment')
class BatchTests(unittest.TestCase):
    def test_drop_is_consumed_once_and_next_events_are_recorded(self):
        import FSEvents as F
        events = NativeEvents('/fixture', 10)
        events.stream = object()
        events._record(['/fixture'], [F.kFSEventStreamEventFlagMustScanSubDirs | F.kFSEventStreamEventFlagUserDropped], [11])
        events._record(['/fixture/changed/file'], [F.kFSEventStreamEventFlagItemIsFile], [12])
        with patch.object(events.stop, 'wait'), patch.object(F, 'FSEventStreamFlushSync'):
            paths, lost, _ = events.drain()
            self.assertTrue(lost)
            self.assertEqual(paths, {'/fixture/changed'})
            events._record(['/fixture/later/file'], [F.kFSEventStreamEventFlagItemIsFile], [13])
            paths, lost, _ = events.drain()
            self.assertFalse(lost)
            self.assertEqual(paths, {'/fixture/later'})

    def test_historical_drop_during_startup_does_not_abort_live_stream(self):
        import FSEvents as F
        events = NativeEvents('/fixture', 10)
        events.stream = object()
        events.ready.set(); events.history_done.set()
        events._record(['/fixture'], [F.kFSEventStreamEventFlagMustScanSubDirs | F.kFSEventStreamEventFlagUserDropped], [11])
        with patch.object(events.thread, 'start'):
            self.assertIs(events.__enter__(), events)
        self.assertTrue(events.issues)  # first drain must still require full repair
        self.assertIsNone(events.failure)

    def test_coalescing_requires_named_subtree_without_poisoning_stream(self):
        import FSEvents as F
        events = NativeEvents('/fixture', 10)
        events._record(['/fixture/coalesced'], [F.kFSEventStreamEventFlagMustScanSubDirs], [11])
        self.assertEqual(events.paths, {'/fixture/coalesced'})
        self.assertEqual(events.issues, [])


class GapSavingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.data = self.root / 'data'; self.data.mkdir()
        (self.data / 'child').mkdir()
        (self.data / 'child' / 'file').write_bytes(b'first')
        self.state = State(self.root / 'state').prepare()
        self.config = defaults()
        self.identity = patch('mactrim.incremental.volume_identity', return_value=[1, 2, 'fixture'])
        self.identity.start()
        self.ids = patch('mactrim.events.current_id', return_value=100)
        self.ids.start()

    def tearDown(self):
        self.ids.stop(); self.identity.stop(); self.temporary.cleanup()

    def scan(self, batches=(), **kwargs):
        class Events:
            def __init__(self, *args): self.batches = iter(copy.deepcopy(batches))
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def drain(self): return next(self.batches, (set(), [], 100))
        return inventory(self.data, self.state, self.config, backend=Events, **kwargs)

    def cache(self):
        return Cache(self.state, self.config['storage_cache']).read()

    def test_historical_loss_is_repaired_by_full_walk_then_incremental_reuses(self):
        first = self.scan([(set(), ['historical drop'], 100)])
        self.assertEqual(first.status, 'measured')
        self.assertTrue(first.refresh['cache']['stored'])
        self.assertTrue(first.refresh['cache']['reusable'])
        self.assertTrue(self.cache()[0]['reuse_allowed'])
        quiet = self.scan()
        self.assertEqual(quiet.refresh['mode'], 'incremental')
        self.assertGreater(quiet.counters['reused'], 0)
        (self.data / 'child' / 'file').write_bytes(b'changed payload')
        changed = self.scan([({str(self.data / 'child')}, [], 100)])
        self.assertEqual(changed.logical, complete(self.data).logical)

    def test_loss_during_walk_saves_observation_without_reusing_it(self):
        initial = self.scan()
        before = self.cache()[0]['created_at']
        observed = self.scan([(set(), [], 100), (set(), ['live drop'], 100),
                              (set(), ['repeated drop'], 100)], full=True)
        self.assertEqual(observed.status, 'partial')
        self.assertTrue(observed.refresh['cache']['stored'])
        self.assertFalse(observed.refresh['cache']['reusable'])
        body, root, nodes = self.cache()
        self.assertGreaterEqual(body['created_at'], before)
        self.assertFalse(body['reuse_allowed'])
        self.assertIsNone(body['volume'][2])
        self.assertEqual(root.logical, observed.logical)
        self.assertEqual(len(nodes), 2)
        repaired = self.scan()
        self.assertEqual(repaired.refresh['mode'], 'full')
        self.assertEqual(repaired.counters['reused'], 0)
        self.assertTrue(repaired.refresh['cache']['reusable'])
        self.assertEqual(self.scan().refresh['mode'], 'incremental')

    def test_unavailable_backend_saves_totals_without_claiming_replay_continuity(self):
        class Unavailable:
            def __init__(self, *args): pass
            def __enter__(self): raise OSError('native unavailable')
            def __exit__(self, *args): pass
        result = inventory(self.data, self.state, self.config, backend=Unavailable)
        self.assertEqual(result.logical, complete(self.data).logical)
        self.assertTrue(result.refresh['cache']['stored'])
        self.assertFalse(result.refresh['cache']['reusable'])
        self.assertFalse(self.cache()[0]['reuse_allowed'])

    def test_missing_volume_event_identity_still_saves_explicit_nonreusable_observation(self):
        with patch('mactrim.incremental.volume_identity', side_effect=OSError('volume identity unavailable')):
            observed = self.scan()
        self.assertTrue(observed.refresh['cache']['stored'])
        self.assertFalse(observed.refresh['cache']['reusable'])
        self.assertEqual(self.cache()[0]['checkpoint'], 0)
        self.assertIsNone(self.cache()[0]['volume'][2])

    def test_cancel_does_not_overwrite_saved_observation(self):
        self.scan()
        path = self.state.path / 'storage-cache' / 'index.json.gz'
        before = path.read_bytes()
        cancel = threading.Event()
        def progress(node, _):
            if node.progress['phase'] == 'Saving directory index': cancel.set()
        result = self.scan(cancel=cancel, progress=progress, full=True)
        self.assertEqual(result.status, 'cancelled')
        self.assertFalse(result.refresh['cache']['stored'])
        self.assertEqual(path.read_bytes(), before)
