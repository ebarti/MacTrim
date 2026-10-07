import copy
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from mactrim.config import defaults
from mactrim.incremental import inventory
from mactrim.state import State
from mactrim.storage import complete
from mactrim.storage_cache import Cache


class JournalReplayTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.data = self.root / 'data'; self.data.mkdir()
        for name in ('hot', 'quiet'):
            (self.data / name).mkdir()
            (self.data / name / 'file').write_bytes(b'original')
        self.state = State(self.root / 'state').prepare()
        self.config = defaults()
        self.event_id = 100
        self.active = 0
        self.starts = []
        self.identity = patch('mactrim.incremental.volume_identity', return_value=[1, 2, 'fixture'])
        self.ids = patch('mactrim.events.current_id', side_effect=lambda: self.event_id)
        self.identity.start(); self.ids.start()

    def tearDown(self):
        self.ids.stop(); self.identity.stop(); self.temporary.cleanup()

    def scan(self, batches=(), **kwargs):
        batches = iter(copy.deepcopy(batches))
        owner = self
        class Journal:
            def __init__(self, root, since, exclusions):
                owner.starts.append(since)
            def __enter__(self):
                owner.active += 1
                return self
            def __exit__(self, *args): owner.active -= 1
            def drain(self):
                batch = next(batches, (set(), [], owner.event_id))
                owner.event_id = max(owner.event_id, batch[2])
                return batch
        return inventory(self.data, self.state, self.config, backend=Journal, **kwargs)

    def test_no_receiver_runs_during_any_metadata_walk(self):
        original = complete
        def walk(*args, **kwargs):
            self.assertEqual(self.active, 0, 'journal receiver left open while scanning')
            return original(*args, **kwargs)
        with patch('mactrim.incremental.complete', side_effect=walk):
            first = self.scan([({str(self.data / 'hot')}, [], 101)])
            quiet = self.scan()
        self.assertEqual(first.status, 'measured')
        self.assertGreater(quiet.counters['reused'], 0)

    def test_fresh_replay_recovers_drop_before_repeating_full_scan(self):
        with patch('mactrim.incremental.complete', wraps=complete) as walker:
            observed = self.scan([(set(), ['UserDropped'], 110), (set(), [], 111)])
        self.assertEqual(walker.call_count, 1)
        self.assertEqual(self.starts, [100, 100])
        self.assertEqual(observed.status, 'measured')
        self.assertTrue(observed.refresh['cache']['reusable'])
        self.assertEqual(observed.refresh['events']['recovered_replays'], 1)

    def test_remeasurement_replaces_size_even_if_initial_walk_saw_change(self):
        (self.data / 'hot' / 'file').write_bytes(b'x' * 12000)
        observed = self.scan([({str(self.data / 'hot')}, [], 101)])
        expected = complete(self.data)
        self.assertEqual((observed.logical, observed.allocated, observed.entries),
                         (expected.logical, expected.allocated, expected.entries))
        self.assertTrue(observed.refresh['cache']['reusable'])

    def test_edit_after_baseline_is_recovered_from_history(self):
        changed = False
        original = complete
        def walk(*args, **kwargs):
            nonlocal changed
            result = original(*args, **kwargs)
            if not changed:
                (self.data / 'hot' / 'file').write_bytes(b'x' * 12000)
                self.event_id = 120
                changed = True
            return result
        with patch('mactrim.incremental.complete', side_effect=walk):
            observed = self.scan([({str(self.data / 'hot')}, [], 120)])
        self.assertEqual(observed.logical, complete(self.data).logical)
        self.assertEqual(self.starts, [100, 120])
        self.assertTrue(observed.refresh['cache']['reusable'])

    def test_checkpoint_precedes_journal_reader_to_walk_race(self):
        self.scan()
        self.event_id = 200
        calls = []
        owner = self
        class Journal:
            def __init__(self, root, since, exclusions): calls.append(since)
            def __enter__(self): return self
            def __exit__(self, *args):
                if len(calls) == 1:
                    (owner.data / 'quiet' / 'file').write_bytes(b'z' * 10000)
                    owner.event_id = 201
            def drain(self):
                return ({str(owner.data / 'quiet')} if len(calls) == 2 else set(), [], owner.event_id)
        observed = inventory(self.data, self.state, self.config, backend=Journal)
        self.assertEqual(calls[1], 200, 'checkpoint skipped a change after closing the reader')
        self.assertEqual(observed.logical, complete(self.data).logical)

    def test_events_during_repair_are_replayed_on_next_refresh(self):
        changed = False
        original = complete
        def walk(*args, **kwargs):
            nonlocal changed
            result = original(*args, **kwargs)
            if kwargs.get('reuse') is not None and not changed:
                (self.data / 'hot' / 'file').write_bytes(b'x' * 12000)
                self.event_id = 130
                changed = True
            return result
        with patch('mactrim.incremental.complete', side_effect=walk):
            observed = self.scan([({str(self.data / 'hot')}, [], 101),
                                  ({str(self.data / 'hot')}, [], 130)])
        self.assertEqual(observed.status, 'partial')
        self.assertTrue(observed.refresh['cache']['reusable'])
        body = Cache(self.state, self.config['storage_cache']).read()[0]
        self.assertLess(body['checkpoint'], 130)
        refreshed = self.scan([({str(self.data / 'hot')}, [], 130)])
        self.assertEqual(refreshed.logical, complete(self.data).logical)
        self.assertEqual(refreshed.status, 'measured')

    def test_edit_after_post_scan_reader_closes_is_not_skipped_by_repair(self):
        owner = self
        calls = []
        class Journal:
            def __init__(self, root, since, exclusions): calls.append(since)
            def __enter__(self): return self
            def __exit__(self, *args):
                if len(calls) == 1:
                    (owner.data / 'quiet' / 'file').write_bytes(b'z' * 10000)
                    owner.event_id = 201
            def drain(self):
                if len(calls) == 1:
                    owner.event_id = 200
                    return {str(owner.data / 'hot')}, [], 200
                return {str(owner.data / 'quiet')}, [], 201
        observed = inventory(self.data, self.state, self.config, backend=Journal)
        self.assertEqual(calls, [100, 200])
        self.assertEqual(observed.status, 'partial')
        body = Cache(self.state, self.config['storage_cache']).read()[0]
        self.assertEqual(body['checkpoint'], 200)
        self.assertEqual({child.name: child.status for child in observed.children},
                         {'hot': 'measured', 'quiet': 'partial'})
        refreshed = self.scan([({str(self.data / 'quiet')}, [], 201)])
        self.assertEqual(refreshed.logical, complete(self.data).logical)
        self.assertEqual(refreshed.status, 'measured')

    def test_cancellation_during_replay_keeps_previous_index(self):
        self.scan()
        path = self.state.path / 'storage-cache' / 'index.json.gz'
        before = path.read_bytes()
        cancel = threading.Event()
        def progress(snapshot, _):
            if snapshot.progress['phase'] == 'Checking filesystem events': cancel.set()
        observed = self.scan(full=True, cancel=cancel, progress=progress)
        self.assertEqual(observed.status, 'cancelled')
        self.assertEqual(path.read_bytes(), before)
        self.assertEqual(self.active, 0)
