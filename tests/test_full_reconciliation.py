import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from mactrim.config import defaults
from mactrim.events import EventCollector
from mactrim.incremental import inventory
from mactrim.state import State
from mactrim.storage import complete, coverage_report, StorageNode


class FullRepairTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.data = self.root / 'data'; self.data.mkdir()
        for name in ('a', 'b', 'c'):
            (self.data / name).mkdir()
            (self.data / name / 'file').write_bytes(b'payload')
        self.state = State(self.root / 'state').prepare()
        self.identity = patch('mactrim.incremental.volume_identity', return_value=[1, 2, 'fixture'])
        self.ids = patch('mactrim.events.current_id', return_value=100)
        self.identity.start(); self.ids.start()

    def tearDown(self):
        self.ids.stop(); self.identity.stop(); self.temporary.cleanup()

    def scan(self, batches, **kwargs):
        class Events:
            def __init__(self, *args): self.batches = iter(batches)
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def drain(self): return next(self.batches, (set(), [], 100))
        return inventory(self.data, self.state, defaults(), backend=Events, full=True, **kwargs)

    def test_one_dropped_interval_gets_full_repair_in_same_scan(self):
        phases = []
        with patch('mactrim.incremental.complete', wraps=complete) as walker:
            observed = self.scan([(set(), [], 100), (set(), ['UserDropped'], 100)],
                                 progress=lambda snapshot, current: phases.append(snapshot.progress['phase']))
        self.assertEqual(walker.call_count, 2)
        self.assertIsNone(walker.call_args.kwargs['reuse'])
        self.assertEqual(observed.status, 'measured', observed.issues)
        self.assertTrue(observed.refresh['cache']['reusable'])
        self.assertEqual(observed.refresh['reconciliation'],
                         {'attempted': True, 'full': True, 'reason': 'Dropped filesystem notifications'})
        self.assertTrue(observed.refresh['coverage']['complete'])
        self.assertTrue(any(value.startswith('Full repair ·') for value in phases))

    def test_repeated_drops_finish_uncertain_without_infinite_restart(self):
        with patch('mactrim.incremental.complete', wraps=complete) as walker:
            observed = self.scan([(set(), [], 100), (set(), ['first drop'], 100), (set(), ['second drop'], 100)])
        self.assertEqual(walker.call_count, 2)
        self.assertEqual(observed.status, 'partial')
        self.assertFalse(observed.refresh['cache']['reusable'])
        self.assertTrue(observed.refresh['cache']['stored'])
        self.assertGreater(observed.refresh['coverage']['counts']['tracking'], 0)

    def test_unrelated_changes_are_repaired_despite_existing_hardlinks(self):
        os.link(self.data / 'a' / 'file', self.data / 'b' / 'alias')
        with patch('mactrim.incremental.complete', wraps=complete) as walker:
            observed = self.scan([(set(), [], 100), ({str(self.data / 'c')}, [], 100)])
        self.assertEqual(walker.call_count, 2)
        self.assertIsNotNone(walker.call_args.kwargs['reuse'])
        self.assertFalse(observed.refresh['reconciliation']['full'])
        self.assertEqual(observed.status, 'measured')
        self.assertEqual((observed.logical, observed.allocated), (complete(self.data).logical, complete(self.data).allocated))

    def test_changes_to_link_accounting_get_globally_counted_repair(self):
        os.link(self.data / 'a' / 'file', self.data / 'b' / 'alias')
        with patch('mactrim.incremental.complete', wraps=complete) as walker:
            observed = self.scan([(set(), [], 100), ({str(self.data / 'a')}, [], 100)])
        self.assertEqual(walker.call_count, 2)
        self.assertIsNone(walker.call_args.kwargs['reuse'])
        self.assertTrue(observed.refresh['reconciliation']['full'])
        self.assertEqual(observed.status, 'measured')
        self.assertEqual((observed.logical, observed.allocated), (complete(self.data).logical, complete(self.data).allocated))

    def test_coverage_lists_permissions_without_counting_ancestor_propagation(self):
        root = StorageNode('/fixture', 'fixture', status='partial',
                           issues=['1 descendant scopes incomplete; inspect coverage reasons'])
        root.children = [StorageNode('/fixture/protected', 'protected', status='denied',
                                    issues=['[Errno 1] Operation not permitted'])]
        report = coverage_report(root)
        self.assertFalse(report['complete'])
        self.assertEqual(report['counts'], {'permissions': 1, 'changes': 0, 'tracking': 0, 'other': 0})
        self.assertEqual(report['examples']['permissions'][0]['path'], '/fixture/protected')


class DirectoryEventTests(unittest.TestCase):
    def test_ordinary_native_directory_event_invalidates_exact_directory(self):
        try:
            import FSEvents
        except ImportError:
            self.skipTest('Native macOS environment required')
        events = EventCollector('/fixture')
        events._record(['/fixture/a'], [0], [100])
        events._process_pending()
        self.assertEqual(events.paths, {'/fixture/a'})
        self.assertEqual(events.issues, [])
