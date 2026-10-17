import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from mactrim.incremental import inventory
from mactrim.regions import Regions
from mactrim.safety import within
from mactrim.state import State
from mactrim.storage import complete
from mactrim.config import defaults


class RegionTests(unittest.TestCase):
    def test_matches_original_ancestor_descendant_and_component_boundaries(self):
        paths = ['/a/hot', '/a/hot/nested', '/a/cold/deep', '/other/é', '/dot/../normalized']
        index = Regions(paths)
        for query in ['/', '/a', '/a/hot', '/a/hot/file', '/a/hotter', '/a/cold',
                      '/a/cold/sibling', '/other/é/nested', '/other/e', '/normalized', '/none']:
            expected = any(within(query, region) or within(region, query) for region in paths)
            self.assertEqual(index.intersects(query), expected, query)
        self.assertTrue(Regions(['/']).intersects('/any/depth'))
        self.assertFalse(Regions([]).intersects('/'))

    def test_large_disjoint_regions_do_not_compare_against_every_event(self):
        regions = Regions('/data/hot-%s/files' % i for i in range(10000))
        from mactrim import regions as module
        original = module.canonical
        # One canonicalization per query, even with ten thousand dirty regions.
        with patch.object(module, 'canonical', wraps=original) as canonical:
            for index in range(10000):
                self.assertFalse(regions.intersects('/data/cold-%s/files' % index))
                self.assertTrue(regions.intersects('/data/hot-%s' % index))
            self.assertEqual(canonical.call_count, 20000)


class ProgressTests(unittest.TestCase):
    def test_completed_directory_totals_are_visible_before_whole_scan_finishes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name in ('node_modules/package/deep', 'a/child/leaf', 'z/child/leaf'):
                (root / name).mkdir(parents=True)
                (root / name / 'payload').write_bytes(b'x' * 8192)
            order, snapshots = [], []
            clock = iter(range(1, 1000000))
            def progress(snapshot, current):
                if current.path not in order:
                    order.append(current.path)
                snapshots.append(snapshot)
            with patch('mactrim.storage.time.monotonic', side_effect=lambda: next(clock)):
                result = complete(root, progress=progress)
            visible = [str(root / name) for name in ('a', 'z', 'a/child', 'z/child', 'a/child/leaf', 'z/child/leaf')]
            self.assertTrue(all(path in order for path in visible))
            self.assertNotIn(str(root / 'node_modules/package'), order)
            self.assertTrue({'a', 'z', 'node_modules'} <= {row.name for row in snapshots[0].children})
            self.assertTrue({'a', 'z', 'node_modules'} <= {row.name for row in snapshots[-1].children})
            self.assertTrue(any(row.status == 'scanning' and any(child.status == 'measured' and child.logical >= 8192 for child in row.children) for row in snapshots))
            self.assertEqual(result.logical, complete(root, lazy=False).logical)

    def test_selected_directory_sizes_include_deep_observations_before_final_aggregation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            payload = root / 'a/child/leaf/payload'
            payload.parent.mkdir(parents=True)
            payload.write_bytes(b'x' * 8192)
            seen = []
            clock = iter(range(1, 1000000))
            with patch('mactrim.storage.time.monotonic', side_effect=lambda: next(clock)):
                result = complete(root, progress=lambda snapshot, _: seen.append(snapshot), view=lambda: root / 'a')
            running = [row.view for row in seen if hasattr(row, 'view') and row.progress['phase'] == 'Native size scan']
            self.assertGreaterEqual(running[-1].logical, 8192)
            self.assertGreaterEqual(running[-1].children[0].logical, 8192)
            self.assertEqual(running[-1].logical, result.children[0].logical)
            self.assertLess(running[0].logical, running[-1].logical)

    def test_live_ancestor_totals_count_reused_subtrees_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name in ('a/quiet/leaf', 'a/hot/leaf'):
                (root / name).mkdir(parents=True)
                (root / name / 'payload').write_bytes(b'x' * 8192)
            baseline = complete(root)
            quiet = next(child for child in baseline.children[0].children if child.name == 'quiet')
            seen = []
            clock = iter(range(1, 1000000))
            with patch('mactrim.storage.time.monotonic', side_effect=lambda: next(clock)):
                result = complete(root, progress=lambda snapshot, _: seen.append(snapshot), view=lambda: root / 'a',
                                  reuse=lambda node, _: quiet if node.path == quiet.path else None)
            self.assertEqual(result.logical, baseline.logical)
            self.assertEqual(seen[-1].logical, baseline.logical)
            self.assertEqual(seen[-1].view.logical, baseline.children[0].logical)
            self.assertGreater(result.counters['reused'], 0)
            pending = [result]
            while pending:
                node = pending.pop()
                self.assertNotIn('_scan_parent', node.__dict__)
                pending.extend(node.children)

    def test_cancel_during_level_discovery_preserves_visible_observations(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'node_modules/package').mkdir(parents=True)
            (root / 'visible/child').mkdir(parents=True)
            (root / 'visible/child/payload').write_bytes(b'x' * 8192)
            cancel = threading.Event()
            clock = iter(range(1, 1000000))
            def progress(snapshot, _):
                if any(child.logical >= 8192 for child in snapshot.children):
                    cancel.set()
            with patch('mactrim.storage.time.monotonic', side_effect=lambda: next(clock)):
                result = complete(root, cancel=cancel, progress=progress)
            self.assertEqual(result.status, 'cancelled')
            self.assertGreaterEqual(next(child for child in result.children if child.name == 'visible').logical, 8192)

    def test_progress_presentation_is_bounded_without_truncating_measurement(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for index in range(600):
                (root / str(index)).mkdir()
            seen = []
            result = complete(root, progress=lambda snapshot, _: seen.append(snapshot))
            self.assertEqual(len(result.children), 600)
            self.assertEqual(result.entries, 601)
            self.assertEqual(seen[-1].entries, 601)
            self.assertTrue(all(len(row.children) <= 500 for row in seen))

    def test_live_lower_bounds_match_final_hardlink_and_reuse_accounting(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / 'one').mkdir(); (root / 'two').mkdir()
            (root / 'one' / 'payload').write_bytes(b'x' * 8192)
            os.link(root / 'one' / 'payload', root / 'two' / 'alias')
            (root / 'excluded-link').symlink_to(root)
            for reuse in (False, True):
                baseline = complete(root)
                nodes = {child.path: child for child in baseline.children}
                seen = []
                # Force progress at every notification to exercise accounting mid-directory.
                clock = iter(range(1, 1000000))
                with patch('mactrim.storage.time.monotonic', side_effect=lambda: next(clock)):
                    result = complete(root, progress=lambda snapshot, _: seen.append(snapshot),
                                      reuse=(lambda node, _: nodes.get(node.path)) if reuse else None)
                self.assertEqual((result.logical, result.allocated, result.entries),
                                 (baseline.logical, baseline.allocated, baseline.entries))
                self.assertEqual((seen[-1].logical, seen[-1].allocated, seen[-1].entries),
                                 (result.logical, result.allocated, result.entries))
                self.assertEqual([row.logical for row in seen], sorted(row.logical for row in seen))
                self.assertLess(seen[0].logical, result.logical)  # early snapshots stay stable
                self.assertTrue(any(row.logical >= 8192 for row in seen[1:]))
                self.assertTrue(all(row.status == ('measured' if row.progress['scope_finished'] else 'scanning') for row in seen))
                self.assertEqual(seen[-1].status, 'measured')
                self.assertEqual(sum(child.logical for child in seen[-1].children) + result.own_logical, result.logical)

    def test_hot_regions_preserve_unaffected_measurements_and_cancel_without_commit(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            data = root / 'data'; data.mkdir()
            for name in ('hot', 'quiet'):
                (data / name).mkdir()
                (data / name / 'file').write_bytes(b'x' * 4096)
            # Hardlinks avoid a second walk, reproducing the expensive post-walk phase.
            os.link(data / 'quiet' / 'file', data / 'quiet' / 'alias')
            state = State(root / 'state').prepare(); config = defaults()
            class HotEvents:
                def __init__(self, *args): self.drains = 0
                def __enter__(self): return self
                def __exit__(self, *args): pass
                def drain(self):
                    self.drains += 1
                    return ({str(data / 'hot')}, [], 123)
            with patch('mactrim.incremental.volume_identity', return_value=[1, 2, 'test']), patch('mactrim.events.current_id', return_value=123):
                observed = inventory(data, state, config, backend=HotEvents)
                self.assertEqual(observed.status, 'partial')
                self.assertEqual({child.name: child.status for child in observed.children}, {'hot': 'partial', 'quiet': 'measured'})
                cache_path = state.path / 'storage-cache' / 'index.json.gz'
                old = cache_path.read_bytes()
                for stop_phase in ('Checking filesystem events', 'Classifying unsettled directories', 'Saving directory index'):
                    cancel = threading.Event(); seen = []
                    def progress(snapshot, _):
                        seen.append(snapshot)
                        if snapshot.progress['phase'] == stop_phase:
                            cancel.set()
                    result = inventory(data, state, config, cancel=cancel, progress=progress, full=True, backend=HotEvents)
                    self.assertEqual(result.status, 'cancelled', stop_phase)
                    self.assertEqual(cache_path.read_bytes(), old)
                    measured = [row for row in seen if row.progress['phase'] != 'Native size scan']
                    self.assertTrue(measured)
                    self.assertGreater(measured[0].allocated, 0)
                    self.assertGreater(measured[0].counters['visited'], 0)


if __name__ == '__main__':
    unittest.main()
