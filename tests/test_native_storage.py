"""Correctness/streaming probes on disposable data, not performance benchmarks."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from mactrim import native_storage as native


@unittest.skipUnless(sys.platform == 'darwin', 'Native macOS FTS collector')
class NativeStorageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='mactrim-native-', dir='/private/tmp')
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def observe(self, root=None, callback=None, lazy=True):
        events = []
        def collect(kind, record):
            row = {key: getattr(record, key) for key, _ in record._fields_ if key != 'reasons'}
            row['path'] = os.fsdecode(row['path'])
            events.append((kind, row))
            return callback(kind, record) if callback else 0
        result = native.scan(root or self.root, (), lazy, collect)
        return result, events

    def test_native_totals_match_du_and_dependencies_are_aggregate_leaves(self):
        for name in ('ordinary/child', 'node_modules/package/lib', '.venv/lib/python'):
            folder = self.root / name; folder.mkdir(parents=True)
            (folder / 'payload').write_bytes(b'x' * 16384)
        result, events = self.observe()
        completed = {row['path']: row for kind, row in events if kind == native.FINISH}
        root = completed[str(self.root)]
        expected = int(subprocess.check_output(['/usr/bin/du', '-sk', str(self.root)]).split(b'\t', 1)[0]) * 1024
        self.assertEqual(root['allocated'], expected)
        self.assertEqual(root['status'], 0)
        self.assertEqual(result, 0)
        summary = completed[str(self.root / 'node_modules')]
        self.assertTrue(summary['flags'] & native.COLLAPSED)
        self.assertGreaterEqual(summary['logical'], 16384)
        self.assertNotIn(str(self.root / 'node_modules/package'), completed)
        _, opened = self.observe(self.root / 'node_modules')
        self.assertTrue(any(row['path'] == str(self.root / 'node_modules/package') for _, row in opened))

    def test_completed_totals_stream_before_sibling_subtrees_finish(self):
        for name in ('a', 'b'):
            (self.root / name).mkdir()
            (self.root / name / 'file').write_bytes(b'x' * 8192)
        _, events = self.observe()
        finished = [row for kind, row in events if kind == native.FINISH]
        self.assertNotEqual(finished[0]['path'], str(self.root))
        self.assertGreaterEqual(finished[0]['logical'], 8192)
        self.assertEqual(finished[-1]['path'], str(self.root))
        discovered = [row['path'] for kind, row in events if kind == native.DISCOVER]
        first_finish = next(i for i, (kind, _) in enumerate(events) if kind == native.FINISH)
        self.assertTrue({str(self.root / 'a'), str(self.root / 'b')} <= set(discovered))
        self.assertTrue(all(any(kind == native.DISCOVER and row['path'] == str(self.root / name)
                               for kind, row in events[:first_finish]) for name in ('a', 'b')))

    def test_files_do_not_create_python_callbacks_and_names_are_lossless(self):
        folder = self.root / 'unicode-é\tand\nnewline'; folder.mkdir()
        for i in range(600):
            (folder / str(i)).write_bytes(b'x')
        _, events = self.observe()
        self.assertTrue(any(row['path'] == str(folder) for _, row in events))
        self.assertLess(len(events), 100)  # callbacks describe directories, not 600 files
        self.assertGreaterEqual(events[-1][1]['visited'], 602)

    def test_cancellation_and_callback_failures_stop_the_native_walk(self):
        (self.root / 'a').mkdir()
        result, _ = self.observe(callback=lambda kind, row: 2 if kind == native.DISCOVER else 0)
        self.assertEqual(result, 1)
        def failed(kind, row):
            raise ValueError('fixture callback failed')
        with self.assertRaisesRegex(ValueError, 'fixture callback failed'):
            self.observe(callback=failed)

    def test_verified_reuse_prunes_native_traversal_without_double_counting(self):
        (self.root / 'inside').mkdir()
        def reuse(kind, row):
            if kind == native.ENTER:
                row.logical=12345; row.allocated=8192; row.entries=71
                row.own_logical=64; row.own_allocated=0
                return 1
        result, events = self.observe(callback=reuse)
        final = next(row for kind, row in reversed(events) if kind == native.FINISH)
        self.assertEqual((result, final['logical'], final['allocated']), (0, 12345, 8192))
        self.assertEqual(final['reused'], 71)
        self.assertEqual(final['visited'], 1)
        self.assertFalse(any(kind == native.DISCOVER for kind, _ in events))

    def test_depth_boundary_counts_all_bytes_and_only_retains_a_summary(self):
        path = self.root
        for i in range(15):
            path /= str(i); path.mkdir()
        (path / 'payload').write_bytes(b'x' * 8192)
        _, events = self.observe()
        finished = [row for kind, row in events if kind == native.FINISH]
        self.assertEqual(max(row['depth'] for row in finished), 9)
        self.assertGreaterEqual(next(row for row in finished if row['depth'] == 9)['logical'], 8192)

    def test_hardlinks_sparse_and_denied_interiors_are_explicit(self):
        (self.root / 'node_modules/private').mkdir(parents=True)
        data = self.root / 'data'; data.write_bytes(b'x' * 8192)
        os.link(data, self.root / 'node_modules/alias')
        sparse = self.root / 'sparse'
        with sparse.open('wb') as stream: stream.truncate(1024 * 1024)
        denied = self.root / 'node_modules/private'; denied.chmod(0)
        try:
            _, events = self.observe()
            root = next(row for kind, row in reversed(events) if kind == native.FINISH)
            self.assertEqual(root['status'], 2)
            self.assertGreater(root['denied'], 0)
            self.assertGreater(root['logical'], root['allocated'])
            summary = next(row for kind, row in events if kind == native.FINISH and row['path'] == str(self.root / 'node_modules'))
            self.assertNotEqual(summary['status'], 0)
            self.assertEqual(os.fsdecode(summary['error_path']), str(denied))
        finally:
            denied.chmod(0o700)
