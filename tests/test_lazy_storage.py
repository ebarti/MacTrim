import gzip
import hashlib
import hmac
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from mactrim.config import defaults
from mactrim.history import aggregates
from mactrim.history import History
from mactrim.incremental import inventory
from mactrim.safety import json_bytes
from mactrim.state import State
from mactrim.storage import complete, page, find_directory, LAZY_DEPTH
from mactrim.storage_cache import Cache, MAGIC_V2, FIELDS, SCHEMA, flatten


class LazyStorageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.data = self.root / 'data'; self.data.mkdir()
        self.dependencies = self.data / 'node_modules'
        deep = self.dependencies / 'package' / 'lib'; deep.mkdir(parents=True)
        (deep / 'payload').write_bytes(b'x' * 8192)
        (self.dependencies / 'link').symlink_to(self.data)
        (self.data / '.venv' / 'lib').mkdir(parents=True)
        (self.data / '.venv' / 'lib' / 'module').write_bytes(b'y' * 4096)
        self.state = State(self.root / 'state').prepare()

    def tearDown(self):
        self.temporary.cleanup()

    def test_dependency_sizes_are_measured_but_browsing_details_are_collapsed(self):
        compact = complete(self.data)
        self.assertEqual(len(compact.children), 2)
        self.assertEqual(compact.status, 'measured')
        for child in compact.children:
            self.assertTrue(child.details_deferred)
            self.assertFalse(child.children)
            self.assertEqual(child.summary()['size_state'], 'measured')
            self.assertEqual(child.status, 'measured')
            self.assertGreaterEqual(child.logical, 4096)
            self.assertEqual(page(child), ([], False))
        details = complete(self.dependencies)
        self.assertFalse(details.details_deferred)
        self.assertTrue(details.children)
        self.assertGreaterEqual(details.logical, 8192)
        self.assertEqual(details.logical, find_directory(compact, self.dependencies).logical)
        self.assertFalse(next(row for row in aggregates(compact) if row['path'] == str(self.dependencies))['children_complete'])

    def test_hardlinks_sparse_files_and_permission_errors_preserve_accounting(self):
        file = self.dependencies / 'package' / 'lib' / 'payload'
        os.link(file, self.data / 'outside-alias')
        with (self.dependencies / 'sparse').open('wb') as stream: stream.truncate(1024 * 1024)
        a, b = complete(self.dependencies), complete(self.dependencies, lazy=False)
        self.assertEqual((a.logical,a.allocated,a.entries),(b.logical,b.allocated,b.entries))
        denied = self.dependencies / 'private'; denied.mkdir(); denied.chmod(0)
        try:
            result = complete(self.dependencies)
            self.assertEqual(result.status, 'partial')
            self.assertTrue(any(str(denied) == child.path and child.status in {'denied', 'partial'} and child.issues for child in result.children))
        finally: denied.chmod(0o700)
        cancel = threading.Event(); cancel.set()
        self.assertEqual(complete(self.data,cancel=cancel).status,'cancelled')

    def test_native_restart_reuses_summary_index_and_remeasures_deep_edit(self):
        first = inventory(self.data,self.state,defaults())
        cache = Cache(self.state,defaults()['storage_cache'])
        _, tree, nodes = cache.read()
        self.assertEqual(len(nodes),3)
        self.assertTrue(all(n.details_deferred for n in tree.children))
        quiet = inventory(self.data,self.state,defaults())
        self.assertEqual(quiet.refresh['mode'],'incremental')
        payload = self.dependencies / 'package' / 'lib' / 'payload'
        payload.write_bytes(b'z' * 24000)
        changed = inventory(self.data,self.state,defaults())
        self.assertGreater(changed.logical, first.logical)
        self.assertTrue(all(child.status == 'measured' for child in changed.children))
        opened = inventory(self.dependencies, None, defaults())
        self.assertGreaterEqual(opened.logical, 24000)
        self.assertTrue(changed.refresh['cache']['reusable'])

    def test_v2_detailed_index_is_readable_and_can_donate_sizes(self):
        full = complete(self.data,lazy=False)
        cache = Cache(self.state,defaults()['storage_cache']); cache.prepare()
        body = dict(schema=SCHEMA,scope=str(self.data),policy={},volume=[1,2,'fixture'],checkpoint=100,
                    created_at=full.completed_at,full_at=full.completed_at,complete_index=True,requires_reconcile=False)
        lines=[json_bytes(body)]
        for row in flatten(full): lines.append(json_bytes([row['parent'],row['name']]+[row[key] for key in FIELDS[:-1]]))
        payload=gzip.compress(b'\n'.join(lines)+b'\n',mtime=0)
        signature=hmac.new(self.state.key,MAGIC_V2+payload,hashlib.sha256).hexdigest().encode()+b'\n'
        (cache.path/'index.json.gz').write_bytes(MAGIC_V2+signature+payload)
        (cache.path/'index.json.gz').chmod(0o600)
        _,old,nodes=cache.read()
        compact=complete(self.data,reuse=lambda node,st:nodes.get(node.path))
        self.assertEqual(compact.logical,old.logical)
        self.assertTrue(all(n.details_deferred and not n.children for n in compact.children))

    def test_native_history_does_not_compare_against_legacy_unmeasured_policy(self):
        history = History(self.state, defaults())
        legacy = complete(self.data)
        legacy.collector = 'storage.on-demand.v2'
        old = history.capture(legacy, [])
        new = history.capture(complete(self.data), [])
        result = history.compare(old['id'], new['id'])
        self.assertEqual(result['rows'], [])
        self.assertIn('Incompatible', result['issues'][0])

    def test_depth_nine_keeps_recursive_bytes_without_retaining_inner_nodes(self):
        paths = [self.data]
        for depth in range(1, 20):
            paths.append(paths[-1] / ('level-%s' % depth))
            paths[-1].mkdir()
        (paths[-1] / 'payload').write_bytes(b'deep' * 4096)
        compact = complete(self.data)
        self.assertFalse(find_directory(compact, paths[LAZY_DEPTH]).details_deferred)
        summary = find_directory(compact, paths[LAZY_DEPTH + 1])
        self.assertTrue(summary.details_deferred)
        self.assertFalse(summary.children)
        self.assertIsNone(find_directory(compact, paths[LAZY_DEPTH + 2]))
        self.assertEqual(summary.summary()['size_state'], 'measured')
        detail = complete(paths[LAZY_DEPTH + 1])
        self.assertEqual(detail.logical, summary.logical)
        self.assertFalse(detail.details_deferred)
        self.assertTrue(find_directory(detail, paths[18]).details_deferred)
        self.assertEqual(find_directory(detail, paths[18]).summary()['size_state'], 'measured')
        self.assertGreaterEqual(complete(paths[18]).logical, 16384)
        self.assertFalse(next(row for row in aggregates(compact) if row['path'] == summary.path)['children_complete'])

    def test_cached_detailed_tree_is_compacted_at_depth_boundary_without_rewalking(self):
        path = self.data
        for depth in range(12):
            path /= str(depth); path.mkdir()
        (path / 'payload').write_bytes(b'cached-size')
        old = complete(self.data, lazy=False)
        calls = []
        def reuse(node, st):
            calls.append(node.path)
            return old if node.path == old.path else None
        current = complete(self.data, reuse=reuse)
        self.assertEqual(calls, [str(self.data)])
        self.assertEqual(current.logical, old.logical)
        cursor = current
        for depth in range(9):
            cursor = next(child for child in cursor.children if child.name == str(depth))
        self.assertTrue(cursor.details_deferred)
        self.assertFalse(cursor.children)

    def test_native_journal_detects_edit_below_deferred_depth_boundary(self):
        path = self.data
        for depth in range(12):
            path /= str(depth); path.mkdir()
        payload = path / 'payload'; payload.write_bytes(b'original')
        first = inventory(self.data, self.state, defaults())
        quiet = inventory(self.data, self.state, defaults())
        self.assertEqual(quiet.refresh['mode'], 'incremental')
        self.assertTrue(quiet.refresh['cache']['reusable'])
        payload.write_bytes(b'changed deep file' * 4096)
        changed = inventory(self.data, self.state, defaults())
        self.assertGreater(changed.logical, first.logical)
        self.assertEqual(changed.status, 'measured')
        _, tree, nodes = Cache(self.state, defaults()['storage_cache']).read()
        self.assertTrue(changed.refresh['cache']['reusable'])
        self.assertTrue(all(len(Path(node.path).relative_to(self.data).parts) <= 9 for node in nodes.values()))
