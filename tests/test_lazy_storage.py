import gzip
import hashlib
import hmac
import os
from pathlib import Path
import tempfile
import threading
import unittest

from mactrim.config import defaults
from mactrim.history import aggregates
from mactrim.incremental import inventory
from mactrim.safety import json_bytes
from mactrim.state import State
from mactrim.storage import complete, page
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

    def test_summaries_match_full_measurement_and_opening_expands_details(self):
        compact = complete(self.data); expanded = complete(self.data, lazy=False)
        self.assertEqual((compact.logical, compact.allocated, compact.entries, compact.recent),
                         (expanded.logical, expanded.allocated, expanded.entries, expanded.recent))
        self.assertEqual(len(compact.children), 2)
        for child in compact.children:
            self.assertTrue(child.details_deferred)
            self.assertFalse(child.children)
            self.assertEqual(page(child), ([], False))
        details = complete(self.dependencies)
        self.assertFalse(details.details_deferred)
        self.assertTrue(details.children)
        self.assertEqual(details.logical, next(n for n in compact.children if n.path == str(self.dependencies)).logical)
        self.assertFalse(next(row for row in aggregates(compact) if row['path'] == str(self.dependencies))['children_complete'])

    def test_hardlinks_sparse_files_and_permission_errors_preserve_accounting(self):
        file = self.dependencies / 'package' / 'lib' / 'payload'
        os.link(file, self.data / 'outside-alias')
        with (self.dependencies / 'sparse').open('wb') as stream: stream.truncate(1024 * 1024)
        a, b = complete(self.data), complete(self.data, lazy=False)
        self.assertEqual((a.logical,a.allocated,a.entries),(b.logical,b.allocated,b.entries))
        denied = self.dependencies / 'private'; denied.mkdir(); denied.chmod(0)
        try:
            result = complete(self.data)
            summary = next(n for n in result.children if n.path == str(self.dependencies))
            self.assertEqual(summary.status, 'partial')
            self.assertTrue(any(str(denied) in issue for issue in summary.issues))
        finally: denied.chmod(0o700)
        cancel = threading.Event(); cancel.set()
        self.assertEqual(complete(self.data,cancel=cancel).status,'cancelled')

    def test_native_restart_reuses_summary_and_detects_deep_inplace_edit(self):
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
        self.assertEqual(changed.logical,complete(self.data,lazy=False).logical)
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
