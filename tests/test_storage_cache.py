"""Persistence contract tests; synthetic trees avoid a whole-Mac rescan."""
import gzip
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from mactrim.config import defaults
from mactrim.regions import Cancelled
from mactrim.safety import SafetyError, json_bytes, rename_exclusive
from mactrim.state import State
from mactrim.storage import StorageNode
from mactrim.storage_cache import Cache, SCHEMA, MAGIC, flatten


class DirectoryIndexTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.state = State(Path(self.temp.name).resolve() / 'state').prepare()
        self.scope = str(Path(self.temp.name).resolve() / 'data')
        self.root = StorageNode(self.scope, 'data', status='measured', kind='directory')
        self.cache = Cache(self.state, defaults()['storage_cache'])

    def tearDown(self):
        self.temp.cleanup()

    def body(self, root=None):
        return dict(schema=SCHEMA, scope=self.scope, policy={}, volume=[1, 2, 'fixture'],
                    checkpoint=100, previous_checkpoint=None, created_at=time.time(), full_at=time.time(),
                    complete_index=True, requires_reconcile=False, reuse_allowed=True,
                    reconcile_scopes=[], directories=flatten(root or self.root))

    def test_large_tree_survives_old_count_and_decoded_limits(self):
        # Above the former 200,000-row cutoff. Retain PARTIAL rows too: coverage
        # uncertainty never justifies losing the directory observation.
        count = 200001
        for index in range(count):
            self.root.children.append(StorageNode(self.scope + '/d' + str(index), 'd' + str(index),
                status='partial', kind='directory', issues=['coverage diagnostic: ' + 'x' * 400],
                signature=(1, 2, 3, 4, 5, 6)))
        result = self.cache.write(self.body())
        self.assertTrue(result['stored'])
        self.assertEqual(result['directory_count'], count + 1)
        path = self.cache.path / 'index.json.gz'
        with path.open('rb') as stream:
            self.assertEqual(stream.read(len(MAGIC)), MAGIC)
            stream.read(65)
            with gzip.GzipFile(fileobj=stream) as decoded:
                size = sum(len(line) for line in decoded)
        self.assertGreater(size, 64 * 1024 * 1024)
        body, root, nodes = Cache(self.state, defaults()['storage_cache']).read()
        self.assertTrue(body['complete_index'])
        self.assertEqual(len(nodes), count + 1)
        self.assertEqual(len(root.children), count)
        self.assertEqual(root.children[-1].path, self.scope + '/d200000')
        self.assertEqual(root.children[-1].status, 'partial')
        # Actual footprint is observable; automatic sizing has no arbitrary cap.
        self.assertIsNone(result['limit_bytes'])
        self.assertEqual(result['allocated_bytes'], self.cache.footprint())

    def test_nested_tree_links_and_corruption_preserved(self):
        child = StorageNode(self.scope + '/child', 'child', status='measured')
        child.children.append(StorageNode(child.path + '/nested', 'nested', status='measured', logical=8192))
        self.root.children.append(child)
        self.cache.write(self.body())
        _, root, nodes = self.cache.read()
        self.assertIs(root.children[0].children[0], nodes[child.path + '/nested'])
        path = self.cache.path / 'index.json.gz'
        content = bytearray(path.read_bytes()); content[-12] ^= 1; path.write_bytes(content)
        with self.assertRaises(SafetyError): self.cache.read()
        self.assertEqual(path.read_bytes(), content)

    def test_cancel_during_write_removes_only_pending_candidate(self):
        self.cache.write(self.body()); self.cache.read()
        path = self.cache.path / 'index.json.gz'; old = path.read_bytes()
        event = threading.Event()
        def rows():
            yield from flatten(self.root)
            event.set()
            yield from flatten(self.root)
        body = self.body(); body['directories'] = rows()
        with self.assertRaises(Cancelled): self.cache.write(body, cancel=event)
        self.assertEqual(path.read_bytes(), old)
        self.assertEqual(set(p.name for p in path.parent.iterdir()), {'index.json.gz'})

    def test_failed_commit_restores_prior_index_and_removes_candidate(self):
        self.cache.write(self.body()); self.cache.read()
        path = self.cache.path / 'index.json.gz'; old = path.read_bytes()
        def fail_pending(fd, source, target_fd, target):
            if source.startswith('.pending-'):
                raise OSError('Injected commit failure')
            return rename_exclusive(fd, source, target_fd, target)
        with patch('mactrim.storage_cache.rename_exclusive', side_effect=fail_pending):
            with self.assertRaises(SafetyError):
                self.cache.write(self.body())
        self.assertEqual(path.read_bytes(), old)
        self.assertEqual(set(p.name for p in path.parent.iterdir()), {'index.json.gz'})

    def test_legacy_index_read_and_migration(self):
        child = StorageNode(self.scope + '/child', 'child', status='measured')
        self.root.children.append(child)
        rows = list(flatten(self.root))
        for row in rows:
            row.pop('parent')
            row['identity'] = list(row['identity']); row['signature'] = list(row['signature'])
            row['child_paths'] = [child.path] if row['path'] == self.scope else []
        body = self.body(); body['directories'] = rows
        self.cache.prepare()
        path = self.cache.path / 'index.json.gz'
        path.write_bytes(gzip.compress(json_bytes(self.state.sign(body)), mtime=0)); path.chmod(0o600)
        saved, root, nodes = self.cache.read()
        self.assertEqual(len(nodes), 2)
        saved['directories'] = flatten(root)
        self.cache.write(saved)
        self.assertTrue(path.read_bytes().startswith(MAGIC))
        self.assertEqual(len(self.cache.read()[2]), 2)
