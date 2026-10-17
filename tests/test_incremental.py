import copy
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
from mactrim.config import defaults
from mactrim.incremental import inventory
from mactrim.state import State
from mactrim.storage import complete
from mactrim.storage_cache import Cache
from mactrim.safety import SafetyError

class IncrementalTests(unittest.TestCase):
    def setUp(self):
        Path('evidence').mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=Path('evidence').resolve())
        self.root = Path(self.temp.name); self.data = self.root / 'data'; self.data.mkdir()
        self.state = State(self.root / 'state').prepare(); self.config = defaults()
        for key in ('repo_roots', 'worktree_roots', 'cache_roots', 'duplicate_roots', 'app_roots', 'app_data_roots'): self.config[key] = []
        self.config_path = self.root / 'config.json'; self.config_path.write_text(json.dumps(self.config))
        for i in range(12):
            path = self.data / str(i); path.mkdir()
            (path / 'file').write_bytes(b'x' * (100 + i))
    def tearDown(self):
        self.temp.cleanup()
    def scan(self, **kwargs):
        return inventory(self.data, self.state, self.config, **kwargs)
    def same(self, observed):
        full = complete(self.data)
        self.assertEqual(observed.status, full.status, observed.refresh)
        self.assertEqual((observed.logical, observed.allocated, observed.entries), (full.logical, full.allocated, full.entries))
    @unittest.skipUnless(sys.platform == 'darwin', 'native macOS FSEvents')
    def test_real_restart_no_change_and_mutation_matrix(self):
        first = self.scan(); self.same(first)
        quiet = self.scan(); self.same(quiet)
        self.assertEqual(quiet.refresh['mode'], 'incremental', quiet.refresh)
        self.assertLess(quiet.counters['visited'], first.counters['visited'])
        path = self.data / '4' / 'file'; mt = (self.data.stat().st_mtime_ns, path.parent.stat().st_mtime_ns)
        path.write_bytes(b'z' * 12000)
        self.assertEqual(mt, (self.data.stat().st_mtime_ns, path.parent.stat().st_mtime_ns))
        # No sleep: immediately written files must not become stale growth baselines.
        # Actual CLI in a new process consumes the saved FSEvents checkpoint.
        result = subprocess.run([sys.executable, '-m', 'mactrim', '--state', str(self.state.path), '--config', str(self.config_path), 'storage', str(self.data), '--json'], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)['measurement']
        self.assertEqual(data['logical'], complete(self.data).logical)
        self.assertEqual(data['refresh']['mode'], 'incremental', data['refresh'])
        self.assertLess(data['refresh']['visited'], first.counters['visited'])
        changes = [lambda: (self.data / 'new').mkdir(),
                   lambda: (self.data / 'new' / 'file').write_bytes(b'a' * 8192),
                   lambda: (self.data / 'new' / 'file').rename(self.data / '3' / 'moved'),
                   lambda: (self.data / '3' / 'moved').write_bytes(b'b'),
                   lambda: (self.data / '3' / 'moved').unlink(),
                   lambda: (self.data / 'new').rmdir(),
                   lambda: os.link(self.data / '1' / 'file', self.data / '8' / 'alias'),
                   lambda: (self.data / '1' / 'file').write_bytes(b'h' * 3000),
                   lambda: (self.data / '8' / 'alias').unlink()]
        for change in changes:
            change(); self.same(self.scan())
    def test_tiny_cache_never_truncates_measurement_and_no_growth(self):
        self.config['storage_cache']['max_bytes'] = 8192
        first = self.scan(); self.same(first)
        self.assertLessEqual(first.refresh.get('cache', {}).get('allocated_bytes', 0), 8192)
        for _ in range(3): self.same(self.scan())
        self.config['storage_cache']['max_bytes'] = 1024 * 1024
        first = self.scan()
        cache = Cache(self.state, self.config['storage_cache'])
        initial = cache.footprint()
        for _ in range(3):
            observed = self.scan(); self.same(observed)
            self.assertLessEqual(cache.footprint(), initial)
            self.assertLessEqual(observed.refresh['cache']['peak_allocated_bytes'], cache.limit)
    def test_corruption_symlink_and_disable_preserve_inputs(self):
        self.scan()
        path = self.state.path / 'storage-cache' / 'index.json.gz'
        path.write_bytes(b'corrupt')
        self.same(self.scan()); self.assertEqual(path.read_bytes(), b'corrupt')
        with self.assertRaises(SafetyError): Cache(self.state, self.config['storage_cache']).clear()
        path.unlink(); target = self.root / 'important'; target.write_bytes(b'keep')
        path.symlink_to(target)
        self.same(self.scan()); self.assertTrue(path.is_symlink()); self.assertEqual(target.read_bytes(), b'keep')
        self.config['storage_cache']['enabled'] = False
        self.same(self.scan()); self.assertEqual(target.read_bytes(), b'keep')
    def test_periodic_reconciliation_and_cancel_do_not_commit(self):
        self.scan(); old = (self.state.path / 'storage-cache' / 'index.json.gz').read_bytes()
        event = threading.Event(); event.set()
        self.assertEqual(self.scan(cancel=event).status, 'cancelled')
        self.assertEqual(old, (self.state.path / 'storage-cache' / 'index.json.gz').read_bytes())
        self.config['storage_cache']['reconcile_seconds'] = 1
        time.sleep(1.1); result = self.scan(); self.same(result)
        self.assertEqual(result.refresh['mode'], 'full')
    def test_simulated_unavailable_backend_cannot_return_stale_cache(self):
        self.scan(); (self.data / '4' / 'file').write_bytes(b'changed'*100)
        class Unavailable:
            def __init__(self, *args): pass
            def __exit__(self, *args): pass
            def __enter__(self): raise SafetyError('Simulated dropped event history')
        result = self.scan(backend=Unavailable); self.same(result)
        self.assertEqual(result.refresh['mode'], 'full')
        self.assertIn('Simulated', ' '.join(result.refresh['warnings']))

    def test_explicit_budget_preserves_previous_tree_without_truncation(self):
        self.scan()
        path = self.state.path / 'storage-cache' / 'index.json.gz'
        old = path.read_bytes()
        for index in range(1800): (self.data / ('directory-' + str(index))).mkdir()
        self.config['storage_cache']['max_bytes'] = 8192
        first = self.scan(); self.same(first)
        self.assertFalse(first.refresh['cache']['stored'])
        self.assertIn('previous index preserved', first.refresh['cache']['reason'])
        self.assertGreater(first.refresh['cache']['required_bytes'], 8192)
        self.assertEqual(path.read_bytes(), old)
        self.assertEqual(set(p.name for p in path.parent.iterdir()), {'index.json.gz'})
        self.config['storage_cache']['max_bytes'] = None
        second = self.scan(); self.same(second)
        self.assertTrue(second.refresh['cache']['complete_index'])
        self.assertEqual(second.refresh['cache']['directory_count'], 1813)

    def test_change_during_walk_is_reconciled(self):
        changed = [False]
        def mutate(node, child):
            if not changed[0]:
                changed[0] = True
                (self.data / '8' / 'file').write_bytes(b'q' * 20000)
        result = self.scan(progress=mutate)
        self.same(result)

    def test_simulated_gap_requires_full_measurement(self):
        from mactrim.events import NativeEvents
        self.scan()
        (self.data / '7' / 'file').write_bytes(b'gap' * 1234)
        class Gap(NativeEvents):
            def drain(self):
                paths, issues, latest = super().drain()
                if not getattr(self, 'injected', False):
                    self.injected = True
                    issues.append('Simulated UserDropped gap')
                return paths, issues, latest
        result = self.scan(backend=Gap); self.same(result)
        self.assertEqual(result.refresh['mode'], 'full')
        self.assertIn('Simulated', ' '.join(result.refresh['warnings']))

    def test_hardlinked_scopes_allow_quiet_reuse_and_reconcile_changes(self):
        os.link(self.data / '1' / 'file', self.data / '8' / 'alias')
        first = self.scan(); self.same(first)
        quiet = self.scan(); self.same(quiet)
        self.assertEqual(quiet.refresh['mode'], 'incremental', quiet.refresh)
        self.assertLess(quiet.counters['visited'], first.counters['visited'])
        (self.data / '1' / 'file').write_bytes(b'h' * 25000)
        changed = self.scan(); self.same(changed)
        self.assertEqual(changed.refresh['mode'], 'full', changed.refresh)

    def test_concurrent_cache_winner_is_preserved(self):
        self.scan()
        loser = Cache(self.state, self.config['storage_cache'])
        body = loser.read()[0]
        body = dict(body, previous_checkpoint=body['checkpoint'])
        (self.data / '3' / 'file').write_bytes(b'x' * 3000)
        winner = self.scan()
        path = self.state.path / 'storage-cache' / 'index.json.gz'
        expected = path.read_bytes()
        with self.assertRaises(SafetyError): loser.write(body)
        self.assertEqual(path.read_bytes(), expected)
        self.same(winner)

    def test_capture_history_uses_same_cli_observation(self):
        result = subprocess.run([sys.executable, '-m', 'mactrim', '--state', str(self.state.path), '--config', str(self.config_path), 'storage', str(self.data), '--json', '--full', '--capture-history'], capture_output=True, text=True, check=True)
        data = json.loads(result.stdout)
        self.assertIsNotNone(data['history_snapshot'])
        self.assertEqual(data['measurement']['logical'], complete(self.data).logical)
