import copy
import json
import os
from pathlib import Path
import plistlib
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from mactrim import apps
from mactrim.activity import Activity, snapshot
from mactrim.config import defaults, validate
from mactrim.demo import create
from mactrim.executor import Executor, approval_for
from mactrim.scanner import Scanner
from mactrim.safety import SafetyError
from mactrim.state import State


class UpgradeFixtures(unittest.TestCase):
    def setUp(self):
        parent = Path.cwd() / 'evidence'
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.root = Path(self.temporary.name)
        self.app_root = self.root / 'Applications'
        self.app_root.mkdir()
        self.preferences = self.root / 'Preferences'
        self.preferences.mkdir()
        self.state = State(self.root / 'state').prepare()
        self.config = defaults()
        self.config.update(repo_roots=[], worktree_roots=[], cache_roots=[], duplicate_roots=[], app_roots=[str(self.app_root)], app_data_roots=[str(self.preferences)], system_reports=False)
        self.process = Activity(True)

    def tearDown(self):
        self.temporary.cleanup()

    def bundle(self, name, identifier, version='1.0', root=None):
        path = (root or self.app_root) / name / 'Contents'
        path.mkdir(parents=True)
        (path / 'Info.plist').write_bytes(plistlib.dumps({'CFBundleIdentifier': identifier, 'CFBundleShortVersionString': version}))
        return path.parent

    def test_apple_helpers_shared_and_equal_unknown_versions_are_not_uninstall_guesses(self):
        self.bundle('Vendor.app', 'com.fixture.Vendor')
        helper_root = self.app_root / 'Vendor.app' / 'Contents' / 'Library' / 'LoginItems'
        self.bundle('Helper.app', 'com.fixture.Helper', root=helper_root)
        self.bundle('Equal A.app', 'org.sample.Editor', '2.0')
        self.bundle('Equal B.app', 'org.sample.Editor', '2.0.0')
        self.bundle('Unknown.app', 'org.sample.Editor', 'unknown')
        for name in ('com.apple.absent.plist', 'com.fixture.Helper.plist', 'com.fixture.Retired.plist', 'net.other.absent.plist'):
            (self.preferences / name).write_text('unique preference')
        with patch('mactrim.apps.services', return_value=(set(), [])):
            items, owners, _ = apps.detect(self.config, self.state.path, self.process)
        self.assertIn('com.fixture.Helper', owners['bundles'])
        self.assertFalse(any(item['path'].endswith(('com.apple.absent.plist', 'com.fixture.Helper.plist')) for item in items))
        shared = next(item for item in items if item['path'].endswith('com.fixture.Retired.plist'))
        self.assertEqual(shared['context']['owner_status'], 'shared')
        self.assertFalse(shared['eligible'])
        self.assertEqual([item['kind'] for item in items if item['context']['bundle_id'] == 'org.sample.Editor'], ['duplicate-app'] * 3)

    def test_related_service_or_process_blocks_exact_retired_scope(self):
        path = self.preferences / 'com.fixture.Product.plist'
        path.write_text('private settings')
        self.config['retired_apps'] = {'com.fixture.Product': {'confirmed': True, 'paths': [str(path)], 'aliases': ['Product']}}
        for labels, commands in (({'com.fixture.Helper'}, {}), (set(), {123: '/Library/PrivilegedHelperTools/com.fixture.Helper'}), ({'application.com.fixture.Product.123.456'}, {123: '/Applications/Fixture.app/Contents/MacOS/Fixture'}), ({'application.com.fixture.Helper.123.456'}, {})):
            process = Activity(True, commands=commands)
            with patch('mactrim.apps.services', return_value=(labels, [])):
                items, owners, _ = apps.detect(self.config, self.state.path, process)
                self.assertFalse(any(item['eligible'] for item in items))
                self.assertEqual(apps.ownership('com.fixture.Product', owners, process)[0], 'running')
                with self.assertRaises(SafetyError):
                    apps.policy(path, 'com.fixture.Product', self.config, self.state.path, process, owners)

    def test_malformed_dictionary_or_incomplete_inventory_keeps_other_categories(self):
        bad = self.app_root / 'Broken.app' / 'Contents'
        bad.mkdir(parents=True)
        (bad / 'Info.plist').write_bytes(plistlib.dumps(['valid plist, invalid bundle schema']))
        (self.preferences / 'net.other.absent.plist').write_text('settings')
        copies = self.root / 'duplicates'
        copies.mkdir()
        (copies / 'a.txt').write_text('retained equal content')
        (copies / 'b.txt').write_text('retained equal content')
        self.config['duplicate_roots'] = [str(copies)]
        with patch('mactrim.apps.services', return_value=(set(), [])):
            plan = Scanner(validate(self.config, self.state.path), self.state, self.process).run()
        self.assertTrue(any(item['kind'] == 'duplicate' and item['eligible'] for item in plan['candidates']))
        app = next(item for item in plan['candidates'] if item['path'].endswith('net.other.absent.plist'))
        self.assertEqual(app['context']['owner_status'], 'uncertain')
        self.assertFalse(app['eligible'])
        self.assertTrue(any(row.get('category') == 'apps' and row['status'] == 'partial' for row in plan['coverage']))

    def test_invalid_xml_bundle_is_partial_and_preserves_other_discovery(self):
        broken = self.app_root / 'Broken.app' / 'Contents'
        broken.mkdir(parents=True)
        (broken / 'Info.plist').write_text('<?xml version="1.0"?><plist><dict><key>CFBundleIdentifier</key>')
        copies = self.root / 'copies'
        copies.mkdir()
        for name in ('a.txt', 'b.txt'):
            (copies / name).write_text('retained equal fixture content')
        self.config['duplicate_roots'] = [str(copies)]
        with patch('mactrim.apps.services', return_value=(set(), [])):
            plan = Scanner(self.config, self.state, self.process).run()
        self.assertTrue(any(item['kind'] == 'duplicate' and item['eligible'] for item in plan['candidates']))
        self.assertTrue(any(row.get('category') == 'apps' and row['status'] == 'partial' for row in plan['coverage']))

    def test_confirmed_exact_retired_scope_moves_restores_and_fresh_owner_blocks_purge(self):
        path = self.preferences / 'net.retired.Tool.plist'
        path.write_text('unique settings explicitly scoped')
        alias = self.preferences / 'Tool'
        alias.mkdir()
        (alias / 'settings.txt').write_text('alias settings')
        self.config['retired_apps'] = {'net.retired.Tool': {'confirmed': True, 'paths': [str(path)], 'aliases': ['Tool']}}
        with patch('mactrim.apps.services', return_value=(set(), [])):
            plan = Scanner(validate(self.config, self.state.path), self.state, self.process).run()
            item = next(item for item in plan['candidates'] if item['path'] == str(path))
            alias_item = next(item for item in plan['candidates'] if item['path'] == str(alias))
            self.assertTrue(item['eligible'], item['blockers'])
            self.assertFalse(alias_item['eligible'])
            executor = Executor(self.state, activity_provider=lambda: self.process)
            outcome = executor.apply(plan, [item['id']], approval_for(plan, [item]))
            identifier = outcome['outcomes'][0]['id']
            executor.restore(identifier)
            self.assertEqual(path.read_text(), 'unique settings explicitly scoped')
            plan = Scanner(self.config, self.state, self.process).run()
            item = next(item for item in plan['candidates'] if item['path'] == str(path))
            identifier = executor.apply(plan, [item['id']], approval_for(plan, [item]))['outcomes'][0]['id']
            record = next(row for row in executor.list() if row['id'] == identifier)
            self.bundle('Reinstalled.app', 'net.retired.Tool')
            with self.assertRaisesRegex(SafetyError, 'Installed'):
                executor.purge(identifier, executor.purge_approval(record))
            self.assertTrue(Path(record['quarantine']).exists())

    def test_mixed_root_quotas_keep_duplicates_when_repository_budget_exhausts(self):
        demo = self.root / 'demo'
        create(demo)
        config = json.loads((demo / 'config.json').read_text())
        config['budgets']['repositories'] = 1
        with patch('mactrim.apps.services', return_value=(set(), [])):
            plan = Scanner(validate(config, self.state.path), self.state, self.process).run()
        self.assertTrue(any(row.get('category') == 'repositories' and row['status'] == 'partial' for row in plan['coverage']))
        item = next(item for item in plan['candidates'] if item['kind'] == 'duplicate' and item['eligible'])
        result = Executor(self.state, activity_provider=lambda: self.process).dry_run(plan, [item['id']])
        self.assertTrue(result['approval'].startswith('QUARANTINE'))

    def test_reports_never_call_expensive_fingerprint_and_cancelled_items_unselectable(self):
        (self.preferences / 'net.absent.Unknown.plist').write_text('report')
        with patch('mactrim.apps.services', return_value=(set(), [])), patch('mactrim.apps.fingerprint', side_effect=AssertionError('report hashing')):
            items, _, _ = apps.detect(self.config, self.state.path, self.process)
        self.assertTrue(items[0]['fingerprint']['measurement_only'])
        cancel = threading.Event()
        cancel.set()
        with patch('mactrim.apps.services', return_value=(set(), [])):
            plan = Scanner(self.config, self.state, self.process, cancel=cancel).run()
        self.assertTrue(plan['cancelled'])
        self.assertFalse(any(item['eligible'] for item in plan['candidates']))


class ChurnTests(unittest.TestCase):
    def result(self, pids, unknown=False):
        data = b''.join(('p%s\\0cfixture\\0\\nfcwd\\0tDIR\\0n/fixture\\0\\n' % pid).encode().replace(b'\\0', b'\0').replace(b'\\n', b'\n') for pid in pids)
        if unknown:
            data += b'f3\0n(revoked)\0\n'
        return subprocess.CompletedProcess([], 0, data, b'')

    def test_confirmed_exit_reconciles_without_dropping_surviving_process(self):
        with patch('mactrim.activity.sys.platform', 'darwin'), patch('mactrim.activity._pids', side_effect=[{10: 'fixture'}, {10: 'fixture', 11: 'child'}, {10: 'fixture'}]), patch('mactrim.activity.subprocess.run', return_value=self.result([10])):
            observed = snapshot()
        self.assertTrue(observed.complete, observed.issues)

    def test_surviving_birth_requires_retry_coverage(self):
        inventories = [{10: 'fixture'}, {10: 'fixture', 11: 'child'}, {10: 'fixture', 11: 'child'}] + [{10: 'fixture', 11: 'child'}] * 3
        with patch('mactrim.activity.sys.platform', 'darwin'), patch('mactrim.activity._pids', side_effect=inventories), patch('mactrim.activity.subprocess.run', side_effect=[self.result([10]), self.result([10, 11])]):
            observed = snapshot()
        self.assertTrue(observed.complete, observed.issues)
        self.assertEqual(observed.attempts, 2)
        self.assertIn(11, observed.commands)

    def test_unknown_descriptor_remains_blocking_across_apparently_successful_retry(self):
        inventories = [{10: 'fixture'}] * 9
        with patch('mactrim.activity.sys.platform', 'darwin'), patch('mactrim.activity._pids', side_effect=inventories), patch('mactrim.activity.subprocess.run', side_effect=[self.result([10], unknown=True), self.result([10]), self.result([10])]):
            observed = snapshot()
        self.assertFalse(observed.complete)
        self.assertTrue(any('inaccessible' in issue for issue in observed.issues))


class CrossRootDuplicateTests(unittest.TestCase):
    def test_duplicate_keeper_can_live_in_another_explicit_root_with_independent_quotas(self):
        parent = Path.cwd() / 'evidence'
        parent.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=parent) as temporary:
            root = Path(temporary)
            roots = [root / name for name in ('a', 'b')]
            for path in roots:
                path.mkdir()
                (path / 'copy.txt').write_text('shared fixture content')
            state = State(root / 'state').prepare()
            config = defaults()
            config.update(repo_roots=[], worktree_roots=[], cache_roots=[], app_roots=[], app_data_roots=[], duplicate_roots=[str(path) for path in roots], system_reports=False)
            with patch('mactrim.apps.services', return_value=(set(), [])):
                plan = Scanner(config, state, Activity(True)).run()
            item = next(item for item in plan['candidates'] if item['kind'] == 'duplicate')
            self.assertTrue(item['eligible'])
            self.assertEqual(item['context']['keeper_root'], str(roots[0]))
            self.assertEqual(item['context']['root'], str(roots[1]))
