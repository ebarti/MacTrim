import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from mactrim.activity import Activity
from mactrim.config import defaults, validate
from mactrim.executor import Executor, approval_for
from mactrim.git_runtime import environment
from mactrim.scanner import candidate
from mactrim.safety import SafetyError
from mactrim.state import State, SCHEMA
from mactrim import worktrees


class WorktreeTests(unittest.TestCase):
    def setUp(self):
        parent = Path.cwd() / 'evidence'
        parent.mkdir(exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(dir=parent)
        self.root = Path(self.temporary.name)
        self.primary = self.root / 'primary'
        self.primary.mkdir()
        self.git(self.primary, 'init', '-qb', 'main')
        (self.primary / 'hello.txt').write_text('retained source\n')
        (self.primary / '.gitignore').write_text('reports/\n.venv/\n')
        self.git(self.primary, 'add', '.')
        self.git(self.primary, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid.example', 'commit', '-qm', 'base')
        self.wt_root = self.root / 'worktrees'
        self.wt_root.mkdir()
        self.linked = self.wt_root / 'merged'
        self.git(self.primary, 'worktree', 'add', '-qb', 'fixture-merged', str(self.linked), 'main')
        self.state = State(self.root / 'state').prepare()
        self.config = defaults()
        self.config.update(repo_roots=[], cache_roots=[], duplicate_roots=[], app_roots=[], app_data_roots=[], worktree_roots=[str(self.wt_root)], system_reports=False, github_squash=False)
        self.config = validate(self.config, self.state.path)
        self.process = Activity(True)
        self.executor = Executor(self.state, activity_provider=lambda: self.process)

    def tearDown(self):
        self.temporary.cleanup()

    def git(self, repo, *args):
        result = subprocess.run(['/usr/bin/git', '-C', str(repo)] + list(args), env=environment(), capture_output=True, check=True)
        return result.stdout.decode().strip()

    def plan(self):
        fp, context = worktrees.policy(self.linked, self.config, self.state.path, self.process)
        item = candidate(self.linked, 'git-worktree', context, fp, ['Fixture incorporated HEAD'], [], 'Git aware')
        import time
        return {'schema': SCHEMA, 'created_at': time.time(), 'state': str(self.state.path), 'config': self.config, 'activity': self.process.summary(), 'coverage': [], 'issues': [], 'apps': {}, 'candidates': [item], 'totals': {'logical': fp['logical'], 'allocated': fp['allocated']}}

    def move(self, executor=None):
        plan = self.plan()
        item = plan['candidates'][0]
        result = (executor or self.executor).apply(plan, [item['id']], approval_for(plan, [item]))
        self.assertEqual(result['outcomes'][0]['status'], 'quarantined', result)
        return result['outcomes'][0]['id']

    def test_merged_registered_worktree_and_detached_are_typed(self):
        items, coverage = worktrees.discover([str(self.wt_root)], self.config, self.state.path, self.process)
        linked = next(item for item in items if item['path'] == str(self.linked))
        primary = next(item for item in items if item['path'] == str(self.primary))
        self.assertTrue(linked['eligible'], linked['blockers'])
        self.assertFalse(primary['eligible'])
        self.assertEqual(linked['context']['merge_proof']['type'], 'git-ancestor')
        self.git(self.primary, 'worktree', 'add', '-q', '--detach', str(self.wt_root / 'detached'), 'main')
        fp, context = worktrees.policy(self.wt_root / 'detached', self.config, self.state.path, self.process)
        self.assertEqual(context['branch'], 'detached')

    def test_unmerged_dirty_ignored_locked_current_and_active_are_protected(self):
        (self.linked / 'new.txt').write_text('unique untracked')
        with self.assertRaisesRegex(SafetyError, 'Dirty or untracked'):
            self.plan()
        (self.linked / 'new.txt').unlink()
        (self.linked / 'reports').mkdir()
        (self.linked / 'reports' / 'unique.txt').write_text('unique ignored report')
        with self.assertRaisesRegex(SafetyError, 'ignored'):
            self.plan()
        shutil.rmtree(self.linked / 'reports')
        self.git(self.primary, 'worktree', 'lock', str(self.linked))
        with self.assertRaisesRegex(SafetyError, 'Locked'):
            self.plan()
        self.git(self.primary, 'worktree', 'unlock', str(self.linked))
        with patch('mactrim.worktrees.os.getcwd', return_value=str(self.linked)):
            with self.assertRaisesRegex(SafetyError, 'Current checkout'):
                self.plan()
        self.process.paths = [(12, 'fixture', str(self.linked), 'cwd')]
        with self.assertRaisesRegex(SafetyError, 'Active PID'):
            self.plan()
        self.process.paths = []
        (self.linked / 'hello.txt').write_text('unique committed change')
        self.git(self.linked, 'add', 'hello.txt')
        self.git(self.linked, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid.example', 'commit', '-qm', 'unique')
        with self.assertRaisesRegex(SafetyError, 'not proven incorporated'):
            self.plan()

    def test_submodule_blocks_even_when_merge_proven(self):
        head = self.git(self.primary, 'rev-parse', 'HEAD')
        self.git(self.linked, 'update-index', '--add', '--cacheinfo', '160000,' + head + ',module')
        self.git(self.linked, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid.example', 'commit', '-qm', 'gitlink')
        self.git(self.primary, 'merge', '--ff-only', 'fixture-merged')
        with self.assertRaisesRegex(SafetyError, 'submodules'):
            self.plan()

    def test_git_aware_move_restore_purge_keeps_branch_registry_and_ref(self):
        identifier = self.move()
        record = self.executor.list()[0]
        q = Path(record['quarantine'])
        common = worktrees.common_dir(self.primary)
        self.assertFalse(self.linked.exists())
        self.assertTrue(q.exists())
        self.assertIn(str(q), [row['worktree'] for row in worktrees.registrations(common)])
        self.assertEqual(self.git(q, 'rev-parse', 'HEAD'), record['candidate']['context']['head'])
        self.assertEqual(self.executor.restore(identifier)['status'], 'restored')
        self.assertIn(str(self.linked), [row['worktree'] for row in worktrees.registrations(common)])
        second = self.move()
        second_record = next(row for row in self.executor.list() if row['id'] == second)
        self.assertEqual(self.executor.purge(second, self.executor.purge_approval(second_record))['status'], 'purged')
        self.assertNotIn(second_record['quarantine'], [row['worktree'] for row in worktrees.registrations(common)])
        self.assertEqual(self.git(self.primary, 'rev-parse', second_record['recovery_ref']), second_record['candidate']['context']['head'])
        self.assertTrue(self.git(self.primary, 'show-ref', 'refs/heads/fixture-merged'))

    def test_crash_between_rename_and_registry_update_repairs_exact_tree(self):
        plan = self.plan()
        item = plan['candidates'][0]
        original_rename = worktrees.rename_exclusive
        def interrupted_rename(*args):
            original_rename(*args)
            raise SystemExit('crash before gitdir pointer update')
        with patch('mactrim.worktrees.rename_exclusive', side_effect=interrupted_rename):
            with self.assertRaises(SystemExit):
                self.executor.apply(plan, [item['id']], approval_for(plan, [item]))
        record = self.executor.list()[0]
        self.assertEqual(record['status'], 'quarantined', record['outcomes'])
        self.assertIn(record['quarantine'], [row['worktree'] for row in worktrees.registrations(worktrees.common_dir(self.primary))])
        self.executor.restore(record['id'])
        self.assertTrue(self.linked.exists())

    def test_hostile_hooks_filters_and_ambient_git_env_never_execute(self):
        common = worktrees.common_dir(self.primary)
        sentinel = self.root / 'executed-project-script'
        for name in ('reference-transaction', 'post-checkout', 'pre-commit'):
            hook = common / 'hooks' / name
            hook.write_text('#!/bin/sh\ntouch "' + str(sentinel) + '"\n')
            hook.chmod(0o755)
        self.git(self.primary, 'config', 'filter.fixture.clean', 'touch "' + str(sentinel) + '"; cat')
        (self.primary / '.gitattributes').write_text('*.txt filter=fixture\n')
        self.git(self.primary, 'add', '.gitattributes')
        self.git(self.primary, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid.example', 'commit', '-qm', 'attributes')
        # Setup Git can run hooks by design; discard only fixture sentinel before
        # exercising the application's isolated Git boundary.
        if sentinel.exists():
            sentinel.unlink()
        self.git(self.linked, 'merge', '--ff-only', 'main')
        if sentinel.exists():
            sentinel.unlink()
        bad = {'GIT_DIR': str(self.root / 'wrong'), 'GIT_WORK_TREE': str(self.root / 'wrong'), 'GIT_INDEX_FILE': str(self.root / 'wrong-index'), 'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.hooksPath', 'GIT_CONFIG_VALUE_0': str(common / 'hooks')}
        with patch.dict(os.environ, bad):
            identifier = self.move()
            self.executor.restore(identifier)
            second = self.move()
            record = next(row for row in self.executor.list() if row['id'] == second)
            self.executor.purge(second, self.executor.purge_approval(record))
        self.assertFalse(sentinel.exists())
        self.assertFalse((self.root / 'wrong-index').exists())

    def test_squash_proof_requires_exact_head_and_retained_merge_commit(self):
        self.git(self.primary, 'remote', 'add', 'origin', 'https://github.com/example/fixture.git')
        self.config['github_squash'] = True
        head = self.git(self.primary, 'rev-parse', 'HEAD')
        response = subprocess.CompletedProcess([], 0, json.dumps([{'merged_at': 'today', 'head': {'sha': 'f' * 40}, 'base': {'ref': 'main'}, 'merge_commit_sha': head, 'html_url': 'https://github.com/example/fixture/pull/1'}]).encode(), b'')
        original_run = subprocess.run
        def run(args, **kwargs):
            return response if args[0] == 'gh' else original_run(args, **kwargs)
        with patch('mactrim.worktrees.subprocess.run', side_effect=run):
            self.assertIsNone(worktrees._github_squash(worktrees.common_dir(self.primary), head, 'refs/heads/main', head, self.config))

    def test_occupied_exact_move_slot_is_preserved_without_nested_move(self):
        plan = self.plan()
        item = plan['candidates'][0]
        rename = worktrees.rename_exclusive
        created = []
        def inserted(source_fd, source_name, target_fd, target_name):
            target = self.state.path / 'quarantine' / target_name
            target.mkdir()
            (target / 'unique-marker.txt').write_text('preserve destination')
            created.append(target)
            return rename(source_fd, source_name, target_fd, target_name)
        with patch('mactrim.worktrees.rename_exclusive', side_effect=inserted):
            result = self.executor.apply(plan, [item['id']], approval_for(plan, [item]))
        self.assertEqual(result['outcomes'][0]['status'], 'blocked')
        self.assertTrue(self.linked.exists())
        self.assertEqual((created[0] / 'unique-marker.txt').read_text(), 'preserve destination')
        self.assertFalse((created[0] / self.linked.name).exists())
        self.assertEqual(self.git(self.linked, 'status', '--porcelain'), '')

    def test_inserted_ignored_data_at_worktree_purge_boundary_is_retained(self):
        identifier = self.move()
        record = self.executor.list()[0]
        q = Path(record['quarantine'])
        remove = worktrees.remove_tree_fd
        unique = q / 'reports' / 'unapproved.txt'
        def inserted(fd, name, approved, relative=''):
            if name == q.name:
                unique.parent.mkdir()
                unique.write_text('unique ignored evidence')
            return remove(fd, name, approved, relative)
        with patch('mactrim.worktrees.remove_tree_fd', side_effect=inserted):
            with self.assertRaisesRegex(SafetyError, 'Unexpected descendant'):
                self.executor.purge(identifier, self.executor.purge_approval(record))
        self.assertEqual(unique.read_text(), 'unique ignored evidence')
        self.assertTrue(Path(record['candidate']['context']['admin_dir']).exists())

    def test_new_or_replaced_admin_entry_is_preserved_after_content_purge(self):
        identifier = self.move()
        record = self.executor.list()[0]
        admin = Path(record['candidate']['context']['admin_dir'])
        finish = worktrees.finish_registration
        unique = admin / 'unique-new-admin.txt'
        def inserted(row, state, process):
            unique.write_text('do not delete new registry data')
            return finish(row, state, process)
        with patch('mactrim.worktrees.finish_registration', side_effect=inserted):
            with self.assertRaisesRegex(SafetyError, 'registration changed'):
                self.executor.purge(identifier, self.executor.purge_approval(record))
        self.assertEqual(unique.read_text(), 'do not delete new registry data')
        self.assertTrue(admin.exists())
        self.assertTrue(self.state.journals()[0]['admin_snapshots'][-1]['path'])
        self.assertFalse(Path(record['quarantine']).exists())
        self.assertEqual(self.executor.list()[0]['status'], 'conflicted')

    def test_crash_after_content_purge_before_admin_removal_recovers_exact_registry(self):
        identifier = self.move()
        record = self.executor.list()[0]
        with patch('mactrim.worktrees.finish_registration', side_effect=SystemExit('after content before admin')):
            with self.assertRaises(SystemExit):
                self.executor.purge(identifier, self.executor.purge_approval(record))
        self.assertFalse(Path(record['quarantine']).exists())
        admin = Path(record['candidate']['context']['admin_dir'])
        self.assertTrue(admin.exists())
        recovered = self.executor.list()[0]
        self.assertEqual(recovered['status'], 'purged', recovered['outcomes'])
        self.assertFalse(admin.exists())
        self.assertTrue(Path(recovered['admin_snapshots'][-1]['path']).exists())
        self.assertTrue(self.git(self.primary, 'show-ref', 'refs/heads/fixture-merged'))

    def test_partial_approved_content_purge_requires_fresh_approval_and_resumes_subset(self):
        identifier = self.move()
        record = self.executor.list()[0]
        q = Path(record['quarantine'])
        remove = worktrees.remove_tree_fd
        def partial(fd, name, approved, relative=''):
            if name == q.name:
                (q / 'hello.txt').unlink()
                raise SystemExit('partial fixture purge')
            return remove(fd, name, approved, relative)
        with patch('mactrim.worktrees.remove_tree_fd', side_effect=partial):
            with self.assertRaises(SystemExit):
                self.executor.purge(identifier, self.executor.purge_approval(record))
        self.assertTrue(q.exists())
        recovered = self.executor.list()[0]
        self.assertEqual(recovered['status'], 'purging')
        self.assertEqual(self.executor.purge(identifier, self.executor.purge_approval(recovered))['status'], 'purged')

    def test_ignored_environment_requires_tracked_spec_and_known_generated_layout(self):
        env = self.linked / '.venv'
        env.mkdir()
        (env / 'pyvenv.cfg').write_text('home = /usr/bin\n')
        (env / 'unique-installed-state.txt').write_text('unique installed state')
        with self.assertRaisesRegex(SafetyError, 'tracked dependency'):
            self.plan()
        (self.linked / 'pyproject.toml').write_text('[project]\nname="fixture"\nversion="0.0.0"\ndependencies=[]\n')
        self.git(self.linked, 'add', 'pyproject.toml')
        self.git(self.linked, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@invalid.example', 'commit', '-qm', 'spec')
        self.git(self.primary, 'merge', '--ff-only', 'fixture-merged')
        with self.assertRaisesRegex(SafetyError, 'unique ignored environment'):
            self.plan()
        (env / 'unique-installed-state.txt').unlink()
        self.assertTrue(self.plan()['candidates'][0]['eligible'])

    def test_redirected_per_worktree_configuration_cannot_hide_dirty_selected_scope(self):
        mirror = self.root / 'clean-mirror'
        mirror.mkdir()
        (mirror / 'hello.txt').write_text('retained source\n')
        (mirror / '.gitignore').write_text('reports/\n.venv/\n')
        self.git(self.primary, 'config', 'extensions.worktreeConfig', 'true')
        self.git(self.linked, 'config', '--worktree', 'core.worktree', str(mirror))
        (self.linked / 'hello.txt').write_text('unique changed source hidden by mirror')
        with self.assertRaisesRegex(SafetyError, 'scope is redirected'):
            self.plan()
        self.assertEqual((self.linked / 'hello.txt').read_text(), 'unique changed source hidden by mirror')

    def test_hidden_index_flags_cannot_hide_unique_tracked_data(self):
        for flag in ('--assume-unchanged', '--skip-worktree'):
            self.git(self.linked, 'update-index', flag, 'hello.txt')
            (self.linked / 'hello.txt').write_text('unique changed source')
            self.assertEqual(self.git(self.linked, 'status', '--porcelain'), '')
            with self.assertRaisesRegex(SafetyError, 'Hidden index'):
                self.plan()
            self.git(self.linked, 'update-index', '--no-assume-unchanged', '--no-skip-worktree', 'hello.txt')
            (self.linked / 'hello.txt').write_text('retained source\n')

    def test_exact_pointer_repair_never_rewrites_unrelated_broken_git_file(self):
        other = self.wt_root / 'other'
        self.git(self.primary, 'worktree', 'add', '-q', '--detach', str(other), 'main')
        pointer = other / '.git'
        pointer.write_text('gitdir: /nonexistent/fixture-unique-pointer\n')
        before = pointer.read_bytes(), pointer.stat().st_ino
        identifier = self.move()
        self.executor.restore(identifier)
        self.assertEqual((pointer.read_bytes(), pointer.stat().st_ino), before)

    def test_crash_after_capturing_old_admin_pointer_recovers_prepared_exact_replacement(self):
        rename = worktrees.rename_exclusive
        def crash(source_fd, source_name, target_fd, target_name):
            rename(source_fd, source_name, target_fd, target_name)
            if source_name == 'gitdir':
                raise SystemExit('pointer captured before installing replacement')
        with patch('mactrim.worktrees.rename_exclusive', side_effect=crash):
            with self.assertRaises(SystemExit):
                self.move()
        recovered = self.executor.list()[0]
        self.assertEqual(recovered['status'], 'quarantined', recovered['outcomes'])
        self.assertEqual(self.git(Path(recovered['quarantine']), 'status', '--porcelain'), '')
        self.executor.restore(recovered['id'])

    def test_raced_in_admin_pointer_is_preserved_with_both_recovery_files(self):
        rename = worktrees.rename_exclusive
        unique = b'gitdir raced-in unique administrative data\n'
        def insert(source_fd, source_name, target_fd, target_name):
            if target_name == 'gitdir':
                fd = os.open('gitdir', os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=target_fd)
                os.write(fd, unique)
                os.close(fd)
            return rename(source_fd, source_name, target_fd, target_name)
        with patch('mactrim.worktrees.rename_exclusive', side_effect=insert):
            plan = self.plan()
            item = plan['candidates'][0]
            result = self.executor.apply(plan, [item['id']], approval_for(plan, [item]))
        self.assertEqual(result['outcomes'][0]['status'], 'blocked')
        record = self.state.journals()[0]
        admin = Path(record['candidate']['context']['admin_dir'])
        self.assertEqual((admin / 'gitdir').read_bytes(), unique)
        self.assertTrue(Path(record['pointer_transition']['backup']).exists())
        self.assertTrue(Path(record['pointer_transition']['replacement']).exists())

    def test_common_git_directory_replacement_is_not_adopted_as_original_repository(self):
        plan = self.plan()
        item = plan['candidates'][0]
        context = item['context']
        common = Path(context['common_dir'])
        displaced = self.root / 'genuine-common'
        common.rename(displaced)
        shutil.copytree(displaced, common)
        admin = Path(context['admin_dir'])
        old_admin = displaced / 'worktrees' / admin.name
        shutil.rmtree(admin)  # disposable replacement admin, preserve genuine inode
        old_admin.rename(admin)
        with self.assertRaisesRegex(SafetyError, 'common Git directory'):
            self.executor.apply(plan, [item['id']], approval_for(plan, [item]))
        self.assertTrue(self.linked.exists())
        self.assertFalse((common / 'refs' / 'mactrim').exists())

    def test_missing_checkout_after_only_purge_authorization_does_not_delete_registry(self):
        identifier = self.move()
        record = self.executor.list()[0]
        q = Path(record['quarantine'])
        admin = Path(record['candidate']['context']['admin_dir'])
        with patch('mactrim.worktrees.remove_tree_fd', side_effect=SystemExit('before any deletion')):
            with self.assertRaises(SystemExit):
                self.executor.purge(identifier, self.executor.purge_approval(record))
        displaced = self.root / 'intact-displaced-checkout'
        q.rename(displaced)
        recovered = self.executor.list()[0]
        self.assertEqual(recovered['status'], 'conflicted')
        self.assertTrue(admin.exists())
        self.assertTrue((displaced / 'hello.txt').exists())

    def test_restore_refuses_active_captured_admin_or_common_git_scope(self):
        identifier = self.move()
        record = self.executor.list()[0]
        context = record['candidate']['context']
        for active in (Path(context['admin_dir']) / 'index', Path(context['common_dir']) / 'objects'):
            self.process.paths = [(98765, 'fixture-reader', str(active), '3')]
            with self.assertRaisesRegex(SafetyError, 'Active PID'):
                self.executor.restore(identifier)
            self.assertFalse(self.linked.exists())
            self.assertTrue(Path(record['quarantine']).exists())
        self.process.paths = []
        self.assertEqual(self.executor.restore(identifier)['status'], 'restored')
