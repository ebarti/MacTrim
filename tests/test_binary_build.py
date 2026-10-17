"""Build-provenance checks operate on disposable repositories, never user data."""
import importlib.util
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from mactrim import activity

SPEC = importlib.util.spec_from_file_location('binary_build', Path(__file__).resolve().parents[1] / 'scripts' / 'build_binary.py')
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)


class BuildProvenance(unittest.TestCase):
    def test_dirty_source_cannot_adopt_clean_ambient_repository_or_run_fsmonitor(self):
        with tempfile.TemporaryDirectory(prefix='mactrim-build-proof-', dir='/private/tmp') as temporary:
            root = Path(temporary)
            environment = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
            environment.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull)
            def git(repository, *arguments):
                return subprocess.run(['/usr/bin/git', '-C', str(repository)] + list(arguments), env=environment,
                                      check=True, capture_output=True, text=True).stdout.strip()
            repositories = []
            for name in ('actual-source', 'ambient-clean'):
                repository = root / name
                repository.mkdir()
                git(repository, 'init', '-q')
                (repository / 'source.py').write_text('original source\n')
                git(repository, 'add', '.')
                git(repository, '-c', 'user.name=MacTrim fixture', '-c', 'user.email=fixture@invalid.example', 'commit', '-qm', name)
                repositories.append(repository)
            actual, ambient = repositories
            marker = root / 'hook-ran'
            hook = root / 'hostile-fsmonitor'
            hook.write_text('#!/bin/sh\n/usr/bin/touch "' + str(marker) + '"\n')
            hook.chmod(0o700)
            git(actual, 'config', 'core.fsmonitor', str(hook))
            hostile = dict(environment, GIT_DIR=str(ambient / '.git'), GIT_WORK_TREE=str(ambient),
                           GIT_INDEX_FILE=str(ambient / '.git' / 'index'), GIT_CONFIG_COUNT='1',
                           GIT_CONFIG_KEY_0='core.fsmonitor', GIT_CONFIG_VALUE_0=str(hook))
            with patch.object(build, 'ROOT', actual):
                source, _ = build.source_revision(hostile)
                self.assertEqual(source, git(actual, 'rev-parse', 'HEAD'))
                self.assertNotEqual(source, git(ambient, 'rev-parse', 'HEAD'))
                (actual / 'source.py').write_text('uncommitted actual source\n')
                with self.assertRaisesRegex(ValueError, 'Commit source changes'):
                    build.source_revision(hostile)
            self.assertFalse(marker.exists())


class FrozenScannerParent(unittest.TestCase):
    def test_verified_parent_only_argv_exemption_retains_real_paths_and_unrelated_pid(self):
        with tempfile.TemporaryDirectory(prefix='mactrim-frozen-proof-', dir='/private/tmp') as temporary:
            root = Path(temporary)
            executable = root / 'mactrim'
            executable.write_bytes(b'owned fixture executable identity')
            candidate = root / 'candidate'
            candidate.mkdir()
            st = executable.stat()
            argv = [str(executable), 'scan', '--repo-root', str(candidate)]
            command = ' '.join(argv)
            uid = os.getuid()
            ps = ('10 9 %s %s\n9 8 %s %s\n' % (uid, command, uid, command)).encode()
            descriptors = b''.join(('p%s\0ftxt\0tREG\0D0x%x\0i%s\0n%s\0\n' % (pid, st.st_dev, st.st_ino, executable)).encode() for pid in (9, 10))
            def result(data, stderr=b'', returncode=0):
                return subprocess.CompletedProcess([], returncode, data, stderr)
            observed = activity.Activity(True, commands={9: command, 10: command})
            with patch.object(activity.sys, 'frozen', True, create=True), patch.object(activity.sys, 'executable', str(executable)), patch.object(activity.sys, 'argv', argv), patch.object(activity.sys, 'prefix', '/global-interpreter'), patch.object(activity.os, 'getpid', return_value=10), patch.object(activity.os, 'getppid', return_value=9):
                with patch.object(activity.subprocess, 'run', side_effect=[result(ps), result(descriptors), result(ps)]):
                    observed._scanner_parent = activity._verified_onefile_parent(observed)
                self.assertEqual(observed._scanner_parent, 9)
                self.assertFalse(observed.blockers(candidate))
                observed.paths = [(9, 'mactrim', str(candidate), 'cwd'), (10, 'mactrim', str(candidate / 'file'), '3')]
                observed.commands[17] = command
                blockers = observed.blockers(candidate)
                self.assertTrue(any('PID 9' in value and 'cwd' in value for value in blockers))
                self.assertTrue(any('PID 10' in value and '3:' in value for value in blockers))
                self.assertTrue(any('PID 17 argv' in value for value in blockers))
                with patch.object(activity.sys, 'prefix', str(candidate / 'environment')):
                    self.assertTrue(any('interpreter environment' in value for value in observed.blockers(candidate)))
                cases = [
                    [result(ps.replace(b'10 9 ', b'10 8 '))],
                    [result(ps), result(descriptors.replace(('i%s' % st.st_ino).encode(), b'i1'))],
                    [result(ps), result(descriptors.replace(b'tREG\0', b''))],
                    [result(ps), result(descriptors.split(b'p10')[0])],
                    [result(ps), result(descriptors), result(ps.replace(b'9 8 ', b'9 7 '))],
                    [result(ps), result(descriptors, stderr=b'incomplete access')],
                    [result(ps), result(descriptors[:-1])],
                ]
                for responses in cases:
                    with self.subTest(responses=responses), patch.object(activity.subprocess, 'run', side_effect=responses):
                        self.assertEqual(activity._verified_onefile_parent(observed), 0)
                observed.commands[9] = command + ' --different'
                self.assertEqual(activity._verified_onefile_parent(observed), 0)
                observed.commands[9] = command
                observed.complete = False
                observed.issues = ['unresolved descriptor']
                self.assertEqual(activity._verified_onefile_parent(observed), 0)
                self.assertIn('unresolved descriptor', observed.blockers(candidate))
                observed.complete = True
                with patch.object(activity.sys, 'frozen', False):
                    self.assertEqual(activity._verified_onefile_parent(observed), 0)


if __name__ == '__main__':
    unittest.main()
