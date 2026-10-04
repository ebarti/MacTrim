#!/usr/bin/env python3
"""Exercise an actual binary outside the repository, using disposable data only.

Run with the project Python; subprocesses execute the copied Mach-O, never Python.
No production activity provider is replaced. Unknown real activity must block.
"""
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pty
import re
import select
import shutil
import struct
import subprocess
import sys
import tempfile
import termios
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--report', required=True, type=Path)
    args = parser.parse_args()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    binary = args.binary.resolve(strict=True)
    report = {'artifact_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(), 'checks': []}
    with tempfile.TemporaryDirectory(prefix='mactrim-binary-qa-', dir='/private/tmp') as temporary:
        root = Path(temporary).resolve()
        executable = root / 'application' / 'mactrim'
        executable.parent.mkdir()
        shutil.copy2(binary, executable)
        cwd = root / 'unrelated-working-directory'
        cwd.mkdir()
        extraction = root / 'extraction'
        extraction.mkdir()
        empty_path = root / 'empty-path'
        empty_path.mkdir()
        env = dict(os.environ, PATH=str(empty_path), TMPDIR=str(extraction),
                   PYTHONHOME='/nonexistent-python-home', PYTHONPATH='/nonexistent-python-path',
                   TERM='xterm-256color', COLORTERM='truecolor')
        env.pop('NO_COLOR', None)
        for name in list(env):
            if name.startswith('GIT_'):
                env.pop(name)
        def run(arguments, expected=0, timeout=100):
            started = time.monotonic()
            result = subprocess.run([str(executable)] + [str(value) for value in arguments],
                                    cwd=cwd, env=env, capture_output=True, text=True, timeout=timeout)
            elapsed = time.monotonic() - started
            accepted = expected if isinstance(expected, tuple) else (expected,)
            if result.returncode not in accepted:
                raise AssertionError('%s: exit %s; stderr %s' % (arguments, result.returncode, result.stderr))
            if list(extraction.iterdir()):
                raise AssertionError('Normal exit left temporary extraction data')
            report['checks'].append({'arguments': [str(value).replace(str(root), '<fixture>') for value in arguments],
                                     'exit': result.returncode, 'seconds': elapsed})
            return result
        startup = [run(['--version']) for _ in range(3)]
        assert all('MacTrim 0.2.0' in result.stdout for result in startup)
        assert 'history' in run(['--help']).stdout
        assert json.loads(run(['config']).stdout)['history']['enabled']
        no_state = root / 'never-created-state'
        assert 'interactive terminal' in run(['--state', no_state], expected=2).stderr
        assert not no_state.exists()
        data = root / 'storage-data'
        (data / 'growing').mkdir(parents=True)
        (data / 'growing' / 'data.txt').write_bytes(b'a' * 100)
        storage = json.loads(run(['storage', data, '--json', '--max-files', 100, '--max-depth', 8]).stdout)
        assert storage['measurement']['status'] == 'measured'
        config = root / 'scoped.json'
        config.write_text(json.dumps({'repo_roots': [], 'worktree_roots': [], 'cache_roots': [],
                                     'duplicate_roots': [], 'app_roots': [], 'app_data_roots': [],
                                     'system_reports': False, 'storage_max_files': 100, 'storage_max_depth': 8}))
        state = root / 'state'
        prefix = ['--state', state, '--config', config]
        first = json.loads(run(prefix + ['history', 'capture', data]).stdout)
        (data / 'growing' / 'data.txt').write_bytes(b'a' * 350)
        second = json.loads(run(prefix + ['history', 'capture', data]).stdout)
        catalog = json.loads(run(prefix + ['history', 'list']).stdout)
        assert len(catalog['snapshots']) == 2
        comparison = json.loads(run(prefix + ['history', 'compare', first['id'], second['id'], '--metric', 'logical']).stdout)
        assert next(row for row in comparison['rows'] if row['path'] == str(data / 'growing'))['delta'] == 250
        report['history_allocated_bytes'] = catalog['allocated_bytes']
        demo = root / 'demo'
        run(['demo', demo])
        demo_config = demo / 'config.json'
        demo_state = root / 'demo-state'
        manifest = root / 'manifest.json'
        scan_args = ['--state', demo_state, '--config', demo_config, 'scan', '--no-defaults',
                     '--duplicate-root', demo / 'duplicates', '--output', manifest, '--json']
        envelope = json.loads(run(scan_args).stdout)
        plan = envelope['body']
        assert plan['candidates']
        report['real_activity'] = plan['activity']
        report['real_activity']['issues'] = [issue.replace(str(root), '<fixture>') for issue in plan['activity']['issues']]
        report['real_candidate_kinds'] = sorted({item['kind'] for item in plan['candidates']})
        report['scan_argv_blockers'] = sorted({blocker for item in plan['candidates'] for blocker in item['blockers'] if 'argv references' in blocker})
        run(['--state', demo_state, 'review', manifest, '--details'])
        item = next(item for item in plan['candidates'] if item['kind'] == 'duplicate')
        before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (demo / 'duplicates').iterdir()}
        dry = run(['--state', demo_state, 'dry-run', manifest, '--select', item['id']], expected=(0, 2) if item['eligible'] else 2)
        if dry.returncode:
            assert 'Activity evidence incomplete' in dry.stderr or 'Report-only candidate' in dry.stderr
        report['dry_run'] = {'exit': dry.returncode, 'reason': dry.stderr.replace(str(root), '<fixture>').strip()}
        refused = run(['--state', demo_state, 'apply', manifest, '--select', item['id'], '--approve', 'yes'], expected=2)
        assert 'Exact approval required' in refused.stderr or 'Report-only candidate is unselectable' in refused.stderr
        after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in (demo / 'duplicates').iterdir()}
        assert before == after
        assert not list((demo_state / 'quarantine').iterdir())
        report['denied_approval'] = refused.stderr.replace(str(root), '<fixture>').strip()
        if item['eligible']:
            approval = refused.stderr.strip().split('Exact approval required: ', 1)[1]
            # An unrelated process really holds the selected fixture file open.
            # The application still collects authentic macOS ps/lsof evidence.
            helper = subprocess.Popen([sys.executable, '-c',
                                       'import sys,time; f=open(sys.argv[1],"rb"); print("READY",flush=True); time.sleep(60)',
                                       item['path']], cwd=cwd, stdout=subprocess.PIPE, text=True)
            try:
                assert helper.stdout.readline().strip() == 'READY'
                active = run(['--state', demo_state, 'apply', manifest, '--select', item['id'], '--approve', approval], expected=2)
                assert 'Active PID' in active.stderr or 'Activity evidence incomplete' in active.stderr
                assert Path(item['path']).exists()
                assert not list((demo_state / 'quarantine').iterdir())
                report['real_open_file_refusal'] = active.stderr.replace(str(root), '<fixture>').strip()
            finally:
                helper.terminate()
                helper.wait(timeout=8)
                helper.stdout.close()
        else:
            report['real_open_file_refusal'] = 'Initial real activity incomplete; report-only selection refused before mutation'
        # Default entry is exercised with empty discovery scopes and a one-entry,
        # one-level storage budget: root front-door metadata only, no broad walk.
        ui_config = json.loads(config.read_text())
        ui_config.update(storage_max_files=1, storage_max_depth=1)
        config.write_text(json.dumps(ui_config))
        # A real terminal controls the frozen product; no source/Pilot execution.
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 44, 160, 0, 0))
        process = subprocess.Popen([str(executable)] + [str(value) for value in prefix],
                                   cwd=cwd, env=env, stdin=slave, stdout=slave, stderr=slave, start_new_session=True)
        os.close(slave)
        transcript = bytearray()
        def read_for(seconds):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if select.select([master], [], [], .05)[0]:
                    try:
                        chunk = os.read(master, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    transcript.extend(chunk)
        try:
            read_for(4)
            if process.poll() is not None:
                raise AssertionError('Frozen TUI exited before rendering: ' + transcript.decode(errors='replace'))
            extracted = list(extraction.glob('_MEI*'))
            assert len(extracted) == 1
            files = [path for path in extracted[0].rglob('*') if path.is_file() and not path.is_symlink()]
            report['extraction_logical_bytes'] = sum(path.stat().st_size for path in files)
            report['extraction_allocated_bytes'] = sum(path.stat().st_blocks * 512 for path in files)
            report['extraction_files'] = len(files)
            assert not any('.venv' in path.parts or 'evidence' in path.parts or 'tests' in path.parts for path in files)
            # Mouse clicks on Textual's real tab strip (row2), then quit from a
            # non-input widget. Labels/content must arrive in terminal output.
            for x in (6, 14, 27):
                os.write(master, ('\x1b[<0;%s;2M\x1b[<0;%s;2m' % (x, x)).encode())
                read_for(.7)
            os.write(master, b'q')
            read_for(1)
            process.wait(timeout=8)
            assert process.returncode == 0
            assert not list(extraction.iterdir())
            text = re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', transcript.decode(errors='replace'))
            args.report.with_suffix('.ansi').write_bytes(transcript)
            assert all(label in text for label in ('Cleanup', 'Storage', 'History / Growth'))
            missing = [content for content in ('quarantine frees 0 bytes', 'Root /', 'Parent/child deltas overlap') if content not in text]
            assert not missing, 'Tab content did not render: ' + repr(missing)
            assert 'Traceback' not in text and 'ModuleNotFoundError' not in text
            assert b'38;2;' in transcript or b'48;2;' in transcript
            report['actual_truecolor_pty_tabs'] = ['Cleanup', 'Storage', 'History / Growth']
            report['actual_default_tui'] = True
            report['pty_normal_exit'] = process.returncode
        finally:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=8)
            os.close(master)
        report['no_python_path'] = True
        report['poisoned_python_variables'] = True
        report['normal_extraction_cleanup'] = True
    args.report.write_text(json.dumps(report, indent=2, sort_keys=True) + '\n')
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == '__main__':
    main()
