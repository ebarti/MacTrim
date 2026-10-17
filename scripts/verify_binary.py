#!/usr/bin/env python3
"""Exercise an actual binary outside the repository, using disposable data only.

Run with the project Python; subprocesses execute the copied Mach-O, never Python.
No production activity provider is replaced. Unknown real activity must block.
"""
import argparse
import fcntl
import hashlib
import gzip
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
        for i in range(16):
            folder = data / ('stable-' + str(i)); folder.mkdir()
            for j in range(100): (folder / str(j)).write_bytes(b'x' * 100)
        dependency = data / 'node_modules'
        (dependency / 'package' / 'lib').mkdir(parents=True)
        (dependency / 'package' / 'lib' / 'payload').write_bytes(b'd' * 8192)
        deep = data
        for depth in range(1, 14):
            deep /= 'depth-%s' % depth; deep.mkdir()
        (deep / 'payload').write_bytes(b'beyond depth eight')
        storage = json.loads(run(['storage', data, '--json', '--max-files', 100, '--max-depth', 8]).stdout)
        assert storage['measurement']['status'] == 'partial'  # explicit 100-entry preview of >1600 files
        config = root / 'scoped.json'
        config.write_text(json.dumps({'repo_roots': [], 'worktree_roots': [], 'cache_roots': [],
                                     'duplicate_roots': [], 'app_roots': [], 'app_data_roots': [],
                                     'system_reports': False, 'storage_max_files': 100, 'storage_max_depth': 8}))
        state = root / 'state'
        prefix = ['--state', state, '--config', config]
        baseline = json.loads(run(prefix + ['storage', data, '--json', '--full']).stdout)['measurement']
        quiet = json.loads(run(prefix + ['storage', data, '--json']).stdout)['measurement']
        assert quiet['refresh']['mode'] == 'incremental', quiet['refresh']
        for observed in (baseline, quiet):
            diagnostics = observed['refresh']['events']
            assert diagnostics['receiver_pid'] > 0, diagnostics
            assert diagnostics['latency_seconds'] == 1.0, diagnostics
            assert diagnostics['callbacks'] > 0, diagnostics
            assert not diagnostics.get('tracking_error'), diagnostics
        report['event_receiver'] = quiet['refresh']['events']
        assert not quiet['refresh']['warnings'], quiet['refresh']
        assert quiet['logical'] == baseline['logical'] and quiet['allocated'] == baseline['allocated']
        summary = next(row for row in baseline['children'] if row['name'] == 'node_modules')
        assert summary['details_deferred'] and summary['size_state'] == 'measured'
        assert summary['status'] == 'measured'
        assert summary['logical'] >= 8192
        assert baseline['native']['backend'] == 'system-fts'
        index = state / 'storage-cache' / 'index.json.gz'
        saved_index = index.read_bytes()
        assert saved_index.startswith(b'MACTRIM-INDEX-3\n')
        records = gzip.decompress(saved_index[len(b'MACTRIM-INDEX-3\n') + 65:]).splitlines()[1:]
        indexed_paths, deferred = [], 0
        for raw in records:
            row = json.loads(raw); parent, name = row[:2]
            folder = data if parent == -1 else indexed_paths[parent] / name
            indexed_paths.append(folder)
            depth = len(folder.relative_to(data).parts)
            assert depth <= 9
            if depth == 9:
                assert row[-1] is True
                assert row[2] >= len(b'beyond depth eight') and row[9] == 'measured', 'Collapsed depth boundary lost recursive bytes'
                deferred += 1
        assert deferred > 0
        report['lazy_depth_boundary'] = {'detailed_levels': 8, 'unopened_level': 9, 'aggregate_measured': True}
        detail = json.loads(run(['--state', root / 'detail-state', '--config', config,
                                 'storage', dependency, '--json']).stdout)['measurement']
        assert not detail['details_deferred'] and detail['children']
        assert detail['logical'] == summary['logical'] and detail['status'] == 'measured'
        assert index.read_bytes() == saved_index
        report['lazy_dependency_details'] = {'aggregate_measured': True, 'explicit_details_loaded': True,
                                              'main_index_preserved': True}
        assert quiet['counters']['visited'] < baseline['counters']['visited']
        first = json.loads(run(prefix + ['history', 'capture', data]).stdout)
        (data / 'growing' / 'data.txt').write_bytes(b'a' * 350)
        changed = json.loads(run(prefix + ['storage', data, '--json']).stdout)['measurement']
        assert changed['refresh']['mode'] == 'incremental', changed['refresh']
        assert changed['logical'] - baseline['logical'] == 250
        assert changed['counters']['visited'] < baseline['counters']['visited']
        verified = json.loads(run(prefix + ['storage', data, '--json', '--full']).stdout)['measurement']
        assert (verified['logical'], verified['allocated']) == (changed['logical'], changed['allocated'])
        report['native_restart_replay'] = {'full_visits': baseline['counters']['visited'], 'quiet_visits': quiet['counters']['visited'], 'changed_visits': changed['counters']['visited'], 'delta_logical': 250, 'cache': changed['refresh']['cache']}
        second = json.loads(run(prefix + ['history', 'capture', data]).stdout)
        catalog = json.loads(run(prefix + ['history', 'list']).stdout)
        assert len(catalog['snapshots']) == 2
        comparison = json.loads(run(prefix + ['history', 'compare', first['id'], second['id'], '--metric', 'logical']).stdout)
        assert next(row for row in comparison['rows'] if row['path'] == str(data / 'growing'))['delta'] == 250
        report['history_allocated_bytes'] = catalog['allocated_bytes']
        # More than one page: the largest directory must survive global
        # ranking even when it is last in native filesystem enumeration.
        wide = root / 'wide-directory'; wide.mkdir()
        for i in range(505): (wide / ('folder-%04d' % i)).mkdir()
        with os.scandir(wide) as entries:
            largest = wide / list(entries)[-1].name
        (largest / 'payload').write_bytes(b'x' * 16384)
        wide_result = json.loads(run(['--state', root / 'wide-state', '--config', config,
                                      'storage', wide, '--json', '--full']).stdout)['measurement']
        assert wide_result['children'][0]['name'] == largest.name
        assert len(wide_result['children']) == 500
        assert wide_result['children'][0]['allocated'] >= 16384
        report['global_directory_order'] = {'immediate_folders': 505,
                                            'largest_source_position': 505,
                                            'largest_in_first_page': True}
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
        # Explicit fixture Storage launch exercises all real tabs without a second whole-Mac walk.
        # A real terminal controls the frozen product; no source/Pilot execution.
        master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack('HHHH', 44, 160, 0, 0))
        process = subprocess.Popen([str(executable)] + [str(value) for value in prefix + ['storage', data]],
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
            # Exercise cancellation through the frozen app's real terminal input.
            # Native replay's settling window keeps this fixture refresh active
            # while the user answers; no source injection or whole-Mac scan.
            def terminal_text(start=0):
                return re.sub(r'\x1b\[[0-?]*[ -/]*[@-~]', '', transcript[start:].decode(errors='replace'))
            os.write(master, b'r')
            read_for(.15)
            os.write(master, b'\x1b')
            read_for(.1)
            prompt_start = len(transcript)
            os.write(master, b'\x18')  # Ctrl+X
            read_for(.25)
            assert 'Cancel the Storage scan? [y/n]' in terminal_text(prompt_start), terminal_text(prompt_start)
            os.write(master, b'n')
            read_for(.1)
            prompt_start = len(transcript)
            os.write(master, b'\x18')
            read_for(.25)
            assert 'Cancel the Storage scan? [y/n]' in terminal_text(prompt_start), terminal_text(prompt_start)
            cancelled_start = len(transcript)
            os.write(master, b'y')
            read_for(3)
            assert 'Storage stopped' in terminal_text(cancelled_start), terminal_text(cancelled_start)
            report['actual_pty_cancellation'] = {'escape_does_not_cancel': True, 'confirmation': 'Ctrl+X then N/Y', 'stopped': True}
            os.write(master, b'r')
            read_for(3)
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
            assert 'Receiver:' in text, 'Receiver diagnostics did not render in Storage'
            report['receiver_diagnostics_rendered'] = True
            missing = [content for content in ('quarantine frees 0 bytes', 'Root /', 'Previous compatible', 'Latest observation') if content not in text]
            assert not missing, 'Tab content did not render: ' + repr(missing)
            assert 'Traceback' not in text and 'ModuleNotFoundError' not in text
            assert b'38;2;' in transcript or b'48;2;' in transcript
            report['actual_truecolor_pty_tabs'] = ['Cleanup', 'Storage', 'History / Growth']
            report['actual_scoped_storage_tui'] = True
            report['default_non_tty_refusal'] = True
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
