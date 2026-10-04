#!/usr/bin/env python3
"""Pinned native onefile build in project-owned isolated directories."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parent.parent
LOCK = ROOT / 'bundle' / 'requirements-build.txt'
SPEC = ROOT / 'bundle' / 'mactrim.spec'


def run(args, env, **kwargs):
    return subprocess.run([str(arg) for arg in args], cwd=ROOT, env=env, check=True, **kwargs)


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--python', default=sys.executable, help='Native arm64 CPython 3.12.12 used only to build')
    args = parser.parse_args()
    env = dict(os.environ)
    for key in ('PYTHONHOME', 'PYTHONPATH', 'PYTHONOPTIMIZE'):
        env.pop(key, None)
    env.update(PYTHONNOUSERSITE='1', PYTHONHASHSEED='0', PYINSTALLER_CONFIG_DIR=str(ROOT / 'build' / 'pyinstaller-cache'))
    info = json.loads(run([args.python, '-I', '-c', 'import json,platform,sys;print(json.dumps([sys.platform,platform.machine(),list(sys.version_info[:3])]))'], env, capture_output=True, text=True).stdout)
    if info != ['darwin', 'arm64', [3, 12, 12]]:
        parser.error('This pinned configuration requires native arm64 macOS CPython 3.12.12')
    if run(['git', 'status', '--porcelain', '--untracked-files=normal'], env, capture_output=True, text=True).stdout:
        parser.error('Commit source changes first so artifact provenance names the exact clean revision')
    source = run(['git', 'rev-parse', 'HEAD'], env, capture_output=True, text=True).stdout.strip()
    env['SOURCE_DATE_EPOCH'] = run(['git', 'show', '-s', '--format=%ct', 'HEAD'], env, capture_output=True, text=True).stdout.strip()
    build = ROOT / 'build'
    build.mkdir(exist_ok=True)
    venv = build / 'binary-venv'
    if not venv.exists():
        run([args.python, '-I', '-m', 'venv', venv], env)
    python = venv / 'bin' / 'python'
    run([python, '-I', '-m', 'pip', '--isolated', 'install', '--disable-pip-version-check', '--no-cache-dir', '--require-hashes', '--no-deps', '-r', LOCK], env)
    run([python, '-I', '-m', 'pip', 'check'], env)
    installed = json.loads(run([python, '-I', '-c', 'import importlib.metadata as m,json; print(json.dumps({d.metadata["Name"]:d.version for d in m.distributions()}))'], env, capture_output=True, text=True).stdout)
    normalize = lambda name: re.sub(r'[-_.]+', '-', name).lower()
    expected = {normalize(name): version for name, version in re.findall(r'^([\w.-]+)==([^ ]+)', LOCK.read_text(), re.M)}
    actual = {normalize(name): version for name, version in installed.items()}
    if actual != expected:
        parser.error('Isolated build environment contains unexpected or mismatched packages; inspect build/binary-venv')
    with tempfile.TemporaryDirectory(prefix='binary-output-', dir=build) as directory:
        output = Path(directory)
        run([python, '-I', '-m', 'PyInstaller', '--clean', '--noconfirm', '--distpath', output, '--workpath', build / 'binary-work', SPEC], env)
        artifact = output / 'mactrim'
        run(['/usr/bin/codesign', '--verify', '--strict', artifact], env)
        architecture = run(['/usr/bin/lipo', '-archs', artifact], env, capture_output=True, text=True).stdout.strip()
        if architecture != 'arm64':
            parser.error('Unexpected artifact architecture: ' + architecture)
        st = artifact.stat()
        report = {'source_sha': source, 'architecture': architecture, 'python': '3.12.12',
                  'pyinstaller': actual['pyinstaller'], 'optimization': 0,
                  'lock_sha256': sha(LOCK), 'spec_sha256': sha(SPEC),
                  'artifact_sha256': sha(artifact), 'artifact_bytes': st.st_size,
                  'artifact_allocated_bytes': st.st_blocks * 512,
                  'signing': 'ad-hoc; not Apple Developer signed or notarized',
                  'dependencies': actual}
        destination = ROOT / 'dist'
        destination.mkdir(exist_ok=True)
        os.replace(artifact, destination / 'mactrim')
        temporary = output / 'mactrim.build.json'
        temporary.write_text(json.dumps(report, sort_keys=True, indent=2) + '\n')
        os.replace(temporary, destination / 'mactrim.build.json')
    print(json.dumps(report, sort_keys=True, indent=2))


if __name__ == '__main__':
    main()
