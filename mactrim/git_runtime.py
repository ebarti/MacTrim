"""Git subprocess boundary: isolated Git environment and no project executables."""
import os
import re
import subprocess

from .safety import SafetyError, clean


def environment():
    # An inherited GIT_DIR/INDEX_FILE/WORK_TREE or injected config cannot redirect
    # a user's approved operation into another repository or execute its hooks.
    env = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
    env.update(GIT_OPTIONAL_LOCKS='0', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT='0')
    return env


def prefix(repo, git_dir=False):
    location = ['--git-dir', str(repo)] if git_dir else ['-C', str(repo)]
    base = ['/usr/bin/git', '--no-optional-locks', '-c', 'core.fsmonitor=false', '-c', 'core.hooksPath=/dev/null', '-c', 'core.attributesFile=/dev/null'] + location
    # Git status/worktree remove can invoke clean/process filters through tracked
    # attributes. Enumerate key names read-only, and explicitly disable drivers.
    result = subprocess.run(base + ['config', '--name-only', '-z', '--get-regexp', r'^filter\..*\.(clean|smudge|process|required)$'], env=environment(), capture_output=True, timeout=10)
    if result.returncode not in (0, 1) or result.stderr or len(result.stdout) > 1024 * 1024:
        raise SafetyError('Cannot establish non-executing Git filter configuration')
    overrides = []
    for raw in result.stdout.split(b'\0'):
        if not raw:
            continue
        key = raw.decode(errors='strict')
        if not re.fullmatch(r'filter\.[A-Za-z0-9_.-]+\.(clean|smudge|process|required)', key):
            raise SafetyError('Unsupported Git filter name; preserve repository')
        overrides += ['-c', key + ('=false' if key.endswith('.required') else '=')]
    # Options precede location/command, so this also covers internal status calls.
    return base[:-len(location)] + overrides + location
