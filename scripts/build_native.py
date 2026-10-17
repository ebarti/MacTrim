#!/usr/bin/env python3
"""Build the read-only system-FTS collector; the shipped binary bundles it."""
from pathlib import Path
import os
import subprocess
import sys

ROOT = Path(__file__).resolve().parent.parent


def build():
    output = ROOT / 'build' / 'native' / 'libmactrim_storage.dylib'
    output.parent.mkdir(parents=True, exist_ok=True)
    pending = output.with_suffix('.pending.dylib')
    subprocess.run(['/usr/bin/clang', '-dynamiclib', '-std=c11', '-O2', '-Wall', '-Wextra', '-Werror',
                    '-o', str(pending), str(ROOT / 'mactrim' / 'native' / 'storage.c')], check=True)
    os.replace(pending, output)
    return output


if __name__ == '__main__':
    if sys.platform != 'darwin':
        raise SystemExit('The native collector requires macOS')
    print(build())
