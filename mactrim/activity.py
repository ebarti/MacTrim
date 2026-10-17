"""macOS lsof snapshots; uncertainty is a mutation blocker."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import subprocess
import sys
import time
import stat

from .safety import canonical, clean, within


def _own_scanner_invocation():
    entry = Path(sys.argv[0])
    is_cli = entry.name == "mactrim" or (entry.parent.name == "mactrim" and entry.name in {"__main__.py", "cli.py"})
    root_flags = ("--repo-root", "--duplicate-root", "--cache-root", "--worktree-root")
    has_root_flag = any(argument == flag or argument.startswith(flag + "=") for argument in sys.argv[1:] for flag in root_flags)
    return is_cli and "scan" in sys.argv[1:] and has_root_flag


@dataclass
class Activity:
    complete: bool
    paths: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    captured_at: float = field(default_factory=time.time)
    commands: dict = field(default_factory=dict, repr=False)
    attempts: int = 1
    _scanner_parent: int = field(default=0, init=False, repr=False)

    def blockers(self, root):
        blockers = list(self.issues) if not self.complete else []
        for pid, command, path, descriptor in self.paths:
            if within(path, root):
                blockers.append("Active PID %s (%s), %s: %s" % (pid, clean(command), clean(descriptor), clean(path)))
        scoped = str(canonical(root))
        for pid, command_line in self.commands.items():
            if pid in {os.getpid(), self._scanner_parent} and _own_scanner_invocation():
                # CLI root flags authorize inspection and are not evidence of
                # self-use. Actual cwd/open handles still apply; preserve an env
                # in which MacTrim itself is running, even if Python is a symlink.
                if within(sys.prefix, root):
                    blockers.append("MacTrim's own interpreter environment uses this scope")
                continue
            # ps argv catches venv interpreters whose symlink resolves to a global
            # executable after pyvenv.cfg and startup files have been closed.
            if scoped + "/" in command_line or scoped in command_line:
                blockers.append("Active PID %s argv references this project/artifact scope" % pid)
        return sorted(set(blockers))

    def summary(self):
        return {"complete": self.complete, "issues": self.issues, "observed_paths": len(self.paths),
                "captured_at": self.captured_at, "attempts": self.attempts, "provider": "macOS lsof + ps", "scope": "current UID, non-zombie cwd/open/executable paths + ps argv references; other UIDs unobserved"}


def _pids():
    process = subprocess.Popen(["/bin/ps", "-U", str(os.getuid()), "-ww", "-o", "pid=,uid=,stat=,command="], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        stdout, stderr = process.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.communicate()
        raise
    if process.returncode or stderr:
        raise ValueError("ps process inventory failed")
    pids = {}
    for line in stdout.splitlines():
        fields = line.split(None, 3)
        if len(fields) != 4:
            raise ValueError("Malformed ps process inventory")
        pid, uid = int(fields[0]), int(fields[1])
        if uid == os.getuid() and b"Z" not in fields[2] and pid != process.pid:
            pids[pid] = fields[3].decode(errors="surrogateescape")
    return pids


def _verified_onefile_parent(observed):
    """Prove a direct onefile bootloader parent; exempt only its scanner argv.

    This extra scoped observation never changes coverage or path blockers. Any
    mismatch retains the ordinary conservative parent argv interpretation.
    """
    if not observed.complete or not getattr(sys, 'frozen', False) or not _own_scanner_invocation():
        return 0
    own, parent = os.getpid(), os.getppid()
    expected_command = ' '.join([sys.executable] + sys.argv[1:])
    if observed.commands.get(own) != expected_command or observed.commands.get(parent) != expected_command:
        return 0
    try:
        executable = canonical(sys.executable)
        original = os.lstat(executable)
        if not stat.S_ISREG(original.st_mode) or original.st_uid != os.getuid():
            return 0
        def inventory():
            result = subprocess.run(['/bin/ps', '-ww', '-p', '%s,%s' % (own, parent),
                                     '-o', 'pid=,ppid=,uid=,command='], capture_output=True, timeout=3)
            if result.returncode or result.stderr or len(result.stdout) > 65536:
                raise ValueError('Unknown onefile process inventory')
            records = {}
            for line in result.stdout.splitlines():
                fields = line.split(None, 3)
                if len(fields) != 4:
                    raise ValueError('Malformed onefile process inventory')
                pid, ppid, uid = map(int, fields[:3])
                records[pid] = (ppid, uid, fields[3].decode(errors='surrogateescape'))
            if set(records) != {own, parent} or records[own] != (parent, os.getuid(), expected_command) or records[parent][1:] != (os.getuid(), expected_command):
                raise ValueError('Onefile parent ancestry/argv changed')
            return records
        before = inventory()
        result = subprocess.run(['/usr/sbin/lsof', '-nP', '-a', '-p', '%s,%s' % (own, parent),
                                 '-d', 'txt', '-F0pftDin'], capture_output=True, timeout=3)
        if result.returncode or result.stderr or not result.stdout.endswith(b'\n') or len(result.stdout) > 65536:
            return 0
        pid, record, matched = None, {}, set()
        def finish():
            if not record:
                return
            if set(record) != {'f', 't', 'D', 'i', 'n'} or record['f'] != 'txt' or record['t'] != 'REG' or not record['n'].startswith('/'):
                raise ValueError('Unknown executable descriptor')
            if canonical(record['n']) == executable:
                if int(record['D'], 16) != original.st_dev or int(record['i']) != original.st_ino:
                    raise ValueError('Executable identity mismatch')
                matched.add(pid)
        for field in result.stdout.split(b'\0'):
            field = field.lstrip(b'\n')
            if not field:
                continue
            key, value = chr(field[0]), field[1:].decode(errors='surrogateescape')
            if key == 'p':
                finish()
                pid, record = int(value), {}
                if pid not in {own, parent}:
                    return 0
            elif key == 'f':
                finish()
                record = {'f': value}
            elif key in {'t', 'D', 'i', 'n'} and pid is not None and 'f' in record and key not in record:
                record[key] = value
            else:
                return 0
        finish()
        current = os.lstat(executable)
        if matched != {own, parent} or inventory() != before or os.getppid() != parent or (current.st_dev, current.st_ino, current.st_mode, current.st_uid) != (original.st_dev, original.st_ino, original.st_mode, original.st_uid):
            return 0
        return parent
    except (OSError, ValueError, KeyError, subprocess.TimeoutExpired):
        return 0


def parse_lsof(data, expected, stderr=b"", returncode=0):
    issues = []
    if returncode or stderr.strip():
        issues.append("lsof failed or reported incomplete access: %s" % clean(stderr.decode(errors="replace")[:500]))
    if not data or not data.endswith(b"\n") or b"\0" not in data:
        issues.append("lsof output is empty, truncated or malformed")
    paths = []
    pid = None
    command = "?"
    descriptor = "?"
    file_type = "?"
    has_descriptor = False
    has_name = False
    seen = set()
    cwd = set()
    def finalize_descriptor():
        if has_descriptor and not has_name and file_type in {"REG", "DIR", "?"}:
            issues.append("lsof missing name for %s descriptor: PID %s (%s), fd %s" % (file_type, pid, clean(command), clean(descriptor)))
    for field in data.split(b"\0"):
        field = field.lstrip(b"\n")
        if not field:
            continue
        key, value = chr(field[0]), field[1:].decode(errors="surrogateescape")
        if key == "p":
            finalize_descriptor()
            has_descriptor = False
            has_name = False
            try:
                pid = int(value)
                seen.add(pid)
                command = "?"
                descriptor = "?"
                file_type = "?"
            except ValueError:
                issues.append("lsof malformed PID")
                pid = None
        elif key == "c":
            command = value
        elif key == "f":
            finalize_descriptor()
            descriptor = value
            file_type = "?"
            has_descriptor = True
            has_name = False
        elif key == "t":
            file_type = value
        elif key == "n":
            has_name = True
            if not has_descriptor:
                issues.append("lsof name without descriptor")
            if "(revoked)" in value or "Permission denied" in value or "can't" in value or (file_type in {"REG", "DIR", "?"} and not value.startswith("/")):
                if file_type not in {"CHR", "KQUEUE"}:
                    issues.append("lsof inaccessible %s descriptor: PID %s (%s), fd %s; close/restart that app manually and rescan" % (file_type, pid, clean(command), clean(descriptor)))
            if pid and value.startswith("/"):
                # Deleted-open descriptors still block their containing project.
                path = value.removesuffix(" (deleted)")
                paths.append((pid, command, str(canonical(path)), descriptor))
                if descriptor == "cwd":
                    cwd.add(pid)
        else:
            issues.append("lsof returned unexpected field %s" % clean(key))
    finalize_descriptor()
    missing = expected - seen
    no_cwd = expected - cwd
    if missing:
        issues.append("lsof missed %s live current-user processes" % len(missing))
    if no_cwd:
        issues.append("lsof could not establish cwd for %s live current-user processes" % len(no_cwd))
    if not expected:
        issues.append("Process inventory is empty")
    return Activity(not issues, paths, sorted(set(issues)))


def snapshot():
    if sys.platform != "darwin":
        return Activity(False, issues=["Mutation requires complete macOS lsof activity evidence"])
    # Reconcile short-lived processes within three bounded attempts. A second
    # post-lsof inventory only drops confirmed exits; surviving newborns must
    # be covered on a retry. Descriptor uncertainty is never erased by retries.
    paths, persistent = [], set()
    observed = Activity(False)
    try:
        for attempt in range(1, 4):
            before = _pids()
            result = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-u", str(os.getuid()), "-F0pcftn"], capture_output=True, timeout=25)
            after = _pids()
            surviving = _pids()
            if len(result.stdout) > 32 * 1024 * 1024:
                return Activity(False, issues=["lsof output exceeded the 32 MiB bound"], attempts=attempt)
            expected = set(surviving)
            observed = parse_lsof(result.stdout, expected, result.stderr, result.returncode)
            paths.extend(observed.paths)
            persistent.update(issue for issue in observed.issues if not issue.startswith(("lsof missed ", "lsof could not establish cwd for ")))
            born = expected - set(before)
            if born:
                observed.issues.append("Surviving newly born processes require lsof reconciliation")
            observed.issues = sorted(set(observed.issues) | persistent)
            observed.complete = not observed.issues
            observed.attempts = attempt
            observed.paths = list(dict.fromkeys(paths))
            observed.commands = surviving if isinstance(surviving, dict) else {}
            if observed.complete:
                observed._scanner_parent = _verified_onefile_parent(observed)
                return observed
        return observed
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return Activity(False, paths=paths, issues=sorted(persistent | {"Activity snapshot failed: %s" % clean(exc)}))
