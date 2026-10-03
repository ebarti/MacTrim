"""macOS lsof snapshots; uncertainty is a mutation blocker."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import subprocess
import sys
import time

from .safety import canonical, clean, within


def _own_scanner_invocation():
    entry = Path(sys.argv[0])
    is_cli = entry.name == "mactrim" or (entry.parent.name == "mactrim" and entry.name in {"__main__.py", "cli.py"})
    root_flags = ("--repo-root", "--duplicate-root", "--cache-root")
    has_root_flag = any(argument == flag or argument.startswith(flag + "=") for argument in sys.argv[1:] for flag in root_flags)
    return is_cli and "scan" in sys.argv[1:] and has_root_flag


@dataclass
class Activity:
    complete: bool
    paths: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    captured_at: float = field(default_factory=time.time)
    commands: dict = field(default_factory=dict, repr=False)

    def blockers(self, root):
        blockers = list(self.issues) if not self.complete else []
        for pid, command, path, descriptor in self.paths:
            if within(path, root):
                blockers.append("Active PID %s (%s), %s: %s" % (pid, clean(command), clean(descriptor), clean(path)))
        scoped = str(canonical(root))
        for pid, command_line in self.commands.items():
            if pid == os.getpid() and _own_scanner_invocation():
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
                "captured_at": self.captured_at, "provider": "macOS lsof + ps", "scope": "current UID, non-zombie cwd/open/executable paths + ps argv references; other UIDs unobserved"}


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
    try:
        before = _pids()
        result = subprocess.run(["/usr/sbin/lsof", "-nP", "-a", "-u", str(os.getuid()), "-F0pcftn"], capture_output=True, timeout=25)
        after = _pids()
        if len(result.stdout) > 32 * 1024 * 1024:
            return Activity(False, issues=["lsof output exceeded the 32 MiB bound"])
        # Include newly born live processes: missing children fail closed rather
        # than disappearing from a stable-intersection inventory.
        observed = parse_lsof(result.stdout, set(after), result.stderr, result.returncode)
        if isinstance(after, dict):
            observed.commands = after
        observed.issues = sorted(set(observed.issues))
        return observed
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        return Activity(False, issues=["Activity snapshot failed: %s" % clean(exc)])
