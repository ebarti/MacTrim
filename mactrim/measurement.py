"""Bounded metadata inventory. This module never hashes or grants deletion rights."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import threading

from .safety import SafetyError, ancestor_identity, canonical, clean, directory_fd, protected

VIRTUAL = {"/dev", "/proc", "/sys", "/private/dev"}
DATA_ALIAS = "/System/Volumes/Data"


@dataclass
class Node:
    path: str
    name: str
    logical: int = 0
    allocated: int = 0
    status: str = "unknown"
    entries: int = 0
    newest_ns: int = 0
    identity: tuple = ()
    issues: list = field(default_factory=list)
    children: list = field(default_factory=list)
    alias_of: str = ""
    kind: str = "directory"
    protected: bool = False

    def summary(self):
        return {"logical": self.logical, "allocated": self.allocated, "entries": self.entries,
                "newest_ns": self.newest_ns, "identity": list(self.identity), "status": self.status,
                "issues": self.issues, "alias_of": self.alias_of, "kind": self.kind,
                "digest": None, "measurement_only": True}

    def export(self):
        return dict(self.summary(), path=self.path, name=self.name, protected=self.protected,
                    children=[child.export() for child in self.children])


class Counter:
    def __init__(self, limit, depth):
        self.limit, self.depth, self.used = limit, depth, 0

    def take(self, level):
        self.used += 1
        if self.used > self.limit or level > self.depth:
            raise SafetyError("Metadata budget/depth exhausted")


def measure(path, max_entries=20000, max_depth=16, cancel=None, progress=None,
            seen=None, storage=False, independent_children=False):
    """No-follow, inode-aware lower bounds; inspect system ownership read-only.

    Storage / uses independent child budgets so /System cannot starve /Users.
    Data's firmlink aliases and virtual trees are explicitly skipped even when
    their st_dev matches /. A drill-down starts its own independent inventory.
    """
    path = canonical(path)
    cancel = cancel or threading.Event()
    seen = seen if seen is not None else {}
    budget = Counter(max_entries, max_depth)
    root = Node(str(path), path.name or "/", protected=bool(protected(path)))
    try:
        root_st = os.lstat(path)
        root_device = root_st.st_dev
        ancestor_identity(path.parent if path != Path("/") else path)
    except (OSError, SafetyError) as exc:
        root.status = "denied"
        root.issues = [clean(exc)]
        return root

    def walk(parent_fd, name, node, level, counter, expected=None):
        if cancel.is_set():
            node.status = "cancelled"
            node.issues.append("Measurement cancelled; totals are lower bounds")
            return
        try:
            counter.take(level)
            st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False) if name else os.fstat(parent_fd)
            node.identity = (st.st_dev, st.st_ino)
            node.newest_ns = st.st_mtime_ns
            node.entries = 1
            if expected and (st.st_dev, st.st_ino, stat.S_IFMT(st.st_mode)) != expected:
                raise SafetyError("Object changed during measurement")
            absolute = node.path
            if storage and (absolute in VIRTUAL or absolute == DATA_ALIAS):
                node.status = "skipped"
                node.alias_of = "/Users and /Applications" if absolute == DATA_ALIAS else ""
                node.issues.append("APFS Data alias; explore /Users and /Applications" if absolute == DATA_ALIAS else "Virtual filesystem; metadata enumeration skipped")
                return
            if stat.S_ISLNK(st.st_mode):
                node.kind = "symlink"
                node.status = "skipped"
                node.issues.append("Symlink target is not followed")
                return
            if getattr(st, "st_flags", 0) & 0x40000000:
                node.status = "skipped"
                node.issues.append("Cloud placeholder; never hydrate")
                return
            if st.st_dev != root_device:
                # User-selected root owns its device. At /, preserve the useful
                # macOS firmlink front doors, but do not recursively visit mounts.
                allow_front = storage and path == Path("/") and absolute in {"/Users", "/Applications"}
                if not allow_front:
                    node.status = "skipped"
                    node.issues.append("Mount boundary")
                    return
            identity = (st.st_dev, st.st_ino)
            if identity in seen:
                node.status = "skipped"
                node.alias_of = seen[identity]
                node.issues.append("Already accounted inode / hardlink / firmlink alias")
                return
            seen[identity] = absolute
            if stat.S_ISREG(st.st_mode):
                node.kind = "file"
                node.logical, node.allocated = st.st_size, getattr(st, "st_blocks", 0) * 512
                node.status = "measured"
                return
            if not stat.S_ISDIR(st.st_mode):
                node.kind = "special"
                node.status = "skipped"
                node.issues.append("Special object; no content read")
                return
            if not st.st_mode & 0o444 or not st.st_mode & 0o111:
                raise PermissionError("Directory metadata inaccessible")
            fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent_fd) if name else os.dup(parent_fd)
            try:
                if (os.fstat(fd).st_dev, os.fstat(fd).st_ino) != identity:
                    raise SafetyError("Directory changed before enumeration")
                node.status = "measured"
                # listdir does not read file content. Its entry count is separately
                # bounded; directory populations beyond the budget are partial.
                names = sorted(os.listdir(fd))
                for child_name in names:
                    child_path = str(Path(absolute) / child_name)
                    child = Node(child_path, child_name, protected=bool(protected(child_path)))
                    node.children.append(child)
                    child_counter = Counter(max_entries, max_depth) if independent_children and level == 0 else counter
                    if child_counter.used >= child_counter.limit:
                        child.status = "partial"
                        child.issues.append("Metadata budget exhausted before this entry")
                    else:
                        walk(fd, child_name, child, level + 1, child_counter)
                    node.logical += child.logical
                    node.allocated += child.allocated
                    node.entries += child.entries
                    node.newest_ns = max(node.newest_ns, child.newest_ns)
                    if child.status != "measured":
                        node.status = "partial" if child.status != "cancelled" else "cancelled"
                    if progress:
                        progress(node, child)
                    if cancel.is_set():
                        node.status = "cancelled"
                        node.issues.append("Remaining entries unmeasured")
                        break
                final = os.fstat(fd)
                if final.st_mtime_ns != st.st_mtime_ns or final.st_ctime_ns != st.st_ctime_ns:
                    node.status = "partial"
                    node.issues.append("Directory changed during metadata enumeration")
            finally:
                os.close(fd)
        except PermissionError as exc:
            node.status = "denied"
            node.issues.append(clean(exc))
        except (OSError, SafetyError) as exc:
            node.status = "partial" if "budget" in str(exc).lower() else "denied"
            node.issues.append(clean(exc))

    try:
        if path == Path("/"):
            with directory_fd(path) as fd:
                walk(fd, "", root, 0, budget)
        else:
            with directory_fd(path.parent) as fd:
                walk(fd, path.name, root, 0, budget, (root_st.st_dev, root_st.st_ino, stat.S_IFMT(root_st.st_mode)))
    except (OSError, SafetyError) as exc:
        root.status = "denied"
        root.issues.append(clean(exc))
    return root


def capacities(path="/"):
    """Filesystem capacity is separate from directory sums; no APFS volume sum."""
    selected = canonical(path)
    roots = [(str(selected), "Selected filesystem")]
    if selected == Path("/") and Path(DATA_ALIAS).exists():
        roots = [("/", "System filesystem"), (DATA_ALIAS, "APFS Data filesystem")]
    result = []
    for volume, label in roots:
        try:
            info = os.statvfs(volume)
            result.append({"path": volume, "label": label, "total": info.f_blocks * info.f_frsize,
                           "used": (info.f_blocks - info.f_bfree) * info.f_frsize,
                           "available": info.f_bavail * info.f_frsize, "status": "measured",
                           "note": "APFS volumes may share a container; do not sum capacities or equate them with directory estimates"})
        except OSError as exc:
            result.append({"path": volume, "label": label, "status": "unknown", "reason": clean(exc)})
    return result
