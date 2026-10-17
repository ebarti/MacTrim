"""Bounded metadata inventory. This module never hashes or grants deletion rights."""
from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import threading
import time

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
    metadata_visits: int = 0
    newest_ns: int = 0
    identity: tuple = ()
    issues: list = field(default_factory=list)
    children: list = field(default_factory=list)
    alias_of: str = ""
    kind: str = "unknown"
    protected: bool = False
    budget_limited: bool = False
    recent: dict = field(default_factory=lambda: {"modified_7d": 0, "modified_30d": 0, "created_7d": 0})

    def summary(self):
        return {"logical": self.logical, "allocated": self.allocated, "entries": self.entries,
                "newest_ns": self.newest_ns, "identity": list(self.identity), "status": self.status,
                "metadata_visits": self.metadata_visits,
                "issues": self.issues, "alias_of": self.alias_of, "kind": self.kind,
                "digest": None, "measurement_only": True, "recent": self.recent}

    def export(self):
        return dict(self.summary(), path=self.path, name=self.name, protected=self.protected,
                    children=[child.export() for child in self.children])


class Counter:
    def __init__(self, limit, depth, parent=None):
        self.limit, self.depth, self.used, self.parent = limit, depth, 0, parent

    @property
    def remaining(self):
        own = max(0, self.limit - self.used)
        return min(own, self.parent.remaining) if self.parent else own

    def take(self, level):
        if level > self.depth:
            raise SafetyError("Metadata depth exhausted")
        if self.remaining == 0:
            raise SafetyError("Metadata budget exhausted")
        if self.parent:
            self.parent.take(level)
        self.used += 1


def fair_frontier(path, level):
    """Partition useful storage front doors without multiplying their budget."""
    if level <= 2:
        return True
    parts = Path(path).parts
    home = Path.home()
    try:
        if len(Path(path).relative_to(home).parts) <= 2:
            return True
    except ValueError:
        pass
    # Other user homes must receive the same treatment when exploring /.
    if len(parts) >= 3 and parts[1] == 'Users' and len(parts) <= 5:
        return True
    for collection in ('Github', 'Projects', 'Developer', 'src', 'tmp', 'folders', 'worktrees'):
        if collection in parts and len(parts) - parts.index(collection) <= 3:
            return True
    return False


def measure(path, max_entries=20000, max_depth=16, cancel=None, progress=None,
            seen=None, storage=False, independent_children=False):
    """No-follow, inode-aware lower bounds; inspect system ownership read-only.

    Storage / uses independent child budgets so /System cannot starve /Users.
    At useful home/project/temp frontiers, files are measured first and directory
    siblings share the remaining quota; an early large directory cannot consume
    later siblings' share. All child quotas debit their parent's fixed bound.
    Data's firmlink aliases and virtual trees are explicitly skipped even when
    their st_dev matches /. A drill-down starts its own independent inventory.
    """
    path = canonical(path)
    cancel = cancel or threading.Event()
    seen = seen if seen is not None else {}
    budget = Counter(max_entries, max_depth)
    now = time.time()
    root = Node(str(path), path.name or "/", protected=bool(protected(path)))
    try:
        root_st = os.lstat(path)
        root_device = root_st.st_dev
        ancestor_identity(path.parent if path != Path("/") else path)
    except (OSError, SafetyError) as exc:
        root.status = "denied"
        root.issues = [clean(exc)]
        return root

    def walk(parent_fd, name, node, level, counter, expected=None, device=None):
        if cancel.is_set():
            node.status = "cancelled"
            node.issues.append("Measurement cancelled; totals are lower bounds")
            return
        visits_start = counter.used
        try:
            counter.take(level)
            st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False) if name else os.fstat(parent_fd)
            node.kind = 'directory' if stat.S_ISDIR(st.st_mode) else 'file' if stat.S_ISREG(st.st_mode) else 'symlink' if stat.S_ISLNK(st.st_mode) else 'special'
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
            device = root_device if device is None else device
            if st.st_dev != device:
                # User-selected root owns its device. At /, preserve the useful
                # macOS firmlink front doors, but do not recursively visit mounts.
                allow_front = storage and path == Path("/") and level == 1 and absolute in {"/Users", "/Applications"}
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
                for days in (7, 30):
                    if st.st_mtime >= now - days * 86400:
                        node.recent["modified_%sd" % days] = node.allocated
                if getattr(st, "st_birthtime", 0) >= now - 7 * 86400:
                    node.recent["created_7d"] = node.allocated
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
                if level >= max_depth:
                    node.status = "partial"
                    node.issues.append("Depth limit; directory contents remain unknown")
                    return
                # listdir does not read file content. Its entry count is separately
                # bounded; directory populations beyond the budget are partial.
                names = []
                truncated = unvisited = False
                maximum_names = max(1, min(64, max_entries) if independent_children and level == 0 else counter.remaining)
                with os.scandir(fd) as stream:
                    for entry in stream:
                        if cancel.is_set():
                            node.status = "cancelled"
                            node.issues.append("Enumeration cancelled; remaining names unknown")
                            break
                        if len(names) >= maximum_names:
                            truncated = True
                            break
                        # Type is an ordering hint only; walk revalidates lstat
                        # and opened directory identity before trusting it.
                        try:
                            directory_hint = entry.is_dir(follow_symlinks=False)
                        except OSError:
                            directory_hint = True
                        names.append((entry.name, directory_hint))
                fair = storage and fair_frontier(absolute, level)
                names.sort(key=lambda row: (row[1] if fair else False, row[0]))
                directories_left = sum(hint for _, hint in names)
                if truncated:
                    node.budget_limited = True
                    node.status = "partial"
                    node.issues.append("Directory enumeration budget exhausted; additional entries are unknown")
                for child_name, directory_hint in names:
                    if not (independent_children and level == 0) and counter.remaining == 0:
                        unvisited = True
                        node.budget_limited = True
                        node.status = "partial"
                        node.issues.append("Remaining entries unmeasured after subtree budget exhaustion")
                        break
                    child_path = str(Path(absolute) / child_name)
                    child = Node(child_path, child_name, protected=bool(protected(child_path)))
                    node.children.append(child)
                    if independent_children and level == 0:
                        child_counter = Counter(max_entries, max_depth)
                    elif fair and directory_hint:
                        quota = max(1, counter.remaining // max(1, directories_left))
                        child_counter = Counter(quota, max_depth, parent=counter)
                    else:
                        child_counter = counter
                    if directory_hint:
                        directories_left -= 1
                    if child_counter.remaining == 0:
                        child.status = "partial"
                        child.issues.append("Metadata budget exhausted before this entry")
                    else:
                        walk(fd, child_name, child, level + 1, child_counter, device=st.st_dev)
                    node.budget_limited |= child.budget_limited
                    node.logical += child.logical
                    node.allocated += child.allocated
                    node.entries += child.entries
                    for bucket in node.recent:
                        node.recent[bucket] += child.recent[bucket]
                    node.newest_ns = max(node.newest_ns, child.newest_ns)
                    if child.status != "measured":
                        node.status = "partial" if child.status != "cancelled" else "cancelled"
                    if progress:
                        progress(root, child)
                    if cancel.is_set():
                        node.status = "cancelled"
                        node.issues.append("Remaining entries unmeasured")
                        break
                # Once every sibling received a share, spend unused quota on
                # the largest partial regions. This continues the same bounded
                # collector; History never initiates another walk. Each repeated
                # metadata visit also debits the shared budget. Exact inode
                # accounting is removed only for the replaced region.
                if fair and not (independent_children and level == 0) and not cancel.is_set():
                    partials = sorted((child for child in node.children if child.kind == 'directory' and child.budget_limited), key=lambda child: (-child.allocated, child.name))
                    for old in partials:
                        if counter.remaining < max(32, old.entries * 2) or cancel.is_set():
                            break
                        def forget(value):
                            if seen.get(value.identity) == value.path:
                                del seen[value.identity]
                            for descendant in value.children:
                                forget(descendant)
                        forget(old)
                        fresh = Node(old.path, old.name, protected=old.protected)
                        walk(fd, old.name, fresh, level + 1, counter,
                             expected=old.identity + (stat.S_IFDIR,), device=st.st_dev)
                        node.children[node.children.index(old)] = fresh
                    # Refinement replaces, never adds, a region's earlier total.
                    node.logical = sum(child.logical for child in node.children)
                    node.allocated = sum(child.allocated for child in node.children)
                    node.entries = 1 + sum(child.entries for child in node.children)
                    node.newest_ns = max([st.st_mtime_ns] + [child.newest_ns for child in node.children])
                    node.recent = {key: sum(child.recent[key] for child in node.children) for key in node.recent}
                    node.budget_limited = truncated or unvisited or any(child.budget_limited for child in node.children)
                    if not (truncated or unvisited):
                        node.status = 'cancelled' if cancel.is_set() else 'measured' if all(child.status == 'measured' for child in node.children) else 'partial'
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
            node.budget_limited = "budget" in str(exc).lower()
            node.status = "partial" if any(word in str(exc).lower() for word in ("budget", "depth")) else "denied"
            node.issues.append(clean(exc))
        finally:
            node.metadata_visits = counter.used - visits_start
            if independent_children and level == 0:
                node.metadata_visits += sum(child.metadata_visits for child in node.children)

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
