"""Complete streaming Storage metadata, separate from bounded cleanup evidence.

Only directories and multiply-linked file exceptions are retained. Presentation
is paged independently of measurement. No contents are opened or hashed.
"""
from collections import deque
from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import threading
import time

from .measurement import Node, VIRTUAL, DATA_ALIAS, capacities
from .safety import SafetyError, canonical, clean, directory_fd, protected, within

PAGE_SIZE = 500
FRONT_DOORS = {'/Users', '/Applications', '/Library', '/private', '/usr', '/System', '/bin', '/sbin', '/opt'}


@dataclass
class StorageNode(Node):
    collector: str = 'storage.complete.v1'
    started_at: float = 0.0
    completed_at: float = 0.0
    counters: dict = field(default_factory=lambda: {'visited': 0, 'denied': 0, 'excluded': 0, 'changed': 0, 'reused': 0})
    exclusions: dict = field(default_factory=dict)
    direct_files: int = 0
    page: int = 0
    own_logical: int = 0
    own_allocated: int = 0

    def summary(self):
        return dict(super().summary(), collector=self.collector, started_at=self.started_at,
                    completed_at=self.completed_at, counters=self.counters, exclusions=self.exclusions,
                    direct_files=self.direct_files, page_size=PAGE_SIZE)

    def export(self):
        # No recursive per-file JSON tree. Current-directory pages are separate
        # from the complete totals; omission never stops filesystem traversal.
        return dict(self.summary(), path=self.path, name=self.name, protected=self.protected,
                    children=[dict(child.summary(), path=child.path, name=child.name, protected=child.protected)
                              for child in self.children[:PAGE_SIZE]],
                    presentation={'limit': PAGE_SIZE, 'directory_rows': len(self.children),
                                  'file_rows_available': self.direct_files,
                                  'note': 'Presentation is bounded; measurement is complete under the declared policy'})


def _signature(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_size, st.st_mtime_ns, st.st_ctime_ns


def complete(path, cancel=None, progress=None, exclusions=(), reuse=None):
    """Iterative no-follow full walk; quotas/depth never determine completion.

    Each directory is opened from verified ancestors with a captured inode;
    queued replacement/denial/change remains explicit. Regular-file identities
    are retained only for nlink>1. Totals include directory metadata allocation
    and apparent bytes; symlinks/cloud/virtual/external mounts are exclusions.
    """
    path = canonical(path)
    cancel = cancel or threading.Event()
    root = StorageNode(str(path), path.name or '/', kind='directory', protected=bool(protected(path)),
                       started_at=time.time(), status='scanning')
    records, directory_inodes, links = [], {}, {}
    queue = deque([(root, None, None)])
    now, last_progress = time.time(), 0.0
    own_exclusions = tuple(canonical(value) for value in exclusions)
    def notify(node):
        nonlocal last_progress
        if progress and time.monotonic() - last_progress >= .15:
            last_progress = time.monotonic()
            progress(root, node)
    def excluded(node, reason):
        node.status = 'skipped'
        node.issues.append(reason)
        root.counters['excluded'] += 1
        root.exclusions[reason] = root.exclusions.get(reason, 0) + 1
    while queue and not cancel.is_set():
        node, expected, device = queue.popleft()
        records.append(node)
        try:
            with directory_fd(Path(node.path).parent if node.path != '/' else '/') as parent:
                st = os.stat(Path(node.path).name, dir_fd=parent, follow_symlinks=False) if node.path != '/' else os.fstat(parent)
                root.counters['visited'] += 1
                root.metadata_visits += 1
                node.identity = (st.st_dev, st.st_ino)
                if expected is not None and node.identity != expected:
                    raise SafetyError('Queued directory replaced during inventory')
                node.kind = 'directory' if stat.S_ISDIR(st.st_mode) else 'symlink' if stat.S_ISLNK(st.st_mode) else 'special'
                if node.path in VIRTUAL or (path == Path('/') and node.path == DATA_ALIAS):
                    excluded(node, 'Virtual filesystem' if node.path in VIRTUAL else 'Redundant APFS Data namespace alias')
                    continue
                if any(within(node.path, value) for value in own_exclusions):
                    excluded(node, 'Verified scanner state accounted separately')
                    continue
                if stat.S_ISLNK(st.st_mode):
                    excluded(node, 'Symlink target not followed')
                    continue
                if getattr(st, 'st_flags', 0) & 0x40000000:
                    excluded(node, 'Cloud placeholder not hydrated')
                    continue
                if not stat.S_ISDIR(st.st_mode):
                    raise SafetyError('Selected Storage scope is not a directory')
                if device is not None and st.st_dev != device and not (path == Path('/') and node.path in FRONT_DOORS):
                    excluded(node, 'External mount boundary')
                    continue
                if node.identity in directory_inodes:
                    node.alias_of = directory_inodes[node.identity]
                    excluded(node, 'Already accounted directory/firmlink inode')
                    continue
                directory_inodes[node.identity] = node.path
                if not st.st_mode & 0o444 or not st.st_mode & 0o111:
                    raise PermissionError('Directory metadata inaccessible')
                fd = os.open(Path(node.path).name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent) if node.path != '/' else os.dup(parent)
            try:
                initial = os.fstat(fd)
                if _signature(initial) != _signature(st):
                    raise SafetyError('Directory changed before enumeration')
                node.own_logical = st.st_size
                node.own_allocated = st.st_blocks * 512
                node.entries = 1
                node.newest_ns = st.st_mtime_ns
                node.status = 'measured'
                with os.scandir(fd) as stream:
                    for entry in stream:
                        if cancel.is_set():
                            break
                        absolute = str(Path(node.path) / entry.name)
                        try:
                            child_st = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                            root.counters['visited'] += 1
                            root.metadata_visits += 1
                            kind = 'directory' if stat.S_ISDIR(child_st.st_mode) else 'file' if stat.S_ISREG(child_st.st_mode) else 'symlink' if stat.S_ISLNK(child_st.st_mode) else 'special'
                            if kind == 'directory':
                                child = StorageNode(absolute, entry.name, identity=(child_st.st_dev, child_st.st_ino),
                                                    kind=kind, protected=bool(protected(absolute)), status='scanning')
                                node.children.append(child)
                                queue.append((child, child.identity, st.st_dev))
                                continue
                            node.entries += 1
                            node.direct_files += 1
                            if kind != 'file' or getattr(child_st, 'st_flags', 0) & 0x40000000:
                                reason = 'Cloud placeholder not hydrated' if getattr(child_st, 'st_flags', 0) & 0x40000000 else 'Symlink target not followed' if kind == 'symlink' else 'Special object not read'
                                root.counters['excluded'] += 1
                                root.exclusions[reason] = root.exclusions.get(reason, 0) + 1
                                continue
                            identity = (child_st.st_dev, child_st.st_ino)
                            if child_st.st_nlink > 1:
                                if identity in links:
                                    root.counters['excluded'] += 1
                                    root.exclusions['Already accounted hardlink'] = root.exclusions.get('Already accounted hardlink', 0) + 1
                                    continue
                                links[identity] = absolute
                            node.own_logical += child_st.st_size
                            allocated = child_st.st_blocks * 512
                            node.own_allocated += allocated
                            node.newest_ns = max(node.newest_ns, child_st.st_mtime_ns)
                            for days in (7, 30):
                                if child_st.st_mtime >= now - days * 86400:
                                    node.recent['modified_%sd' % days] += allocated
                            if getattr(child_st, 'st_birthtime', 0) >= now - 7 * 86400:
                                node.recent['created_7d'] += allocated
                        except OSError as exc:
                            node.status = 'partial'
                            node.issues.append('Unobserved entry %s: %s' % (clean(entry.name), clean(exc)))
                            root.counters['denied'] += 1
                        notify(node)
                final = os.fstat(fd)
                if _signature(final) != _signature(initial):
                    node.status = 'partial'
                    node.issues.append('Directory changed during enumeration; interval observation incomplete')
                    root.counters['changed'] += 1
            finally:
                os.close(fd)
        except (OSError, SafetyError) as exc:
            node.status = 'denied' if isinstance(exc, PermissionError) else 'partial'
            node.issues.append(clean(exc))
            root.counters['denied'] += 1
        notify(node)
    # Reverse breadth-first order propagates directory totals without recursion.
    for node in reversed(records):
        node.logical = node.own_logical + sum(child.logical for child in node.children)
        node.allocated = node.own_allocated + sum(child.allocated for child in node.children)
        node.entries += sum(child.entries for child in node.children)
        for key in node.recent:
            node.recent[key] += sum(child.recent[key] for child in node.children)
        unknown = [child for child in node.children if child.status not in {'measured', 'skipped'}]
        if unknown and node.status == 'measured':
            node.status = 'partial'
            node.issues.append('%s descendant scopes incomplete; inspect coverage reasons' % len(unknown))
    if cancel.is_set():
        root.status = 'cancelled'
        root.issues.append('Cancelled; unvisited scopes remain unknown')
    root.completed_at = time.time()
    if root.counters['denied']:
        root.issues.append('%s inaccessible/replaced entries; estimates are lower bounds' % root.counters['denied'])
    if root.counters['excluded']:
        root.issues.append('Intentional exclusions: ' + '; '.join('%s (%s)' % (reason, count) for reason, count in root.exclusions.items()))
    return root


def page(node, offset=0, limit=PAGE_SIZE):
    """Bounded current-directory display; fresh file metadata has its own interval.

    Directory aggregates come from the completed inventory. Regular file rows
    are inspected only for the requested page and never determine completion.
    """
    directories = {child.name: child for child in node.children}
    rows, seen, more = [], 0, False
    with directory_fd(node.path) as fd, os.scandir(fd) as stream:
        for entry in stream:
            if seen < offset:
                seen += 1
                continue
            if len(rows) >= limit:
                more = True
                break
            if entry.name in directories:
                rows.append(directories[entry.name])
            else:
                st = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                rows.append(Node(str(Path(node.path) / entry.name), entry.name, logical=st.st_size,
                                 allocated=st.st_blocks * 512, status='measured',
                                 kind='file' if stat.S_ISREG(st.st_mode) else 'symlink' if stat.S_ISLNK(st.st_mode) else 'special',
                                 issues=['Current page metadata; file rows are not additive accounting totals']))
            seen += 1
    return rows, more


def accounting(node, capacity_rows):
    measured = [row for row in capacity_rows if row.get('status') == 'measured']
    denominator = next((row['used'] for row in measured if row['path'] == DATA_ALIAS), measured[0]['used'] if measured else None)
    return {'namespace_allocated': node.allocated, 'filesystem_used_denominator': denominator,
            'difference': None if denominator is None else denominator - node.allocated,
            'status': node.status, 'reason': 'Signed accounting difference, not reclaimed space. APFS clones, snapshots, system metadata, exclusions and inaccessible scopes differ from namespace estimates.'}
