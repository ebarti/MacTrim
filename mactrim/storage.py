"""Complete streaming Storage metadata, separate from bounded cleanup evidence.

Only directories and multiply-linked file exceptions are retained. Presentation
is paged independently of measurement. No contents are opened or hashed.
"""
from collections import deque
from copy import copy
from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import threading
import time

from .measurement import Node, VIRTUAL, DATA_ALIAS, capacities
from .safety import SafetyError, canonical, clean, directory_fd, protected, within
from .regions import check_cancel

PAGE_SIZE = 500
FRONT_DOORS = {'/Users', '/Applications', '/Library', '/private', '/usr', '/System', '/bin', '/sbin', '/opt'}
LAZY_DETAILS = frozenset({'node_modules', '.venv', 'venv', '.tox', '.nox', '__pypackages__'})


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
    signature: tuple = ()
    details_deferred: bool = False

    def summary(self):
        return dict(super().summary(), collector=self.collector, started_at=self.started_at,
                    completed_at=self.completed_at, refresh=getattr(self, 'refresh', {}), counters=self.counters, exclusions=self.exclusions,
                    direct_files=self.direct_files, page_size=PAGE_SIZE, details_deferred=self.details_deferred)

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


def find_directory(root, path):
    """Follow path components; never search every node to navigate."""
    target = canonical(path)
    if not within(target, root.path):
        return None
    node = root
    for name in target.relative_to(root.path).parts:
        node = next((child for child in node.children if child.name == name), None)
        if node is None:
            return None
    return node


def progress_snapshot(root, phase, current_path, totals=None, branches=None, reused=()):
    """Stable, shallow UI observation. Unfinished directory totals are lower bounds."""
    snapshot = copy(root)
    snapshot.status = 'scanning'
    snapshot.counters = dict(root.counters)
    snapshot.issues = list(root.issues)
    snapshot.exclusions = dict(root.exclusions)
    snapshot.progress = {'phase': phase, 'path': current_path}
    snapshot.children = []
    if totals is not None:
        snapshot.logical, snapshot.allocated, snapshot.entries = totals
    else:
        snapshot.logical = max(root.logical, root.own_logical + sum(child.logical for child in root.children))
        snapshot.allocated = max(root.allocated, root.own_allocated + sum(child.allocated for child in root.children))
    # Presentation must not make every progress tick copy an unbounded tree.
    # Totals above still include every observed directory and file.
    for child in root.children[:PAGE_SIZE]:
        row = copy(child)
        row.issues = list(child.issues)
        row.children = []
        row.logical = max(row.logical, child.own_logical)
        row.allocated = max(row.allocated, child.own_allocated)
        if branches is not None:
            row.logical, row.allocated, row.entries = branches.get(child.path, (0, 0, 0))
        if row.status == 'measured' and row.path not in reused:
            row.status = 'scanning'
        snapshot.children.append(row)
    return snapshot


def complete(path, cancel=None, progress=None, exclusions=(), reuse=None, view=None, lazy=True):
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
    reused = set()
    reconcile_scopes = set()
    queue = deque([(root, None, None, None, None)])
    now, last_progress = time.time(), 0.0
    own_exclusions = tuple(canonical(value) for value in exclusions)
    totals, branches = [0, 0, 0], {}
    current, branch, accounted = None, None, (0, 0, 0)
    aggregate = None
    selected_view = [None, None]
    def account():
        nonlocal accounted
        if current is None:
            return
        values = (current.logical, current.allocated, current.entries) if current.path in reused else (current.own_logical, current.own_allocated, current.entries)
        delta = [value - old for value, old in zip(values, accounted)]
        for index in range(3):
            totals[index] += delta[index]
        if aggregate is not None and aggregate is not current:
            aggregate.own_logical += delta[0]
            aggregate.own_allocated += delta[1]
            aggregate.entries += delta[2]
        if branch is not None:
            values_by_branch = branches.setdefault(branch.path, [0, 0, 0])
            for index in range(3):
                values_by_branch[index] += delta[index]
        accounted = values
    def finish_current():
        if current is None or aggregate is None or aggregate is current:
            return
        aggregate.newest_ns = max(aggregate.newest_ns, current.newest_ns)
        for key in aggregate.recent:
            aggregate.recent[key] += current.recent[key]
        if current.status not in {'measured', 'skipped'}:
            aggregate.status = 'partial'
            if len(aggregate.issues) < 16:
                aggregate.issues.append('%s: %s' % (clean(current.path), '; '.join(current.issues)))
    def notify(node, force=False, phase='Enumerating metadata'):
        nonlocal last_progress
        if progress and (force or time.monotonic() - last_progress >= .15):
            account()
            last_progress = time.monotonic()
            snapshot = progress_snapshot(root, phase, node.path, totals, branches, reused)
            target = str(canonical(view())) if view else root.path
            if target != selected_view[0] or selected_view[1] is None:
                selected_view[:] = [target, find_directory(root, target)]
            if target != root.path and selected_view[1] is not None:
                snapshot.view = progress_snapshot(selected_view[1], phase, node.path)
            progress(snapshot, copy(node))
    def excluded(node, reason):
        node.status = 'skipped'
        node.issues.append(reason)
        root.counters['excluded'] += 1
        root.exclusions[reason] = root.exclusions.get(reason, 0) + 1
    while queue and not cancel.is_set():
        account()
        finish_current()
        node, expected, device, branch, aggregate = queue.popleft()
        if aggregate is None and lazy and node is not root and node.name in LAZY_DETAILS:
            aggregate = node
            node.details_deferred = True
        current, accounted = node, (0, 0, 0)
        if aggregate is None or aggregate is node:
            records.append(node)
        notify(node)
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
                    reconcile_scopes.update((aggregate.path if aggregate else node.path, node.alias_of))
                    excluded(node, 'Already accounted directory/firmlink inode')
                    continue
                directory_inodes[node.identity] = aggregate.path if aggregate else node.path
                if not st.st_mode & 0o444 or not st.st_mode & 0o111:
                    raise PermissionError('Directory metadata inaccessible')
                fd = os.open(Path(node.path).name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent) if node.path != '/' else os.dup(parent)
            try:
                initial = os.fstat(fd)
                if _signature(initial) != _signature(st):
                    raise SafetyError('Directory changed before enumeration')
                node.signature = _signature(st)
                cached = reuse(node, st) if reuse and (aggregate is None or aggregate is node) else None
                if cached is not None:
                    for key in ('logical', 'allocated', 'entries', 'newest_ns', 'direct_files', 'own_logical', 'own_allocated', 'signature', 'recent', 'status', 'issues', 'children', 'kind'):
                        setattr(node, key, getattr(cached, key))
                    if node.details_deferred:
                        node.own_logical, node.own_allocated = node.logical, node.allocated
                        node.children = []
                    reused.add(node.path)
                    root.counters['reused'] += node.entries
                    continue
                node.own_logical = st.st_size
                node.own_allocated = st.st_blocks * 512
                node.entries = 1
                node.newest_ns = st.st_mtime_ns
                node.status = 'measured'
                with os.scandir(fd) as stream:
                    for entry in stream:
                        if cancel.is_set():
                            break
                        try:
                            child_st = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                            root.counters['visited'] += 1
                            root.metadata_visits += 1
                            kind = 'directory' if stat.S_ISDIR(child_st.st_mode) else 'file' if stat.S_ISREG(child_st.st_mode) else 'symlink' if stat.S_ISLNK(child_st.st_mode) else 'special'
                            if kind == 'directory':
                                absolute = str(Path(node.path) / entry.name)
                                child = StorageNode(absolute, entry.name, identity=(child_st.st_dev, child_st.st_ino),
                                                    kind=kind, protected=bool(protected(absolute)), status='scanning')
                                if aggregate is None:
                                    node.children.append(child)
                                item = (child, child.identity, st.st_dev, child if node is root else branch, aggregate)
                                if aggregate is None:
                                    queue.append(item)
                                else:
                                    queue.appendleft(item)
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
                                reconcile_scopes.add(aggregate.path if aggregate else node.path)
                                if identity in links:
                                    root.counters['excluded'] += 1
                                    root.exclusions['Already accounted hardlink'] = root.exclusions.get('Already accounted hardlink', 0) + 1
                                    continue
                                links[identity] = str(Path(node.path) / entry.name)
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
                            if len(node.issues) < 16:
                                node.issues.append('Unobserved entry %s: %s' % (clean(entry.name), clean(exc)))
                            root.counters['denied'] += 1
                        finally:
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
    account()
    finish_current()
    notify(current or root, force=True, phase='Aggregating directory totals')
    # Reverse breadth-first order propagates directory totals without recursion.
    for node in reversed(records):
        if node.path in reused:
            continue
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
    root.reconcile_scopes = sorted(reconcile_scopes)
    root.requires_reconcile = bool(reconcile_scopes)
    root.completed_at = time.time()
    if root.counters['denied']:
        root.issues.append('%s inaccessible/replaced entries; estimates are lower bounds' % root.counters['denied'])
    if root.counters['excluded']:
        root.issues.append('Intentional exclusions: ' + '; '.join('%s (%s)' % (reason, count) for reason, count in root.exclusions.items()))
    if lazy:
        # Previously saved detailed trees can donate their sizes without a
        # new baseline solely to change presentation granularity.
        pending = list(root.children)
        while pending:
            if cancel.is_set():
                root.status = 'cancelled'
                break
            node = pending.pop()
            if node.name in LAZY_DETAILS:
                node.details_deferred = True
                node.own_logical, node.own_allocated = node.logical, node.allocated
                node.children = []
            else:
                pending.extend(node.children)
    return root


def coverage_report(root, limit=8, cancel=None):
    """Explain actual incomplete scopes; presentation limits never limit scans."""
    counts = dict(permissions=0, changes=0, tracking=0, other=0)
    examples = {key: [] for key in counts}
    pending = [root]
    while pending:
        check_cancel(cancel)
        node = pending.pop()
        pending.extend(reversed(node.children))
        if node.status in {'measured', 'skipped'}:
            continue
        local = [issue for issue in node.issues if not any(value in issue for value in
                 ('descendant scopes incomplete', 'inaccessible/replaced entries', 'Intentional exclusions:',
                  'Filesystem still changing or event continuity uncertain; pending regions:'))]
        grouped = {}
        for issue in local:
            lower = issue.lower()
            category = ('permissions' if any(value in lower for value in
                         ('operation not permitted', 'permission denied', 'metadata inaccessible')) else
                        'tracking' if 'unsettled filesystem events' in lower else
                        'changes' if any(value in lower for value in
                         ('changed', 'replaced', 'no such file or directory')) else 'other')
            grouped.setdefault(category, issue)
        for category, issue in grouped.items():
            counts[category] += 1
            if len(examples[category]) < limit:
                examples[category].append({'path': node.path, 'reason': issue})
    return {'scope': root.path, 'complete': root.status == 'measured', 'counts': counts,
            'examples': examples, 'examples_per_category': limit,
            'note': 'Complete means all accessible metadata measured under the no-follow local-disk policy. '
                    'Permission failures need access granted by macOS; active writers can leave interval uncertainty.'}


def page(node, offset=0, limit=PAGE_SIZE):
    """Bounded current-directory display; fresh file metadata has its own interval.

    Directory aggregates come from the completed inventory. Regular file rows
    are inspected only for the requested page and never determine completion.
    """
    if getattr(node, 'details_deferred', False):
        return [], False
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
                try:
                    st = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                except OSError as exc:
                    rows.append(Node(str(Path(node.path) / entry.name), entry.name, status='denied', issues=[clean(exc)]))
                    seen += 1
                    continue
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
