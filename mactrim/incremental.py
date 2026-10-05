"""Complete baseline + advisory native event replay + directory subtree reuse."""
import os
from pathlib import Path
import time
from . import events
from .history import policy
from .safety import SafetyError, canonical, clean
from .regions import Regions, Cancelled, check_cancel
from .storage import progress_snapshot
from .storage import complete, _signature, coverage_report
from .storage_cache import Cache, SCHEMA, flatten


def volume_identity(path):
    import FSEvents as F
    import CoreFoundation as C
    st = os.lstat(path)
    uuid = F.FSEventsCopyUUIDForDevice(st.st_dev)
    if uuid is None:
        raise SafetyError('Volume event-history identity unavailable')
    return [st.st_dev, st.st_ino, str(C.CFUUIDCreateString(None, uuid))]


def inventory(path, state=None, config=None, cancel=None, progress=None, full=False, backend=events.NativeEvents):
    from .config import defaults
    config = config or defaults()
    settings = config['storage_cache']
    path = canonical(path)
    cache = Cache(state, settings) if state is not None and settings['enabled'] else None
    excluded = (state.path / 'storage-cache', state.path / 'history') if state else ()
    warnings, dirty, previous, nodes, cached = [], set(), None, {}, None
    visits = 0
    node = None
    identity, checkpoint, reuse_allowed = None, 0, True
    repair = {'attempted': False}
    save_blocker = 'No private state configured' if state is None else 'Directory index disabled in configuration'
    def phase(value):
        check_cancel(cancel)
        if progress and node is not None:
            snapshot = progress_snapshot(node, value, node.path)
            snapshot.counters['visited'] = visits
            snapshot.metadata_visits = visits
            progress(snapshot, snapshot)
    reason, mode = 'Complete initial inventory', 'full'
    current_policy = policy(config, path, 'storage.complete.v1')
    # Measurement-owned stores are explicitly excluded and accounted separately.
    current_policy = dict(current_policy, measurement_state=[str(value) for value in excluded])
    if cache:
        try:
            observed = cache.read()
            if observed:
                previous, cached, nodes = observed
                reason = 'Cached directory details omitted; full reconciliation'
        except (OSError, SafetyError) as exc:
            warnings.append(clean(exc)); cache = None
            reason = 'Unsafe/unreadable cache preserved; full reconciliation'
            save_blocker = reason
    try:
        identity, now_id = volume_identity(path), events.current_id()
        compatible = bool(previous and cached and previous['policy'] == current_policy and previous['volume'] == identity and
                          previous.get('reuse_allowed', True) and
                          previous['checkpoint'] <= now_id and time.time() - previous['full_at'] < settings['reconcile_seconds'])
        if full:
            reason = 'Explicit full reconciliation'
        elif previous and not compatible:
            reason = 'Index/policy/volume/event continuity or periodic reconciliation requires a full scan'
        since = previous['checkpoint'] if compatible and not full else now_id
        # Watching precedes every walk, so changes during enumeration can be
        # observed. A checkpoint precedes the observation interval; it is never
        # advanced past unmeasured events.
        with backend(path, since, excluded) as watcher:
            dirty, lost, _ = watcher.drain()
            if lost:
                warnings.extend('Before scan: ' + issue for issue in lost); compatible = False
                reason = 'Full reconciliation after a pre-scan FSEvents gap'
            if compatible and not full:
                mode = 'incremental'
                reason = 'Persistent FSEvents replay; changed directories measured, unchanged subtrees reused'
            accounting_scopes = previous.get('reconcile_scopes', [str(path)] if previous.get('requires_reconcile') else []) if previous else []
            dirty_index = Regions(dirty, cancel)
            if dirty_index.intersects_any(accounting_scopes, cancel):
                compatible = False; mode = 'full'
                reason = 'Hardlink/alias accounting spans directories; full reconciliation'
            def walk(regions, allow_reuse):
                nonlocal visits
                regions = Regions(regions, cancel)
                def walk_progress(snapshot, current):
                    snapshot.counters['visited'] += visits
                    snapshot.metadata_visits += visits
                    if repair['attempted']:
                        prefix = 'Full repair' if repair['full'] else 'Targeted repair'
                        snapshot.progress['phase'] = prefix + ' · ' + snapshot.progress['phase']
                    progress(snapshot, current)
                def reuse(node, st):
                    old = nodes.get(node.path)
                    if not old or old.status != 'measured' or old.signature != _signature(st):
                        return None
                    if regions.intersects(node.path):
                        return None
                    return old
                result = complete(path, cancel=cancel, progress=walk_progress if progress else None, exclusions=excluded,
                                  reuse=reuse if allow_reuse else None)
                visits += result.counters['visited']
                return result
            # Capture the boundary BEFORE the walk. Later events get remeasured
            # below or replayed next time; checkpoint persistence is transactional.
            checkpoint = events.current_id()
            node = walk(dirty, compatible and not full)
            phase('Checking filesystem events')
            after, lost, _ = watcher.drain()
            if node.counters['reused'] and getattr(node, 'requires_reconcile', False):
                checkpoint = events.current_id()
                node = walk(set(), False)
                after, lost, _ = watcher.drain()
                mode, reason = 'full', 'New multiply-linked file requires global accounting reconciliation'
            unstable = set()
            for row in iter_nodes(node):
                check_cancel(cancel)
                if any('changed during enumeration' in issue or 'changed before enumeration' in issue or
                       'Queued directory replaced' in issue for issue in row.issues):
                    unstable.add(row.path)
            if (after or lost or unstable) and node.status != 'cancelled':
                # One repair round, chosen by accounting scope, avoids both a
                # blanket hardlink veto and endless restarts on hot writers.
                after.update(unstable)
                link_scopes = set(accounting_scopes) | set(getattr(node, 'reconcile_scopes', []))
                global_repair = bool(lost or Regions(after, cancel).intersects_any(link_scopes, cancel))
                repair = {'attempted': True, 'full': global_repair,
                          'reason': 'Dropped filesystem notifications' if lost else
                                    'Changes overlap hardlink accounting' if global_repair else 'Changed directories'}
                warnings.extend('Before repair: ' + issue for issue in lost)
                phase('Repairing event gap: full metadata sweep' if lost else
                      'Repairing hardlink accounting: full metadata sweep' if global_repair else
                      'Reconciling changed directories')
                nodes = {}
                if not global_repair:
                    for row in iter_nodes(node):
                        check_cancel(cancel)
                        nodes[row.path] = row
                else:
                    # A global repair cannot reuse this observation. Release
                    # its tree before allocating another whole-disk tree.
                    node = None
                checkpoint = events.current_id()
                node = walk(after, not global_repair)
                if global_repair:
                    mode, reason = 'full', 'Full reconciliation: ' + repair['reason']
                after, lost, _ = watcher.drain()
                if node.counters['reused'] and getattr(node, 'requires_reconcile', False):
                    checkpoint = events.current_id()
                    node = walk(set(), False)
                    after, lost, _ = watcher.drain()
                    mode, reason = 'full', 'New hardlink during reconciliation requires global accounting'
            if after or lost:
                warnings.extend(lost)
                node.status = 'partial' if node.status != 'cancelled' else node.status
                node.issues.append('Filesystem still changing or event continuity uncertain; pending regions: ' + ', '.join(sorted(after)[:8]))
                phase('Classifying unsettled directories')
                after_index = Regions(after, cancel)
                updated = time.monotonic()
                for row in iter_nodes(node):
                    check_cancel(cancel)
                    if time.monotonic() - updated >= .15:
                        phase('Classifying unsettled directories')
                        updated = time.monotonic()
                    if row.status == 'measured' and (lost or after_index.intersects(row.path)):
                        row.status = 'partial'
                        row.issues.append('Unsettled filesystem events; growth for this scope remains unknown')
                # Save the observation even when continuity is lost. It remains
                # explicitly ineligible for reuse until a fresh scan repairs it.
                if lost:
                    reuse_allowed = False
            node.counters['visited'] = node.metadata_visits = visits
            node.refresh = {'mode': mode, 'reason': reason, 'dirty_regions': len(dirty),
                            'visited': node.counters['visited'], 'reused_entries': node.counters['reused'],
                            'last_verified': node.completed_at, 'warnings': warnings}
    except Cancelled:
        if node is None:
            node = complete(path, cancel=cancel, exclusions=excluded)
        node.status = 'cancelled'
        node.issues.append('Cancelled during reconciliation; cache checkpoint preserved')
        node.counters['visited'] = node.metadata_visits = visits or node.counters['visited']
        node.refresh = {'mode': mode, 'reason': reason, 'visited': node.counters['visited'],
                        'reused_entries': node.counters['reused'], 'warnings': warnings}
    except (ImportError, OSError, SafetyError) as exc:
        warnings.append(clean(exc))
        reuse_allowed = False
        mode = 'full'
        node = complete(path, cancel=cancel, progress=progress, exclusions=excluded)
        visits = node.counters['visited']
        node.refresh = {'mode': 'full', 'reason': 'Native event backend unavailable/unsafe; full metadata fallback',
                        'visited': node.counters['visited'], 'reused_entries': 0, 'last_verified': node.completed_at, 'warnings': warnings}
    if node.status != 'cancelled':
        try:
            phase('Reporting coverage')
            node.refresh['coverage'] = coverage_report(node, cancel=cancel)
        except Cancelled:
            node.status = 'cancelled'
            node.issues.append('Cancelled while reporting coverage; previous saved index preserved')
    saved = {'stored': False, 'reason': save_blocker, 'reusable': False}
    if node.status == 'cancelled':
        saved['reason'] = 'Scan cancelled; previous saved index preserved'
    elif cache:
        try:
            phase('Saving directory index')
            directories = flatten(node, cancel=cancel)
            check_cancel(cancel)
            if identity is None:
                st = os.lstat(path)
                identity = [st.st_dev, st.st_ino, None]
            # Missing event identity also prevents older binaries from reusing
            # an observation whose stream could not establish continuity.
            saved_identity = identity if reuse_allowed else identity[:2] + [None]
            body = {'schema': SCHEMA, 'scope': str(path), 'policy': current_policy, 'volume': saved_identity,
                    'reuse_allowed': reuse_allowed,
                    'checkpoint': checkpoint, 'previous_checkpoint': previous['checkpoint'] if previous else None,
                    'created_at': node.completed_at, 'full_at': previous['full_at'] if mode == 'incremental' else node.completed_at,
                    'complete_index': True, 'reconcile_scopes': sorted(set(getattr(node, 'reconcile_scopes', [])) | (set(accounting_scopes) if mode == 'incremental' else set())), 'requires_reconcile': bool(getattr(node, 'requires_reconcile', False) or (mode == 'incremental' and previous.get('requires_reconcile'))),
                    'directories': directories}
            saved = cache.write(body, cancel=cancel)
            saved['reusable'] = bool(saved['stored'] and saved.get('complete_index') and reuse_allowed)
            if saved['stored']:
                saved['reason'] = ('Directory index saved; incremental refresh available' if saved['reusable'] else
                                   'Totals saved only; directory details exceeded retention limits' if not saved.get('complete_index') else
                                   'Directory observation saved; event continuity uncertain, full reconciliation required')
        except Cancelled:
            node.status = 'cancelled'
            node.issues.append('Cancelled while saving; previous saved index preserved')
            saved['reason'] = 'Scan cancelled; previous saved index preserved'
        except (OSError, SafetyError) as exc:
            warnings.append(clean(exc))
            saved['reason'] = 'Directory index not saved: ' + clean(exc)
    node.refresh['cache'] = saved
    node.refresh['reconciliation'] = repair
    node.policy = current_policy
    node.refresh['last_full_reconciliation'] = previous['full_at'] if mode == 'incremental' and previous else node.completed_at
    if state:
        footprint = {}
        for folder in excluded:
            try:
                st = os.lstat(folder)
                if folder.is_symlink():
                    raise SafetyError('Unsafe measurement state path')
                value = st.st_blocks * 512
                with os.scandir(folder) as stream:
                    for entry in stream:
                        value += entry.stat(follow_symlinks=False).st_blocks * 512
                footprint[str(folder)] = value
            except FileNotFoundError:
                footprint[str(folder)] = 0
            except (OSError, SafetyError):
                footprint[str(folder)] = None
        node.refresh['measurement_state_allocated'] = footprint
    return node


def iter_nodes(root):
    pending = [root]
    while pending:
        node = pending.pop()
        yield node
        pending.extend(node.children)
