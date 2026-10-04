"""Complete baseline + advisory native event replay + directory subtree reuse."""
import os
from pathlib import Path
import time
from . import events
from .history import policy
from .safety import SafetyError, canonical, clean, within
from .storage import complete, _signature
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
    try:
        identity, now_id = volume_identity(path), events.current_id()
        compatible = bool(previous and cached and previous['policy'] == current_policy and previous['volume'] == identity and
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
                warnings.extend(lost); compatible = False
                reason = 'FSEvents continuity lost; full reconciliation'
            if compatible and not full:
                mode = 'incremental'
                reason = 'Persistent FSEvents replay; changed directories measured, unchanged subtrees reused'
            accounting_scopes = previous.get('reconcile_scopes', [str(path)] if previous.get('requires_reconcile') else []) if previous else []
            if any(within(region, scope) or within(scope, region) for region in dirty for scope in accounting_scopes):
                compatible = False; mode = 'full'
                reason = 'Hardlink/alias accounting spans directories; full reconciliation'
            def walk(regions, allow_reuse):
                nonlocal visits
                def reuse(node, st):
                    old = nodes.get(node.path)
                    if not old or old.status != 'measured' or old.signature != _signature(st):
                        return None
                    if any(within(node.path, value) or within(value, node.path) for value in regions):
                        return None
                    return old
                result = complete(path, cancel=cancel, progress=progress, exclusions=excluded,
                                  reuse=reuse if allow_reuse else None)
                visits += result.counters['visited']
                return result
            # Capture the boundary BEFORE the walk. Later events get remeasured
            # below or replayed next time; checkpoint persistence is transactional.
            checkpoint = events.current_id()
            node = walk(dirty, compatible and not full)
            after, lost, _ = watcher.drain()
            if node.counters['reused'] and getattr(node, 'requires_reconcile', False):
                checkpoint = events.current_id()
                node = walk(set(), False)
                after, lost, _ = watcher.drain()
                mode, reason = 'full', 'New multiply-linked file requires global accounting reconciliation'
            if after and not lost and node.status != 'cancelled' and not getattr(node, 'requires_reconcile', False):
                # One bounded reconciliation round avoids chasing hot writers.
                nodes = {row.path: row for row in iter_nodes(node)}
                compatible = not any(within(region, scope) or within(scope, region)
                                     for region in after for scope in accounting_scopes)
                checkpoint = events.current_id()
                node = walk(after, compatible)
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
                for row in iter_nodes(node):
                    if row.status == 'measured' and (lost or any(within(row.path, value) or within(value, row.path) for value in after)):
                        row.status = 'partial'
                        row.issues.append('Unsettled filesystem events; growth for this scope remains unknown')
                # Retain the pre-walk checkpoint so unsettled changes replay next time.
                # Continuity loss prevents any cache commit.
                if lost:
                    cache = None
            node.counters['visited'] = node.metadata_visits = visits
            node.refresh = {'mode': mode, 'reason': reason, 'dirty_regions': len(dirty),
                            'visited': node.counters['visited'], 'reused_entries': node.counters['reused'],
                            'last_verified': node.completed_at, 'warnings': warnings}
            if cache and node.status != 'cancelled':
                body = {'schema': SCHEMA, 'scope': str(path), 'policy': current_policy, 'volume': identity,
                        'checkpoint': checkpoint, 'previous_checkpoint': previous['checkpoint'] if previous else None,
                        'created_at': node.completed_at, 'full_at': previous['full_at'] if mode == 'incremental' else node.completed_at,
                        'complete_index': True, 'reconcile_scopes': sorted(set(getattr(node, 'reconcile_scopes', [])) | (set(accounting_scopes) if mode == 'incremental' else set())), 'requires_reconcile': bool(getattr(node, 'requires_reconcile', False) or (mode == 'incremental' and previous.get('requires_reconcile'))),
                        'directories': flatten(node)}
                try:
                    node.refresh['cache'] = cache.write(body)
                except (OSError, SafetyError) as exc:
                    warnings.append(clean(exc))
    except (ImportError, OSError, SafetyError) as exc:
        warnings.append(clean(exc))
        node = complete(path, cancel=cancel, progress=progress, exclusions=excluded)
        node.refresh = {'mode': 'full', 'reason': 'Native event backend unavailable/unsafe; full metadata fallback',
                        'visited': node.counters['visited'], 'reused_entries': 0, 'last_verified': node.completed_at, 'warnings': warnings}
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
