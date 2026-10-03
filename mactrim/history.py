"""Tiny signed, compressed directory observations; history grants no mutation rights."""
import gzip
import heapq
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
import time

from .safety import SafetyError, canonical, clean, directory_fd, json_bytes, rename_exclusive

SCHEMA = 'mactrim.history.v1'
MAX_BYTES = 16 * 1024 * 1024
MAX_ENCODED = 1024 * 1024
MAX_DECODED = 4 * 1024 * 1024
MAX_ENTRIES = 5000
NAME = re.compile(r'(?:\.([a-f0-9]{32})\.(?:pending|[a-f0-9]{16}\.retiring)|([a-f0-9]{32}))\.json\.gz$')


def policy(config, scope):
    return {'collector': 'metadata.v3', 'scope': str(canonical(scope)),
            'max_files': config['storage_max_files'], 'max_depth': config['storage_max_depth'],
            'root_child_budgets': canonical(scope) == Path('/'), 'follow_symlinks': False,
            'dataless': 'skip', 'hardlinks': 'inode-first', 'data_alias': 'skip', 'virtual': 'skip'}


def aggregates(root):
    # Walk only the collector's existing in-memory nodes, never the filesystem.
    heap = []
    sequence = 0
    def visit(node, ancestors):
        nonlocal sequence
        if node.kind != 'directory':
            return
        sequence += 1
        item = (node.allocated, -len(ancestors), sequence, node, ancestors)
        if len(heap) < MAX_ENTRIES - 1:
            heapq.heappush(heap, item)
        elif item[:3] > heap[0][:3]:
            heapq.heapreplace(heap, item)
        for child in node.children:
            visit(child, ancestors + (node,))
    visit(root, ())
    selected = {root.path: root}
    for _, _, _, node, ancestors in sorted(heap, reverse=True):
        additions = {value.path: value for value in ancestors + (node,) if value.path not in selected}
        if len(selected) + len(additions) <= MAX_ENTRIES:
            selected.update(additions)
    result = []
    for node in selected.values():
        result.append({'path': node.path, 'logical': node.logical, 'allocated': node.allocated,
                       'status': node.status, 'identity': list(node.identity),
                       'children_complete': node.status == 'measured' and all(child.path in selected for child in node.children if child.kind == 'directory'),
                       'recent': dict(node.recent)})
    return sorted(result, key=lambda item: item['path'])


def _metadata(st):
    return st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns


class History:
    def __init__(self, state, config):
        self.state, self.config = state, config
        self.settings = config['history']
        self.path = state.path / 'history'
        self.limit = min(MAX_BYTES, self.settings['max_bytes'])

    def prepare(self):
        self.state.verify()
        if not os.path.lexists(self.path):
            with directory_fd(self.state.path) as fd:
                os.mkdir('history', 0o700, dir_fd=fd)
                os.fsync(fd)
        self.state._private(self.path, True)

    def footprint(self):
        self.prepare()
        total = os.lstat(self.path).st_blocks * 512
        with directory_fd(self.path) as fd:
            with os.scandir(fd) as stream:
                for index, entry in enumerate(stream):
                    if index >= 4096:
                        raise SafetyError('History entry inventory bound exceeded')
                    total += entry.stat(follow_symlinks=False).st_blocks * 512
        return total

    def read(self, name, fd):
        matched = NAME.fullmatch(name)
        if not matched:
            raise SafetyError('Unexpected history entry retained: ' + clean(name))
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1 or st.st_size > MAX_ENCODED:
            raise SafetyError('Unsafe or oversized history entry retained: ' + clean(name))
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            if _metadata(os.fstat(file_fd)) != _metadata(st):
                raise SafetyError('History entry replaced before reading')
            data = b''
            while len(data) <= MAX_ENCODED:
                block = os.read(file_fd, min(65536, MAX_ENCODED + 1 - len(data)))
                if not block:
                    break
                data += block
            if _metadata(os.fstat(file_fd)) != _metadata(st):
                raise SafetyError('History entry changed while reading')
        finally:
            os.close(file_fd)
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(data), mode='rb') as stream:
                raw = stream.read(MAX_DECODED + 1)
            if len(raw) > MAX_DECODED:
                raise SafetyError('Decompressed history bound exceeded')
            body = self.state.verify_signed(json.loads(raw))
        except (ValueError, UnicodeError, EOFError, OSError) as exc:
            raise SafetyError('Malformed/altered history entry retained: ' + clean(name)) from exc
        self.validate(body, matched.group(1) or matched.group(2))
        return {'name': name, 'body': body, 'metadata': _metadata(st), 'allocated': st.st_blocks * 512, 'temporary': bool(matched.group(1)), 'encoded_digest': hashlib.sha256(data).hexdigest()}

    def validate(self, body, identifier):
        if not isinstance(body, dict) or set(body) != {'schema', 'id', 'created_at', 'scope', 'policy', 'directories', 'capacity', 'coverage'} or body.get('schema') != SCHEMA or body.get('id') != identifier:
            raise SafetyError('History schema/identity mismatch')
        if type(body['created_at']) not in (int, float) or not math.isfinite(body['created_at']) or body['created_at'] > time.time() + 60 or not isinstance(body['scope'], str) or str(canonical(body['scope'])) != body['scope']:
            raise SafetyError('Invalid history timestamp/scope')
        if not isinstance(body['policy'], dict) or body['policy'].get('scope') != body['scope'] or not isinstance(body['capacity'], list) or len(body['capacity']) > 8 or not isinstance(body['coverage'], dict):
            raise SafetyError('Invalid history policy/capacity/coverage')
        for capacity in body['capacity']:
            if not isinstance(capacity, dict) or not isinstance(capacity.get('path'), str) or not isinstance(capacity.get('label'), str) or capacity.get('status') not in {'measured', 'unknown'}:
                raise SafetyError('Invalid filesystem capacity observation')
            if capacity['status'] == 'measured' and any(type(capacity.get(key)) is not int or not 0 <= capacity[key] <= 2**64 for key in ('total', 'used', 'available')):
                raise SafetyError('Invalid filesystem capacity bytes')
        expected_policy = {'collector', 'scope', 'max_files', 'max_depth', 'root_child_budgets', 'follow_symlinks', 'dataless', 'hardlinks', 'data_alias', 'virtual'}
        if set(body['policy']) != expected_policy or body['policy']['collector'] not in {'metadata.v2', 'metadata.v3'} or type(body['policy']['max_files']) is not int or not 1 <= body['policy']['max_files'] <= 1000000 or type(body['policy']['max_depth']) is not int or not 1 <= body['policy']['max_depth'] <= 64:
            raise SafetyError('Invalid history collector policy')
        values = body['directories']
        if not isinstance(values, list) or not 1 <= len(values) <= MAX_ENTRIES:
            raise SafetyError('History directory count bound exceeded')
        seen = set()
        for row in values:
            if not isinstance(row, dict) or set(row) != {'path', 'logical', 'allocated', 'status', 'identity', 'children_complete', 'recent'}:
                raise SafetyError('Invalid directory aggregate')
            path = row['path']
            if not isinstance(path, str) or str(canonical(path)) != path or path in seen or not (path == body['scope'] or body['scope'] == '/' or path.startswith(body['scope'] + '/')):
                raise SafetyError('Duplicate or escaped history directory')
            seen.add(path)
            if any(type(row[key]) is not int or not 0 <= row[key] <= 2**64 for key in ('logical', 'allocated')) or row['status'] not in {'measured', 'partial', 'denied', 'unknown', 'skipped', 'cancelled'} or type(row['children_complete']) is not bool:
                raise SafetyError('Invalid directory size/status')
            if not isinstance(row['identity'], list) or len(row['identity']) not in (0, 2) or any(type(number) is not int for number in row['identity']) or not isinstance(row['recent'], dict) or set(row['recent']) != {'modified_7d', 'modified_30d', 'created_7d'} or any(type(number) is not int or not 0 <= number <= 2**64 for number in row['recent'].values()):
                raise SafetyError('Invalid directory identity/recent activity')
        if body['scope'] not in seen:
            raise SafetyError('History root aggregate missing')

    def inventory(self, strict=True):
        self.prepare()
        records, issues = [], []
        with directory_fd(self.path) as fd:
            with os.scandir(fd) as stream:
                for index, entry in enumerate(stream):
                    if index >= 4096:
                        raise SafetyError('History entry inventory bound exceeded')
                    try:
                        records.append(self.read(entry.name, fd))
                    except SafetyError as exc:
                        issues.append(clean(exc))
        if strict and issues:
            raise SafetyError('; '.join(issues))
        return sorted(records, key=lambda row: row['body']['created_at']), issues

    def remove(self, row, fd):
        verified = self.read(row['name'], fd)
        if verified['metadata'] != row['metadata'] or verified['encoded_digest'] != row['encoded_digest']:
            raise SafetyError('History retention target changed; preserved')
        isolated = '.' + row['body']['id'] + '.' + secrets.token_hex(8) + '.retiring.json.gz'
        rename_exclusive(fd, row['name'], fd, isolated)
        try:
            captured = self.read(isolated, fd)
            # Rename changes ctime. Identity, size, mtime and exact encoded bytes
            # bind the isolated record; never adopt a raced-in replacement.
            if captured['metadata'][:-1] != row['metadata'][:-1] or captured['encoded_digest'] != row['encoded_digest']:
                raise SafetyError('Isolated history target changed; unexpected bytes preserved')
        except SafetyError:
            if not os.path.lexists(self.path / row['name']):
                rename_exclusive(fd, isolated, fd, row['name'])
            raise
        os.unlink(isolated, dir_fd=fd)
        os.fsync(fd)

    def recover(self, rows, fd):
        for row in rows:
            if row['temporary']:
                destination = row['body']['id'] + '.json.gz'
                if os.path.lexists(self.path / destination):
                    raise SafetyError('Interrupted history target collision; both entries retained')
                if self.read(row['name'], fd)['metadata'] != row['metadata']:
                    raise SafetyError('Interrupted history entry changed')
                rename_exclusive(fd, row['name'], fd, destination)
        return self.inventory()[0]

    def capture(self, node, capacity, automatic=False, now=None):
        if not self.settings['enabled']:
            return {'skipped': 'history disabled', 'allocated_bytes': 0, 'limit_bytes': self.limit}
        if node.status == 'cancelled' or node.kind != 'directory':
            raise SafetyError('Cancelled/non-directory observations are unsuitable for history')
        now = time.time() if now is None else now
        body = {'schema': SCHEMA, 'id': secrets.token_hex(16), 'created_at': now,
                'scope': node.path, 'policy': policy(self.config, node.path),
                'directories': aggregates(node), 'capacity': capacity,
                'coverage': {'status': node.status, 'entries': node.entries, 'issues': [clean(issue) for issue in node.issues[:16]], 'aggregate_limit': MAX_ENTRIES}}
        self.validate(body, body['id'])
        raw = json_bytes(self.state.sign(body))
        if len(raw) > MAX_DECODED:
            raise SafetyError('History decoded size bound exceeded')
        encoded = gzip.compress(raw, mtime=0)
        if len(encoded) > MAX_ENCODED:
            raise SafetyError('History encoded size bound exceeded')
        # Conservative allocation reservation covers file rounding and directory
        # metadata growth, in addition to observed allocated bytes already present.
        unit = max(4096, os.statvfs(self.state.path).f_frsize)
        reservation = ((len(encoded) + unit - 1) // unit) * unit + 16 * unit
        if reservation > self.limit:
            raise SafetyError('History observation exceeds configured total budget')
        with self.state.lock():
            rows, _ = self.inventory()
            with directory_fd(self.path) as fd:
                rows = self.recover(rows, fd)
                compatible = [row for row in rows if row['body']['scope'] == body['scope'] and row['body']['policy'] == body['policy']]
                if automatic and compatible and now - compatible[-1]['body']['created_at'] < self.settings['auto_interval_seconds']:
                    return {'skipped': 'automatic capture rate limit', 'id': compatible[-1]['body']['id'], 'allocated_bytes': self.footprint(), 'limit_bytes': self.limit}
                cutoff = now - self.settings['max_days'] * 86400
                for row in list(rows):
                    if row['body']['created_at'] < cutoff:
                        self.remove(row, fd)
                        rows.remove(row)
                while rows and (len(rows) >= self.settings['max_snapshots'] or self.footprint() + reservation > self.limit):
                    self.remove(rows.pop(0), fd)
                if self.footprint() + reservation > self.limit:
                    raise SafetyError('Cannot reserve history capacity within hard budget')
                temporary = '.' + body['id'] + '.pending.json.gz'
                destination = body['id'] + '.json.gz'
                output = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
                try:
                    offset = 0
                    while offset < len(encoded):
                        offset += os.write(output, encoded[offset:])
                    os.fsync(output)
                finally:
                    os.close(output)
                os.fsync(fd)
                if self.footprint() > self.limit:
                    raise SafetyError('Unexpected history allocation exceeds budget; retained for inspection')
                rename_exclusive(fd, temporary, fd, destination)
                return {'id': body['id'], 'scope': node.path, 'created_at': now, 'directories': len(body['directories']),
                        'encoded_bytes': len(encoded), 'allocated_bytes': self.footprint(), 'limit_bytes': self.limit}

    def list(self):
        with self.state.lock():
            rows, issues = self.inventory(strict=False)
            return {'snapshots': [{'id': row['body']['id'], 'created_at': row['body']['created_at'], 'scope': row['body']['scope'], 'status': row['body']['coverage']['status'], 'directories': len(row['body']['directories']), 'temporary': row['temporary'], 'recent': row['body']['directories'][0]['recent'], 'capacity': row['body']['capacity']} for row in rows],
                    'issues': issues, 'allocated_bytes': self.footprint(), 'limit_bytes': self.limit,
                    'note': 'Earlier reported 380 GB directory breakdown is unknown. Recent activity bytes are clues, not measured growth.'}

    def clear(self):
        with self.state.lock():
            rows, _ = self.inventory()
            with directory_fd(self.path) as fd:
                for row in rows:
                    self.remove(row, fd)
            return {'removed': len(rows), 'allocated_bytes': self.footprint(), 'limit_bytes': self.limit}

    def compare(self, earlier=None, later=None, metric='allocated'):
        if metric not in {'logical', 'allocated'}:
            raise SafetyError('Unknown history size metric')
        with self.state.lock():
            records, issues = self.inventory(strict=False)
            committed = [row['body'] for row in records if not row['temporary']]
            def select(identifier, default):
                if identifier is None:
                    return default
                matches = [row for row in committed if row['id'] == identifier]
                if len(matches) != 1:
                    raise SafetyError('Unknown/altered history snapshot ID')
                return matches[0]
            latest = select(later, committed[-1] if committed else None)
            if latest is None:
                raise SafetyError('No history baseline exists yet')
            candidates = [row for row in committed if row['id'] != latest['id'] and row['created_at'] < latest['created_at'] and row['policy'] == latest['policy']]
            first = select(earlier, candidates[-1] if candidates else None)
            if first is None:
                return {'baseline': latest['id'], 'scope': latest['scope'], 'rows': [], 'capacity': [], 'issues': issues, 'note': 'First measured baseline: earlier 380 GB breakdown is unknown; another comparable observation is needed.'}
            return compare(first, latest, metric, issues)


def compare(first, latest, metric='allocated', issues=None):
    if first['scope'] != latest['scope'] or first['policy'] != latest['policy']:
        return {'earlier': first['id'], 'later': latest['id'], 'scope': latest['scope'], 'rows': [], 'capacity': [], 'issues': ['Incompatible measurement scope/policy'], 'note': 'No directory growth asserted across incompatible observations'}
    before = {row['path']: row for row in first['directories']}
    after = {row['path']: row for row in latest['directories']}
    rows = []
    for path in sorted(set(before) | set(after)):
        a, b = before.get(path), after.get(path)
        status, delta, percent = 'unknown', None, None
        if a and b and a['status'] == b['status'] == 'measured' and a['identity'] == b['identity']:
            delta = b[metric] - a[metric]
            percent = delta / a[metric] * 100 if a[metric] else None
            status = 'comparable'
        elif b and not a:
            parent = before.get(str(Path(path).parent))
            if parent and parent['children_complete'] and b['status'] == 'measured':
                status, delta = 'new-directory', b[metric]
            else:
                status = 'newly-observed'
        elif a and not b:
            parent = after.get(str(Path(path).parent))
            if parent and parent['children_complete'] and a['status'] == 'measured':
                status, delta = 'removed-directory', -a[metric]
        rows.append({'path': path, 'status': status, 'before': a[metric] if a else None, 'after': b[metric] if b else None, 'delta': delta, 'percent': percent, 'recent': b['recent'] if b else {}, 'overlaps_parent': path != latest['scope']})
    capacity = []
    old = {row['path']: row for row in first['capacity'] if row.get('status') == 'measured'}
    fingerprints = set()
    for row in latest['capacity']:
        previous = old.get(row['path'])
        if row.get('status') != 'measured' or previous is None:
            continue
        values = (previous['total'], previous['used'], previous['available'], row['total'], row['used'], row['available'])
        alias = values in fingerprints
        fingerprints.add(values)
        capacity.append({'path': row['path'], 'label': row['label'], 'used_delta': row['used'] - previous['used'], 'available_delta': row['available'] - previous['available'], 'shared_observation_alias': alias})
    return {'earlier': first['id'], 'later': latest['id'], 'scope': latest['scope'], 'metric': metric,
            'earlier_at': first['created_at'], 'later_at': latest['created_at'], 'rows': rows, 'capacity': capacity, 'issues': issues or [],
            'note': 'Parent/child deltas overlap; never sum them. Partial attribution is unknown. Recent mtime/birth bytes are clues, not growth. Capacity trends are separate APFS observations.'}
