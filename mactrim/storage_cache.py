"""Disposable signed directory index. The allocation cap never caps scanning."""
import gzip
import hashlib
import io
import json
import math
import os
from pathlib import Path
import secrets
import stat
import time
from .safety import SafetyError, canonical, directory_fd, json_bytes, within, rename_exclusive
from .storage import StorageNode
from .regions import check_cancel

MAX_BYTES = 16 * 1024 * 1024
MAX_DECODED = 64 * 1024 * 1024
SCHEMA = 'mactrim.storage-cache.v1'

def metadata(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def flatten(root, cancel=None):
    rows, pending = [], [root]
    while pending:
        check_cancel(cancel)
        node = pending.pop()
        row = dict(node.summary(), path=node.path, name=node.name, protected=node.protected,
                   own_logical=node.own_logical, own_allocated=node.own_allocated,
                   direct_files=node.direct_files, signature=list(getattr(node, 'signature', ())),
                   child_paths=[child.path for child in node.children])
        # Root-only instrumentation belongs to the transaction, not every row.
        for key in ('counters', 'exclusions', 'started_at', 'completed_at'):
            row.pop(key, None)
        rows.append(row)
        pending.extend(node.children)
    return rows


def inflate(rows, scope):
    if not isinstance(rows, list) or not rows or len(rows) > 200000:
        raise SafetyError('Cache directory inventory invalid')
    nodes = {}
    for row in rows:
        if not isinstance(row, dict):
            raise SafetyError('Invalid cached directory object')
        path = row.get('path')
        if not isinstance(path, str) or str(canonical(path)) != path or not within(path, scope) or path in nodes:
            raise SafetyError('Escaped/duplicate cached directory')
        if row.get('status') not in {'measured', 'partial', 'denied', 'skipped'}:
            raise SafetyError('Invalid cache observation status')
        for key in ('logical', 'allocated', 'own_logical', 'own_allocated', 'entries', 'direct_files'):
            if type(row.get(key)) is not int or not 0 <= row[key] <= 2**64:
                raise SafetyError('Invalid cache byte/entry count')
        if not isinstance(row.get('identity'), list) or len(row['identity']) not in (0, 2):
            raise SafetyError('Invalid cached identity')
        if not isinstance(row.get('issues'), list) or not all(isinstance(value, str) for value in row['issues']) or not isinstance(row.get('name'), str):
            raise SafetyError('Invalid cache diagnostic data')
        recent = row.get('recent')
        if not isinstance(recent, dict) or set(recent) != {'modified_7d', 'modified_30d', 'created_7d'} or any(type(value) is not int or not 0 <= value <= 2**64 for value in recent.values()):
            raise SafetyError('Invalid cache recent activity')
        if not isinstance(row.get('signature'), list) or len(row['signature']) not in (0, 6) or any(type(value) is not int for value in row['signature'] + row['identity']):
            raise SafetyError('Invalid cache metadata signature')
        node = StorageNode(path, row['name'])
        for key in ('logical', 'allocated', 'own_logical', 'own_allocated', 'entries', 'direct_files',
                    'newest_ns', 'status', 'kind', 'protected', 'issues', 'alias_of', 'recent'):
            setattr(node, key, row[key])
        node.identity = tuple(row['identity'])
        node.signature = tuple(row['signature'])
        nodes[path] = node
    for row in rows:
        children = row['child_paths']
        if not isinstance(children, list) or len(set(children)) != len(children):
            raise SafetyError('Invalid cache child paths')
        for child in children:
            if child not in nodes or str(Path(child).parent) != row['path'] or child == scope:
                raise SafetyError('Incomplete/non-tree directory index')
        nodes[row['path']].children = [nodes[child] for child in children]
    if scope not in nodes:
        raise SafetyError('Cache root missing')
    # Reachability validates that disconnected payloads cannot hide omitted data.
    seen, todo = set(), [scope]
    while todo:
        path = todo.pop()
        if path in seen:
            raise SafetyError('Cache tree cycle')
        seen.add(path); todo.extend(child.path for child in nodes[path].children)
    if seen != set(nodes):
        raise SafetyError('Disconnected cache tree')
    return nodes[scope], nodes


class Cache:
    def __init__(self, state, settings):
        self.state, self.settings = state, settings
        self.path = state.path / 'storage-cache'
        self.limit = min(MAX_BYTES, settings['max_bytes'])
        self.unit = max(4096, os.statvfs(state.path).f_frsize)
        self.peak = 0
        self.read_metadata = None
        self.read_digest = None

    def prepare(self):
        self.state.verify()
        with directory_fd(self.state.path) as fd:
            try:
                os.mkdir('storage-cache', 0o700, dir_fd=fd)
            except FileExistsError:
                pass
        self.state._private(self.path, True)

    def footprint(self):
        self.prepare()
        total = os.lstat(self.path).st_blocks * 512
        with directory_fd(self.path) as fd:
            names = os.listdir(fd)
            if set(names) - {'index.json.gz'}:
                raise SafetyError('Unexpected cache entries preserved')
            for name in names:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o600 or st.st_nlink != 1:
                    raise SafetyError('Unsafe cache entry preserved')
                total += st.st_blocks * 512
        return total

    def read(self):
        self.prepare()
        if self.footprint() > self.limit:
            raise SafetyError('Existing cache exceeds cap; preserved, reuse disabled')
        with directory_fd(self.path) as fd:
            try:
                st = os.stat('index.json.gz', dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            if st.st_size > self.limit:
                raise SafetyError('Oversized cache preserved')
            file_fd = os.open('index.json.gz', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                before = os.fstat(file_fd)
                if metadata(before) != metadata(st):
                    raise SafetyError('Cache replaced before read')
                with os.fdopen(os.dup(file_fd), 'rb') as stream:
                    encoded = stream.read(self.limit + 1)
                if metadata(os.fstat(file_fd)) != metadata(before):
                    raise SafetyError('Cache changed while reading')
            finally:
                os.close(file_fd)
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(encoded)) as stream:
                raw = stream.read(MAX_DECODED + 1)
            if len(raw) > MAX_DECODED:
                raise SafetyError('Cache decode bound exceeded')
            body = self.state.verify_signed(json.loads(raw))
            if not isinstance(body, dict) or type(body.get('created_at')) not in (int, float) or not math.isfinite(body['created_at']) or type(body.get('full_at')) not in (int, float) or not math.isfinite(body['full_at']) or type(body.get('complete_index')) is not bool or type(body.get('requires_reconcile')) is not bool:
                raise SafetyError('Invalid cache transaction metadata')
            if body['schema'] != SCHEMA or type(body['checkpoint']) is not int or body['checkpoint'] < 0 or body['created_at'] > time.time() + 60:
                raise SafetyError('Cache schema/checkpoint invalid')
            root, nodes = inflate(body['directories'], body['scope']) if body['complete_index'] else (None, {})
        except (OSError, ValueError, KeyError, TypeError, EOFError) as exc:
            raise SafetyError('Corrupt cache preserved; complete fallback required') from exc
        self.read_metadata, self.read_digest = st, hashlib.sha256(encoded).digest()
        return body, root, nodes

    def write(self, body, cancel=None):
        check_cancel(cancel)
        self.prepare()
        encoded = gzip.compress(json_bytes(self.state.sign(body)), mtime=0)
        footprint = self.footprint()
        # Reserve old + replacement allocations concurrently, including metadata.
        reserve = ((len(encoded) + self.unit - 1) // self.unit) * self.unit + 4 * self.unit
        if footprint + reserve > self.limit or len(body['directories']) > 200000 or len(json_bytes(body)) > MAX_DECODED // 2:
            # Preserve complete totals as a small hint; missing index details
            # invalidate reuse next time, never the baseline measurement.
            body = dict(body, directories=[dict(body['directories'][0], child_paths=[])], complete_index=False)
            encoded = gzip.compress(json_bytes(self.state.sign(body)), mtime=0)
            reserve = ((len(encoded) + self.unit - 1) // self.unit) * self.unit + 4 * self.unit
        if footprint + reserve > self.limit:
            return {'stored': False, 'reason': 'Cache cap too small for atomic replacement; next scan measures fully', 'allocated_bytes': footprint, 'limit_bytes': self.limit}
        check_cancel(cancel)
        with self.state.lock(), directory_fd(self.path) as fd:
            expected = self.read_digest
            current = self.read()
            if self.read_digest != expected:
                raise SafetyError('Concurrent cache revision changed; no checkpoint committed')
            footprint = self.footprint()
            if footprint + reserve > self.limit:
                raise SafetyError('Concurrent cache allocation changed; no checkpoint committed')
            if self.read_digest is not None and current is None:
                raise SafetyError('Cache disappeared during transaction')
            # The caller binds expected cache revision separately; this lock only
            # covers commit, never filesystem traversal.
            if body.get('previous_checkpoint') is not None and current and current[0]['checkpoint'] != body['previous_checkpoint']:
                raise SafetyError('Concurrent cache refresh won; candidate preserved in memory')
            check_cancel(cancel)
            name = '.pending-' + secrets.token_hex(8)
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                view = memoryview(encoded)
                while view:
                    view = view[os.write(out, view):]
                os.fsync(out)
                actual = os.fstat(out).st_blocks * 512
                self.peak = max(self.peak, footprint + actual)
                if footprint + actual > self.limit:
                    raise SafetyError('Allocation exceeds reserved cache cap')
            finally:
                os.close(out)
            isolated = None
            if current:
                isolated = '.retiring-' + secrets.token_hex(8)
                rename_exclusive(fd, 'index.json.gz', fd, isolated)
                try:
                    self.verify_isolated(fd, isolated, self.read_metadata, self.read_digest)
                except SafetyError:
                    if not os.path.lexists(self.path / 'index.json.gz'):
                        rename_exclusive(fd, isolated, fd, 'index.json.gz')
                    raise
            # An unexpected new destination is preserved, never overwritten.
            rename_exclusive(fd, name, fd, 'index.json.gz')
            if isolated:
                self.verify_isolated(fd, isolated, self.read_metadata, self.read_digest)
                os.unlink(isolated, dir_fd=fd)
            os.fsync(fd)
        return {'stored': True, 'complete_index': body['complete_index'], 'allocated_bytes': self.footprint(), 'peak_allocated_bytes': self.peak, 'limit_bytes': self.limit}

    def verify_isolated(self, fd, name, observed, digest):
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if metadata(st)[:-1] != metadata(observed)[:-1]:
            raise SafetyError('Isolated cache changed; unexpected input preserved')
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            if metadata(os.fstat(file_fd)) != metadata(st):
                raise SafetyError('Isolated cache replaced; preserved')
            with os.fdopen(os.dup(file_fd), 'rb') as stream:
                encoded = stream.read(self.limit + 1)
            if hashlib.sha256(encoded).digest() != digest or metadata(os.fstat(file_fd)) != metadata(st):
                raise SafetyError('Isolated cache bytes changed; preserved')
        finally:
            os.close(file_fd)

    def clear(self):
        with self.state.lock():
            observed = self.read()
            if observed is None:
                return {'cleared': False}
            with directory_fd(self.path) as fd:
                isolated = '.retiring-' + secrets.token_hex(8)
                rename_exclusive(fd, 'index.json.gz', fd, isolated)
                try:
                    self.verify_isolated(fd, isolated, self.read_metadata, self.read_digest)
                except SafetyError:
                    if not os.path.lexists(self.path / 'index.json.gz'):
                        rename_exclusive(fd, isolated, fd, 'index.json.gz')
                    raise
                os.unlink(isolated, dir_fd=fd)
                os.fsync(fd)
        return {'cleared': True, 'allocated_bytes': self.footprint()}
