"""Streaming authenticated directory tree with automatic storage sizing."""
import gzip
import hashlib
import hmac
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

MAX_DECODED = 64 * 1024 * 1024
SCHEMA = 'mactrim.storage-cache.v1'
MAGIC_V2 = b'MACTRIM-INDEX-2\n'
MAGIC = b'MACTRIM-INDEX-3\n'
AUTH_BYTES = 65  # SHA-256 hex digest plus newline
FIELDS = ('logical', 'allocated', 'own_logical', 'own_allocated', 'entries',
          'direct_files', 'newest_ns', 'status', 'kind', 'protected', 'issues',
          'alias_of', 'recent', 'identity', 'signature', 'details_deferred')


class BudgetExceeded(Exception):
    def __init__(self, required):
        self.required = required


class BudgetedWriter:
    """Enforce an explicit allocation budget before writing compressed chunks."""
    def __init__(self, stream, limit, footprint, unit):
        self.stream, self.limit, self.footprint, self.unit = stream, limit, footprint, unit

    def write(self, data):
        if self.limit is not None:
            length = self.stream.tell() + len(data)
            required = self.footprint + ((length + self.unit - 1) // self.unit) * self.unit + 4 * self.unit
            if required > self.limit:
                raise BudgetExceeded(required)
        return self.stream.write(data)

    def tell(self):
        return self.stream.tell()

def metadata(st):
    return (st.st_dev, st.st_ino, st.st_mode, st.st_uid, st.st_nlink, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def flatten(root, cancel=None):
    # Parent precedes children; only an iterator per depth is retained.
    def row(node, parent):
        values = {key: getattr(node, key) for key in FIELDS}
        values.update(path=node.path, name=node.name, parent=parent)
        return values
    check_cancel(cancel)
    yield row(root, -1)
    pending, ordinal = [(iter(root.children), 0)], 0
    while pending:
        check_cancel(cancel)
        children, parent = pending[-1]
        try:
            node = next(children)
        except StopIteration:
            pending.pop()
            continue
        ordinal += 1
        yield row(node, parent)
        pending.append((iter(node.children), ordinal))


def node_from_row(row, scope, nodes):
    if not isinstance(row, dict):
        raise SafetyError('Invalid cached directory object')
    row = dict(row, details_deferred=row.get('details_deferred', False))
    if type(row['details_deferred']) is not bool:
        raise SafetyError('Invalid deferred directory detail flag')
    path = row.get('path')
    if not isinstance(path, str) or str(canonical(path)) != path or not within(path, scope) or path in nodes:
        raise SafetyError('Escaped/duplicate cached directory')
    if row.get('status') not in {'measured', 'partial', 'denied', 'skipped', 'deferred'}:
        raise SafetyError('Invalid cache observation status')
    for key in ('logical', 'allocated', 'own_logical', 'own_allocated', 'entries', 'direct_files'):
        if type(row.get(key)) is not int or not 0 <= row[key] <= 2**64:
            raise SafetyError('Invalid cache byte/entry count')
    if not isinstance(row.get('identity'), (list, tuple)) or len(row['identity']) not in (0, 2):
        raise SafetyError('Invalid cached identity')
    if not isinstance(row.get('issues'), list) or not all(isinstance(value, str) for value in row['issues']) or not isinstance(row.get('name'), str):
        raise SafetyError('Invalid cache diagnostic data')
    recent = row.get('recent')
    if not isinstance(recent, dict) or set(recent) != {'modified_7d', 'modified_30d', 'created_7d'} or any(type(value) is not int or not 0 <= value <= 2**64 for value in recent.values()):
        raise SafetyError('Invalid cache recent activity')
    if not isinstance(row.get('signature'), (list, tuple)) or len(row['signature']) not in (0, 6) or any(type(value) is not int for value in tuple(row['signature']) + tuple(row['identity'])):
        raise SafetyError('Invalid cache metadata signature')
    node = StorageNode(path, row['name'])
    for key in FIELDS:
        setattr(node, key, tuple(row[key]) if key in {'identity', 'signature'} else row[key])
    nodes[path] = node
    return node


def inflate(rows, scope):
    if not isinstance(rows, list) or not rows:
        raise SafetyError('Cache directory inventory invalid')
    nodes = {}
    for row in rows:
        node_from_row(row, scope, nodes)
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
        self.limit = settings['max_bytes']
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

    def read(self, cancel=None, details=True):
        self.prepare()
        # A smaller configured budget never makes an existing valid index
        # unreadable. The budget applies to the next atomic write.
        self.footprint()
        with directory_fd(self.path) as fd:
            try:
                st = os.stat('index.json.gz', dir_fd=fd, follow_symlinks=False)
            except FileNotFoundError:
                return None
            file_fd = os.open('index.json.gz', os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
            try:
                before = os.fstat(file_fd)
                if metadata(before) != metadata(st):
                    raise SafetyError('Cache replaced before read')
                with os.fdopen(os.dup(file_fd), 'rb') as stream:
                    prefix = stream.read(len(MAGIC))
                    if prefix in {MAGIC, MAGIC_V2}:
                        signature = stream.read(AUTH_BYTES)
                        auth = hmac.new(self.state.key, prefix, hashlib.sha256)
                        while chunk := stream.read(1024 * 1024):
                            check_cancel(cancel)
                            auth.update(chunk)
                        if not hmac.compare_digest(signature, auth.hexdigest().encode() + b'\n'):
                            raise SafetyError('Directory index authentication failed; preserved')
                        stream.seek(len(MAGIC) + AUTH_BYTES)
                        # Authenticate compressed bytes before decoding them.
                        with gzip.GzipFile(fileobj=stream) as decoded:
                            body = json.loads(decoded.readline())
                            self.validate_body(body)
                            if not body['complete_index']:
                                raise SafetyError('Invalid compact index completeness')
                            nodes, ordered = {}, []
                            fields = FIELDS if prefix == MAGIC else FIELDS[:-1]
                            for line in decoded if details else ():
                                check_cancel(cancel)
                                record = json.loads(line)
                                if not isinstance(record, list) or len(record) != len(fields) + 2:
                                    raise SafetyError('Invalid compact directory record')
                                parent, name = record[:2]
                                if type(parent) is not int or not isinstance(name, str):
                                    raise SafetyError('Invalid directory parent/name')
                                if not ordered:
                                    if parent != -1:
                                        raise SafetyError('Directory root missing')
                                    path = body['scope']
                                else:
                                    if not 0 <= parent < len(ordered) or name in {'', '.', '..'} or '/' in name or '\x00' in name:
                                        raise SafetyError('Invalid directory tree link')
                                    path = str(Path(ordered[parent].path) / name)
                                row = dict(zip(fields, record[2:]), path=path, name=name)
                                node = node_from_row(row, body['scope'], nodes)
                                if ordered:
                                    ordered[parent].children.append(node)
                                ordered.append(node)
                            if details and not ordered:
                                raise SafetyError('Directory inventory missing')
                            root = ordered[0] if ordered else None
                            if details:
                                body['directories'] = flatten(root)
                                body['directory_count'] = len(ordered)
                    else:
                        stream.seek(0)
                        with gzip.GzipFile(fileobj=stream) as decoded:
                            raw = decoded.read(MAX_DECODED + 1)
                        if len(raw) > MAX_DECODED:
                            raise SafetyError('Legacy cache decode bound exceeded')
                        body = self.state.verify_signed(json.loads(raw))
                        self.validate_body(body)
                        root, nodes = inflate(body['directories'], body['scope']) if body['complete_index'] and details else (None, {})
                        if root is not None:
                            body['directories'] = flatten(root)
                    stream.seek(0)
                    digest = hashlib.sha256()
                    while chunk := stream.read(1024 * 1024):
                        check_cancel(cancel)
                        digest.update(chunk)
                if metadata(os.fstat(file_fd)) != metadata(before):
                    raise SafetyError('Cache changed while reading')
            except (OSError, ValueError, KeyError, TypeError, EOFError) as exc:
                raise SafetyError('Corrupt cache preserved; complete fallback required') from exc
            finally:
                os.close(file_fd)
        self.read_metadata, self.read_digest = st, digest.digest()
        return body, root, nodes

    @staticmethod
    def validate_body(body):
        if not isinstance(body, dict) or type(body.get('created_at')) not in (int, float) or not math.isfinite(body['created_at']) or type(body.get('full_at')) not in (int, float) or not math.isfinite(body['full_at']) or type(body.get('complete_index')) is not bool or type(body.get('requires_reconcile')) is not bool:
            raise SafetyError('Invalid cache transaction metadata')
        if body['schema'] != SCHEMA or type(body['checkpoint']) is not int or body['checkpoint'] < 0 or body['created_at'] > time.time() + 60:
            raise SafetyError('Cache schema/checkpoint invalid')
        if type(body.get('reuse_allowed', True)) is not bool:
            raise SafetyError('Invalid index reuse eligibility')

    def write(self, body, cancel=None):
        check_cancel(cancel)
        self.prepare()
        self.validate_body(body)
        if not body['complete_index']:
            raise SafetyError('Refusing truncated directory inventory')
        with self.state.lock(), directory_fd(self.path) as fd:
            expected = self.read_digest
            current = self.read(cancel=cancel, details=False)
            if self.read_digest != expected:
                raise SafetyError('Concurrent cache revision changed; no checkpoint committed')
            footprint = self.footprint()
            if self.read_digest is not None and current is None:
                raise SafetyError('Cache disappeared during transaction')
            if body.get('previous_checkpoint') is not None and current and current[0]['checkpoint'] != body['previous_checkpoint']:
                raise SafetyError('Concurrent cache refresh won; candidate preserved in memory')
            name = '.pending-' + secrets.token_hex(8)
            out = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            committed, isolated, rows = False, None, 0
            owned = os.fstat(out)
            try:
                with os.fdopen(os.dup(out), 'r+b') as stream:
                    bounded = BudgetedWriter(stream, self.limit, footprint, self.unit)
                    bounded.write(MAGIC + b'0' * 64 + b'\n')
                    with gzip.GzipFile(fileobj=bounded, mode='wb', mtime=0) as encoded:
                        transaction = {key: value for key, value in body.items() if key not in {'directories', 'directory_count'}}
                        encoded.write(json_bytes(transaction) + b'\n')
                        for row in body['directories']:
                            check_cancel(cancel)
                            encoded.write(json_bytes([row['parent'], row['name']] + [row[key] for key in FIELDS]) + b'\n')
                            rows += 1
                    if not rows:
                        raise SafetyError('Refusing empty directory inventory')
                    stream.flush()
                    actual = os.fstat(out).st_blocks * 512
                    required = footprint + actual + 4 * self.unit
                    if self.limit is not None and required > self.limit:
                        return {'stored': False, 'reason': 'Explicit cache budget cannot retain the whole tree; previous index preserved',
                                'directory_count': rows, 'required_bytes': required,
                                'allocated_bytes': footprint, 'limit_bytes': self.limit}
                    self.peak = max(self.peak, footprint + actual)
                    stream.seek(len(MAGIC) + AUTH_BYTES)
                    auth = hmac.new(self.state.key, MAGIC, hashlib.sha256)
                    while chunk := stream.read(1024 * 1024):
                        check_cancel(cancel)
                        auth.update(chunk)
                    stream.seek(len(MAGIC))
                    stream.write(auth.hexdigest().encode() + b'\n')
                    stream.flush()
                    os.fsync(out)
                check_cancel(cancel)
                if current:
                    isolated = '.retiring-' + secrets.token_hex(8)
                    rename_exclusive(fd, 'index.json.gz', fd, isolated)
                    try:
                        self.verify_isolated(fd, isolated, self.read_metadata, self.read_digest)
                    except SafetyError:
                        if not os.path.lexists(self.path / 'index.json.gz'):
                            rename_exclusive(fd, isolated, fd, 'index.json.gz')
                        raise
                rename_exclusive(fd, name, fd, 'index.json.gz')
                committed = True
                if isolated:
                    self.verify_isolated(fd, isolated, self.read_metadata, self.read_digest)
                    os.unlink(isolated, dir_fd=fd)
                os.fsync(fd)
            except BudgetExceeded as exc:
                return {'stored': False, 'reason': 'Explicit cache budget cannot retain the whole tree; previous index preserved',
                        'directories_serialized': rows, 'required_bytes': exc.required, 'requirement_is_lower_bound': True,
                        'allocated_bytes': footprint, 'limit_bytes': self.limit}
            finally:
                if not committed:
                    if isolated and not os.path.lexists(self.path / 'index.json.gz'):
                        self.verify_isolated(fd, isolated, self.read_metadata, self.read_digest)
                        rename_exclusive(fd, isolated, fd, 'index.json.gz')
                    # Remove only this transaction's still-open owned inode.
                    try:
                        pending = os.stat(name, dir_fd=fd, follow_symlinks=False)
                        if (pending.st_dev, pending.st_ino) == (owned.st_dev, owned.st_ino):
                            os.unlink(name, dir_fd=fd)
                    except FileNotFoundError:
                        pass
                os.close(out)
        return {'stored': True, 'complete_index': True, 'directory_count': rows,
                'allocated_bytes': self.footprint(), 'peak_allocated_bytes': self.peak,
                'limit_bytes': self.limit}

    def verify_isolated(self, fd, name, observed, digest):
        st = os.stat(name, dir_fd=fd, follow_symlinks=False)
        if metadata(st)[:-1] != metadata(observed)[:-1]:
            raise SafetyError('Isolated cache changed; unexpected input preserved')
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=fd)
        try:
            if metadata(os.fstat(file_fd)) != metadata(st):
                raise SafetyError('Isolated cache replaced; preserved')
            with os.fdopen(os.dup(file_fd), 'rb') as stream:
                actual_digest = hashlib.sha256()
                while chunk := stream.read(1024 * 1024):
                    actual_digest.update(chunk)
            if actual_digest.digest() != digest or metadata(os.fstat(file_fd)) != metadata(st):
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
