"""Typed Git worktree evidence and a scoped, journaled Git-aware lifecycle."""
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time

from .measurement import measure
from .git_runtime import environment, prefix
from .safety import Budget, SafetyError, ancestor_identity, canonical, clean, digest, file_hash, fingerprint, within, directory_fd, rename_exclusive, remove_tree_fd

GENERATED = {'.venv', 'venv', '__pycache__', '.pytest_cache', '.mypy_cache', '.ruff_cache', 'node_modules'}


def command(common_or_repo, *args, allow_one=False, git_dir=False):
    result = subprocess.run(prefix(common_or_repo, git_dir) + list(args), env=environment(), capture_output=True, timeout=20)
    if (result.returncode and not (allow_one and result.returncode == 1)) or len(result.stdout) > 16 * 1024 * 1024 :
        raise SafetyError('Git worktree evidence/operation failed: ' + clean(result.stderr.decode(errors='replace')[:400]))
    return result


def common_dir(repo):
    raw = command(repo, 'rev-parse', '--git-common-dir').stdout.decode(errors='surrogateescape').strip()
    return canonical(raw if Path(raw).is_absolute() else Path(repo) / raw)


def registrations(common):
    output = command(common, 'worktree', 'list', '--porcelain', '-z', git_dir=True).stdout
    records = []
    row = {}
    for raw in output.split(b'\0'):
        if not raw:
            if row:
                records.append(row)
                row = {}
            continue
        value = raw.decode(errors='surrogateescape')
        key, _, tail = value.partition(' ')
        row[key] = tail if tail else True
    if row:
        records.append(row)
    if not records or not all(isinstance(row.get('worktree'), str) for row in records):
        raise SafetyError('Git worktree registry is malformed or empty')
    return records


def default_target(common, config):
    explicit = config.get('worktree_default_ref', '')
    if explicit:
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', explicit) or '..' in explicit:
            raise SafetyError('Invalid configured default reference')
        reference = explicit
        origin = 'explicit configured default; local ref snapshot'
    else:
        remote = command(common, 'symbolic-ref', '--quiet', 'refs/remotes/origin/HEAD', git_dir=True, allow_one=True)
        if remote.returncode == 0:
            reference = remote.stdout.decode().strip()
            origin = 'local origin/HEAD; remote freshness is not implied'
        else:
            present = [name for name in ('refs/heads/main', 'refs/heads/master') if command(common, 'show-ref', '--verify', '--quiet', name, git_dir=True, allow_one=True).returncode == 0]
            primary = registrations(common)[0]
            if len(present) != 1 or primary.get('branch') != present[0]:
                raise SafetyError('Default target is unknown; set worktree_default_ref or refresh remote HEAD')
            reference = present[0]
            origin = 'primary conventional default branch; local ref snapshot'
    sha = command(common, 'rev-parse', '--verify', reference + '^{commit}', git_dir=True).stdout.decode().strip()
    return reference, sha, origin


def _github_squash(common, head, target_ref, target_sha, config):
    if not config.get('github_squash'):
        return None
    result = command(common, 'config', '--get', 'remote.origin.url', git_dir=True, allow_one=True)
    if result.returncode:
        return None
    url = result.stdout.decode().strip()
    match = re.fullmatch(r'(?:https://github.com/|git@github.com:)([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?', url)
    if not match:
        return None
    slug = match.group(1)
    try:
        response = subprocess.run(['gh', 'api', 'repos/' + slug + '/pulls?state=closed&per_page=100'], capture_output=True, timeout=15)
        if response.returncode or len(response.stdout) > 8 * 1024 * 1024:
            return None
        pulls = json.loads(response.stdout)
        branch = target_ref.removeprefix('refs/remotes/origin/').removeprefix('refs/heads/')
        for pr in pulls:
            if pr.get('merged_at') and pr.get('head', {}).get('sha') == head and pr.get('base', {}).get('ref') == branch:
                merged = pr.get('merge_commit_sha')
                if isinstance(merged, str) and re.fullmatch(r'[0-9a-f]{40,64}', merged) and command(common, 'merge-base', '--is-ancestor', merged, target_sha, git_dir=True, allow_one=True).returncode == 0:
                    return {'type': 'github-merged-pr', 'url': pr.get('html_url'), 'head': head, 'merge_commit': merged, 'queried_at': time.time()}
    except (OSError, ValueError, subprocess.TimeoutExpired, SafetyError):
        return None
    return None


def merge_proof(common, head, config):
    reference, target, origin = default_target(common, config)
    if command(common, 'merge-base', '--is-ancestor', head, target, git_dir=True, allow_one=True).returncode == 0:
        proof = {'type': 'git-ancestor', 'head': head, 'target_sha': target}
    else:
        proof = _github_squash(common, head, reference, target, config)
        if not proof:
            raise SafetyError('HEAD is not proven incorporated; squash/unique commits remain review-only')
    return {'default_ref': reference, 'target_sha': target, 'target_source': origin, 'merge_proof': proof}


def _admin(path, common, expected=None):
    path, common = canonical(path), canonical(common)
    ancestor_identity(common)
    if os.lstat(common).st_uid != os.getuid():
        raise SafetyError('Git common directory is not user-owned')
    pointer = path / '.git'
    st = os.lstat(pointer)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
        raise SafetyError('Linked worktree .git must be an owned regular pointer')
    with open(pointer, 'rb') as stream:
        raw = stream.read(4097)
    if len(raw) > 4096 or not raw.startswith(b'gitdir: '):
        raise SafetyError('Unexpected worktree Git pointer')
    text = raw[8:].decode(errors='surrogateescape').strip()
    admin = canonical(text if Path(text).is_absolute() else path / text)
    if admin.parent != common / 'worktrees' or expected and str(admin) != expected:
        raise SafetyError('Worktree administrative directory changed or escaped common registry')
    ancestor_identity(admin)
    if os.lstat(admin).st_uid != os.getuid():
        raise SafetyError('Worktree administrative metadata has wrong owner')
    for name in ('gitdir', 'commondir', 'HEAD'):
        item = admin / name
        value = os.lstat(item)
        if not stat.S_ISREG(value.st_mode) or value.st_uid != os.getuid() or value.st_nlink != 1:
            raise SafetyError('Unsafe worktree administrative file: ' + name)
    with open(admin / 'commondir', 'r', encoding='utf-8', errors='surrogateescape') as stream:
        relative_common = stream.read(4097).strip()
    if len(relative_common) > 4096 or canonical(admin / relative_common) != common:
        raise SafetyError('Worktree common-directory pointer escaped its registry')
    return admin


def bound_checkout(path, common, admin):
    top = canonical(command(path, 'rev-parse', '--show-toplevel').stdout.decode(errors='surrogateescape').strip())
    actual_admin = command(path, 'rev-parse', '--git-dir').stdout.decode(errors='surrogateescape').strip()
    index = command(path, 'rev-parse', '--git-path', 'index').stdout.decode(errors='surrogateescape').strip()
    actual_admin = canonical(actual_admin if Path(actual_admin).is_absolute() else path / actual_admin)
    index = canonical(index if Path(index).is_absolute() else path / index)
    if top != path or actual_admin != admin or common_dir(path) != common or index != admin / 'index':
        raise SafetyError('Git checkout/index/common scope is redirected or changed')
    st = os.lstat(index)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_nlink != 1:
        raise SafetyError('Worktree index must be an owned regular captured file')


def meaningful_contents(path):
    sparse = command(path, 'config', '--bool', '--get', 'core.sparseCheckout', allow_one=True).stdout.strip()
    if sparse == b'true':
        raise SafetyError('Sparse checkout may hide unique tracked data')
    for flag in ('-v', '-f'):
        tags = command(path, 'ls-files', flag, '-z').stdout.split(b'\0')
        if any(entry and (entry[:1].islower() or entry[:1] == b'S') for entry in tags):
            raise SafetyError('Hidden index assume-unchanged/skip-worktree/fsmonitor flags protect tracked data')
    staged = command(path, 'ls-files', '--stage', '-z').stdout
    if any(entry.startswith(b'160000 ') for entry in staged.split(b'\0')):
        raise SafetyError('Initialized or registered submodules block worktree cleanup')
    status = command(path, 'status', '--porcelain=v1', '-z', '--untracked-files=all').stdout
    if status:
        raise SafetyError('Dirty or untracked worktree data must be preserved')
    ignored = command(path, 'ls-files', '--others', '--ignored', '--exclude-standard', '-z').stdout
    for raw in ignored.split(b'\0'):
        if not raw:
            continue
        relative = Path(raw.decode(errors='surrogateescape'))
        if not relative.parts or relative.parts[0] not in GENERATED:
            raise SafetyError('Meaningful or unknown ignored worktree data is protected: ' + clean(relative))
        top = relative.parts[0]
        if top in {'.venv', 'venv'}:
            if not (path / top / 'pyvenv.cfg').is_file() or not any(
                    bool(command(path, 'ls-files', '-z', '--', name).stdout) and (path / name).is_file() and not (path / name).is_symlink()
                    for name in ('requirements.txt', 'pyproject.toml', 'Pipfile.lock', 'poetry.lock', 'uv.lock', 'environment.yml')):
                raise SafetyError('Ignored environment regeneration lacks tracked dependency specification')
            if len(relative.parts) < 2 or relative.parts[1] not in {'pyvenv.cfg', 'bin', 'lib', 'lib64', 'include', 'share', '.gitignore', 'CACHEDIR.TAG'}:
                raise SafetyError('Unknown or unique ignored environment contents are protected: ' + clean(relative))
        if top == 'node_modules' and not any((path / name).is_file() for name in ('package-lock.json', 'pnpm-lock.yaml', 'yarn.lock')):
            raise SafetyError('Ignored node modules have no lockfile')


def worktree_fingerprint(path, config, quarantine=False, cancel=None):
    result = fingerprint(path, Budget(config['max_files'], config['max_depth'], cancel), inspect_protected=not quarantine,
                         exclude_top=('.git',), normalize_root=True)
    result['algorithm'] = 'git-worktree.v1'
    return result


def common_identity(common):
    common = canonical(common)
    ancestors = ancestor_identity(common.parent)
    st = os.lstat(common)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise SafetyError('Common Git directory must be user-owned and real')
    return [st.st_dev, st.st_ino, st.st_uid], ancestors


def bound_common(context):
    common = canonical(context['common_dir'])
    identity, ancestors = common_identity(common)
    if identity != context.get('common_identity') or ancestors != context.get('common_ancestors'):
        raise SafetyError('Captured common Git directory or ancestors changed')
    return common


def policy(path, config, state, process, expected=None, relocated=False, cancel=None):
    path = canonical(path)
    if not relocated and not any(within(path, root) for root in config['worktree_roots']):
        raise SafetyError('Registered worktree is outside configured action roots')
    common = canonical(expected['common_dir']) if expected else common_dir(path)
    if expected:
        bound_common(expected)
    rows = registrations(common)
    row = next((row for row in rows if canonical(row['worktree']) == path), None)
    if not row:
        raise SafetyError('Worktree registry no longer names this path')
    if canonical(rows[0]['worktree']) == path or row.get('bare'):
        raise SafetyError('Primary/canonical checkout is protected')
    if within(os.getcwd(), path) or within(os.sys.prefix, path):
        raise SafetyError('Current checkout or interpreter environment is protected')
    if row.get('locked') or row.get('prunable'):
        raise SafetyError('Locked or missing/prunable worktree requires manual Git handling')
    head = row.get('HEAD')
    if not isinstance(head, str) or not re.fullmatch(r'[0-9a-f]{40,64}', head):
        raise SafetyError('Worktree HEAD is unknown')
    admin = _admin(path, common, expected.get('admin_dir') if expected else None)
    if expected and (head != expected['head'] or [os.lstat(admin).st_dev, os.lstat(admin).st_ino] != expected['admin_identity']):
        raise SafetyError('Worktree HEAD or registry identity changed')
    blockers = process.blockers(path) + process.blockers(common)
    if blockers:
        raise SafetyError('; '.join(blockers))
    bound_checkout(path, common, admin)
    meaningful_contents(path)
    proof = merge_proof(common, head, config)
    if expected and proof['default_ref'] != expected['default_ref']:
        raise SafetyError('Resolved default target changed')
    fp = worktree_fingerprint(path, config, relocated, cancel)
    common_id, common_ancestors = common_identity(common)
    context = dict(proof, common_dir=str(common), common_identity=common_id, common_ancestors=common_ancestors, admin_dir=str(admin), admin_identity=[os.lstat(admin).st_dev, os.lstat(admin).st_ino],
                   primary=rows[0]['worktree'], repo=str(path), head=head, branch=row.get('branch', 'detached'),
                   gitfile_sha256=file_hash(path / '.git'))
    return fp, context


def discover(roots, config, state, process, progress=None, cancel=None):
    from .scanner import candidate
    items, coverage = [], []
    commons = {}
    for root in roots:
        root = canonical(root)
        used, issues = 0, []
        limit = min(config['max_files'], config['budgets']['worktrees'])
        def walk(path, level):
            nonlocal used
            if cancel is not None and cancel.is_set():
                raise SafetyError('Worktree discovery cancelled')
            used += 1
            if used > limit or level > config['discovery_depth']:
                raise SafetyError('Worktree discovery budget/depth exhausted')
            ancestor_identity(path)
            if (path / '.git').exists():
                common = common_dir(path)
                commons[str(common)] = common
                return
            with os.scandir(path) as stream:
                for entry in stream:
                    used += 1
                    if used > limit:
                        raise SafetyError('Worktree discovery budget exhausted')
                    if entry.is_dir(follow_symlinks=False) and entry.name not in {'.git', '.venv', 'node_modules', '__pycache__'}:
                        walk(Path(entry.path), level + 1)
        if root.exists():
            try:
                walk(root, 0)
            except (OSError, SafetyError) as exc:
                issues.append(clean(exc))
        coverage.append({'category': 'worktrees', 'root': str(root), 'status': 'partial' if issues else 'measured' if root.exists() else 'absent', 'entries': used, 'limit': limit, 'issues': issues})
    for common in commons.values():
        try:
            rows = registrations(common)
        except SafetyError as exc:
            coverage.append({'category': 'worktrees', 'root': str(common), 'status': 'unknown', 'issues': [clean(exc)]})
            continue
        for row in rows:
            path = canonical(row['worktree'])
            measured = measure(path, min(config['max_files'], config['budgets']['worktrees']), config['max_depth'], cancel=cancel)
            context = {'common_dir': str(common), 'primary': rows[0]['worktree'], 'repo': str(path), 'head': row.get('HEAD', 'unknown'), 'branch': row.get('branch', 'detached')}
            evidence = ['Registered Git worktree', 'Branch: ' + clean(context['branch']), 'HEAD: ' + str(context['head'])]
            blockers = []
            fp = measured.summary()
            try:
                fp, context = policy(path, config, state, process, cancel=cancel)
                evidence += ['HEAD incorporated into ' + context['default_ref'], context['target_source'], 'Merge proof: ' + context['merge_proof']['type'], 'Clean source/index; no meaningful ignored data; no observed use']
            except (OSError, SafetyError, subprocess.TimeoutExpired) as exc:
                blockers.append(clean(exc))
            if measured.status not in {'measured', 'partial'}:
                blockers.append('Worktree measurement is ' + measured.status)
            item = candidate(path, 'git-worktree', context, fp, evidence, blockers, 'Git-aware quarantine preserves registry; restore moves it back; separate purge removes only this registration, never its branch')
            items.append(item)
            if progress:
                progress(item)
    return items, coverage


def _sync(record, location, state):
    admin = canonical(record['candidate']['context']['admin_dir'])
    common = canonical(record['candidate']['context']['common_dir'])
    paths = [admin / 'gitdir', admin / 'HEAD', admin / 'commondir', Path(location) / '.git']
    reference = common / record['recovery_ref']
    if reference.exists():
        paths.append(reference)
    for path in paths:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    for parent in {admin, canonical(record['original']).parent, state.path / 'quarantine', Path(location), reference.parent}:
        if parent.exists():
            fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)


def _registry_at(record, location):
    context = record['candidate']['context']
    common = bound_common(context)
    if record.get('pointer_transition') and record['pointer_transition']['location'] == str(location):
        scoped_repair(record, location)
    admin = _admin(location, common, context['admin_dir'])
    if [os.lstat(admin).st_dev, os.lstat(admin).st_ino] != context['admin_identity']:
        raise SafetyError('Git registry identity changed during recovery')
    with open(admin / 'gitdir', 'r', encoding='utf-8', errors='surrogateescape') as stream:
        linked = stream.read(4096).strip()
    allowed = {str(Path(record['original']) / '.git'), str(Path(record['quarantine']) / '.git')}
    if linked not in allowed:
        raise SafetyError('Registry pointer is outside this signed lifecycle')
    rows = registrations(common)
    row = next((row for row in rows if canonical(row['worktree']) == canonical(location)), None)
    if not row:
        # Precise crash reconciliation: repair only this signed existing worktree,
        # with the exact admin inode and either original/quarantine pointer.
        scoped_repair(record, location)
        rows = registrations(common)
        row = next((row for row in rows if canonical(row['worktree']) == canonical(location)), None)
    if not row or row.get('HEAD') != context['head'] or row.get('locked'):
        raise SafetyError('Git registry cannot be safely reconciled')
    return common


def admin_snapshot(record, state, phase):
    """Durable private recovery copy of ONLY the captured linked registry."""
    context = record['candidate']['context']
    bound_common(context)
    admin = canonical(context['admin_dir'])
    ancestor_identity(admin)
    if [os.lstat(admin).st_dev, os.lstat(admin).st_ino] != context['admin_identity']:
        raise SafetyError('Administrative registration was replaced')
    before = fingerprint(admin, Budget(10000, 24), inspect_protected=False)
    recovery = state.path / 'admin-recovery'
    if not recovery.exists():
        with directory_fd(state.path) as fd:
            os.mkdir('admin-recovery', 0o700, dir_fd=fd)
            os.fsync(fd)
    state._private(recovery, True)
    slot = recovery / (record['id'] + '-' + phase)
    if os.path.lexists(slot):
        raise SafetyError('Administrative recovery snapshot slot already exists')
    with directory_fd(recovery) as fd:
        os.mkdir(slot.name, 0o700, dir_fd=fd)
        os.fsync(fd)
    total, hashes = 0, {}
    for relative, metadata, *tail in before['records']:
        if not relative:
            continue
        source, target = admin / relative, slot / relative
        if metadata[2] == stat.S_IFDIR:
            target.mkdir(mode=0o700)
            continue
        total += metadata[6]
        if total > 64 * 1024 * 1024:
            raise SafetyError('Administrative snapshot exceeds 64 MiB; manual Git lifecycle required')
        with directory_fd(source.parent) as source_fd, directory_fd(target.parent) as target_fd:
            input_fd = os.open(source.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=source_fd)
            output_fd = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=target_fd)
            sha = hashlib.sha256()
            try:
                while True:
                    block = os.read(input_fd, 1024 * 1024)
                    if not block:
                        break
                    sha.update(block)
                    offset = 0
                    while offset < len(block):
                        offset += os.write(output_fd, block[offset:])
                os.fsync(output_fd)
                os.fsync(target_fd)
            finally:
                os.close(input_fd)
                os.close(output_fd)
            hashes[relative] = sha.hexdigest()
    if fingerprint(admin, Budget(10000, 24), inspect_protected=False)['digest'] != before['digest']:
        raise SafetyError('Administrative registry changed while copying recovery snapshot')
    for relative, expected in hashes.items():
        if file_hash(admin / relative) != expected or file_hash(slot / relative) != expected:
            raise SafetyError('Administrative recovery copy does not match original bytes')
    for directory in sorted([slot] + [slot / entry[0] for entry in before['records'] if entry[0] and entry[1][2] == stat.S_IFDIR], key=lambda path: len(path.parts), reverse=True):
        with directory_fd(directory) as fd:
            os.fsync(fd)
    saved = {'phase': phase, 'path': str(slot), 'original': before, 'copy': fingerprint(slot, Budget(10000, 24), inspect_protected=False), 'sha256': hashes}
    record.setdefault('admin_snapshots', []).append(saved)
    state.write_journal(record)  # size bound checked BEFORE any source rename/delete
    return saved


def verify_snapshot(saved, state, record):
    expected = state.path / 'admin-recovery' / (record['id'] + '-' + saved['phase'])
    if canonical(saved['path']) != expected:
        raise SafetyError('Administrative recovery snapshot escaped owned state')
    state._private(expected, True)
    if fingerprint(expected, Budget(10000, 24), inspect_protected=False)['digest'] != saved['copy']['digest']:
        raise SafetyError('Administrative recovery snapshot changed')
    for relative, sha in saved['sha256'].items():
        if file_hash(expected / relative) != sha:
            raise SafetyError('Administrative recovery snapshot bytes changed')


def _other_registries(common, excluded):
    parent = common / 'worktrees'
    result = {}
    if parent.exists():
        with os.scandir(parent) as stream:
            for index, entry in enumerate(stream):
                if index >= 10000:
                    raise SafetyError('Registration guard budget exhausted')
                path = Path(entry.path)
                if path == excluded:
                    continue
                ancestor_identity(path)
                result[str(path)] = {'identity': [os.lstat(path).st_dev, os.lstat(path).st_ino],
                                     'pointers': {name: file_hash(path / name) for name in ('gitdir', 'HEAD', 'commondir')}}
    return result


def validate_move_admin(record):
    saved = record.get('admin_snapshots', [])
    if not saved:
        raise SafetyError('Missing durable administrative move snapshot')
    saved = saved[-1]
    admin = canonical(record['candidate']['context']['admin_dir'])
    expected = {entry[0]: entry[1:] for entry in saved['original']['records']}
    current = fingerprint(admin, Budget(10000, 24), inspect_protected=False)
    if {entry[0] for entry in current['records']} != set(expected):
        raise SafetyError('Administrative entries changed during move')
    for relative, metadata, *tail in current['records']:
        before, *old_tail = expected[relative]
        if relative == 'gitdir' and record.get('pointer_transition') and record['pointer_transition']['phase'] == 'installed':
            if fingerprint(admin / 'gitdir', inspect_protected=False)['digest'] != record['pointer_transition']['new']['digest']:
                raise SafetyError('Journaled replacement pointer changed')
        elif relative in {'', 'gitdir'}:
            if metadata[:6] != before[:6] or metadata[9] != before[9]:
                raise SafetyError('Administrative move pointer/directory identity changed')
        elif metadata != before or tail != old_tail:
            raise SafetyError('Administrative file changed during move')
    with open(admin / 'gitdir', encoding='utf-8', errors='surrogateescape') as stream:
        value = stream.read(4097).strip()
    if value not in {str(Path(record['original']) / '.git'), str(Path(record['quarantine']) / '.git')}:
        raise SafetyError('Administrative move back-pointer escaped signed paths')


def scoped_repair(record, location):
    """Exact pointer transition, never Git's common-registry repair traversal.

    An exclusive rename captures the displaced back-pointer in private state.
    It is verified before a separately fsynced replacement enters the absent
    slot. A raced-in replacement remains intact; both displaced bytes and the
    prepared replacement remain available for manual recovery.
    """
    context = record['candidate']['context']
    common, admin = bound_common(context), canonical(context['admin_dir'])
    expected_value = (str(Path(location) / '.git') + '\n').encode(errors='surrogateescape')
    before_others = _other_registries(common, admin)
    # Already repaired is accepted only with exact journaled replacement bytes.
    transition = record.get('pointer_transition')
    if transition and transition['location'] == str(location):
        backup, replacement = canonical(transition['backup']), canonical(transition['replacement'])
    else:
        validate_move_admin(record)
        with open(admin / 'gitdir', 'rb') as stream:
            if stream.read(4097) == expected_value:
                return
        state_path = canonical(record['quarantine']).parent.parent
        private = state_path / 'admin-recovery'
        phase = 'restore' if canonical(location) == canonical(record['original']) else 'apply'
        backup = private / (record['id'] + '-' + phase + '-gitdir-old')
        replacement = private / (record['id'] + '-' + phase + '-gitdir-new')
        with directory_fd(private) as fd:
            output = os.open(replacement.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                os.write(output, expected_value)
                os.fsync(output)
            finally:
                os.close(output)
            os.fsync(fd)
        transition = {'location': str(location), 'backup': str(backup), 'replacement': str(replacement),
                      'old': fingerprint(admin / 'gitdir', inspect_protected=False),
                      'new': fingerprint(replacement, inspect_protected=False), 'phase': 'prepared'}
        record['pointer_transition'] = transition
        from .state import State
        state = State(state_path).prepare()
        state.write_journal(record)
    state_path = canonical(record['quarantine']).parent.parent
    from .state import State
    state = State(state_path).prepare()
    expected_private = state.path / 'admin-recovery'
    if backup.parent != expected_private or replacement.parent != expected_private or backup.name != record['id'] + ('-restore' if canonical(location) == canonical(record['original']) else '-apply') + '-gitdir-old':
        raise SafetyError('Pointer recovery paths escaped signed private slots')
    state._private(expected_private, True)
    if not os.path.lexists(backup):
        validate_move_admin(record)
        with directory_fd(admin) as admin_fd, directory_fd(expected_private) as private_fd:
            if fingerprint(admin / 'gitdir', inspect_protected=False)['digest'] != transition['old']['digest']:
                raise SafetyError('Captured back-pointer changed before replacement')
            rename_exclusive(admin_fd, 'gitdir', private_fd, backup.name)
        if fingerprint(backup, inspect_protected=False)['digest'] != transition['old']['digest']:
            # Preserve any raced-in bytes, restoring only to a still absent slot.
            with directory_fd(expected_private) as private_fd, directory_fd(admin) as admin_fd:
                if not os.path.lexists(admin / 'gitdir'):
                    rename_exclusive(private_fd, backup.name, admin_fd, 'gitdir')
            raise SafetyError('Displaced back-pointer changed; unique bytes retained')
        transition['phase'] = 'old-captured'
        state.write_journal(record)
    elif fingerprint(backup, inspect_protected=False)['digest'] != transition['old']['digest']:
        raise SafetyError('Captured pointer recovery bytes changed')
    pointer = admin / 'gitdir'
    if os.path.lexists(pointer):
        if fingerprint(pointer, inspect_protected=False)['digest'] != transition['new']['digest']:
            raise SafetyError('New or changed back-pointer retained; replacement refused')
    else:
        if fingerprint(replacement, inspect_protected=False)['digest'] != transition['new']['digest']:
            raise SafetyError('Prepared back-pointer replacement changed')
        with directory_fd(expected_private) as private_fd, directory_fd(admin) as admin_fd:
            rename_exclusive(private_fd, replacement.name, admin_fd, 'gitdir')
    transition['phase'] = 'installed'
    state.write_journal(record)
    if _other_registries(common, admin) != before_others:
        raise SafetyError('Unrelated registration changed concurrently; retained for inspection')


def move(record, state, restore=False, process=None):
    context = record['candidate']['context']
    common = bound_common(context)
    source = canonical(record['quarantine'] if restore else record['original'])
    target = canonical(record['original'] if restore else record['quarantine'])
    if process is None or not process.complete:
        raise SafetyError('Fresh complete activity is required for worktree move/restore')
    blockers = process.blockers(source) + process.blockers(target) + process.blockers(common) + process.blockers(context['admin_dir'])
    if blockers:
        raise SafetyError('; '.join(blockers))
    if os.path.lexists(target):
        raise SafetyError('Git worktree move destination exists; no overwrite')
    _registry_at(record, source)
    raw_pointer = (source / '.git').read_bytes()
    value = raw_pointer[8:].decode(errors='surrogateescape').strip()
    if file_hash(source / '.git') != context['gitfile_sha256'] or canonical(value if Path(value).is_absolute() else target / value) != canonical(context['admin_dir']):
        raise SafetyError('Worktree Git pointer cannot retain exact captured admin after relocation')
    saved = admin_snapshot(record, state, 'restore' if restore else 'apply')
    record.pop('pointer_transition', None)
    if not restore:
        record['recovery_ref'] = 'refs/mactrim/recovery/' + record['id']
        command(common, 'update-ref', record['recovery_ref'], context['head'], '0' * len(context['head']), git_dir=True)
    elif not record.get('recovery_ref'):
        raise SafetyError('Git recovery reference is missing')
    record['git_phase'] = 'exclusive-rename-authorized'
    state.write_journal(record)
    source_ancestors, target_ancestors = ancestor_identity(source.parent), ancestor_identity(target.parent)
    with directory_fd(source.parent) as source_fd, directory_fd(target.parent) as target_fd:
        if os.fstat(source_fd).st_dev != os.fstat(target_fd).st_dev:
            raise SafetyError('Cross-volume Git worktree move is refused')
        if ancestor_identity(source.parent) != source_ancestors or ancestor_identity(target.parent) != target_ancestors:
            raise SafetyError('Git worktree move ancestor changed')
        if worktree_fingerprint(source, record['config'], restore)['digest'] != record['fingerprint']['digest']:
            raise SafetyError('Worktree contents changed at move boundary')
        if fingerprint(context['admin_dir'], Budget(10000, 24), inspect_protected=False)['digest'] != saved['original']['digest']:
            raise SafetyError('Administrative registration changed before move')
        rename_exclusive(source_fd, source.name, target_fd, target.name)
    record['git_phase'] = 'renamed-awaiting-repair'
    state.write_journal(record)
    scoped_repair(record, target)
    _registry_at(record, target)
    _sync(record, target, state)
    record['git_phase'] = 'registration-repaired'
    state.write_journal(record)


def _recovery_ref(record):
    common = bound_common(record['candidate']['context'])
    if not record.get('recovery_ref') or command(common, 'rev-parse', record['recovery_ref'], git_dir=True).stdout.decode().strip() != record['candidate']['context']['head']:
        raise SafetyError('Exact Git recovery reference is missing or altered')
    return common


def _admin_subset(record, saved):
    admin = canonical(record['candidate']['context']['admin_dir'])
    ancestor_identity(admin.parent)
    current = fingerprint(admin, Budget(10000, 24), inspect_protected=False)
    expected = {entry[0]: entry[1:] for entry in saved['original']['records']}
    for relative, metadata, *tail in current['records']:
        previous = expected.get(relative)
        if previous is None:
            raise SafetyError('Unexpected administrative descendant; registration retained')
        before, *before_tail = previous
        if metadata[2] == stat.S_IFDIR:
            if metadata[:6] != before[:6] or metadata[9] > before[9]:
                raise SafetyError('Administrative directory replaced')
        elif metadata != before or tail != before_tail:
            raise SafetyError('Administrative file changed; registration retained')
    return current


def finish_registration(record, state, process):
    # Never ask Git to recursively remove a possibly recreated checkout path.
    context = record['candidate']['context']
    common, admin, path = bound_common(context), canonical(context['admin_dir']), canonical(record['quarantine'])
    if os.path.lexists(path):
        raise SafetyError('Quarantine path reappeared; administrative removal refused')
    if record.get('git_phase') not in {'content-purged', 'admin-deleting', 'registration-purged'} or not record.get('purge_approval'):
        raise SafetyError('No durable content/registration purge authorization')
    _recovery_ref(record)
    blockers = process.blockers(path) + process.blockers(admin) + process.blockers(common)
    if blockers:
        raise SafetyError('; '.join(blockers))
    saved = next((item for item in reversed(record.get('admin_snapshots', [])) if item['phase'] == 'purge'), None)
    if saved is None:
        raise SafetyError('No durable administrative recovery snapshot')
    verify_snapshot(saved, state, record)
    if record.get('git_phase') == 'registration-purged':
        if os.path.lexists(admin):
            raise SafetyError('Purged administrative path reappeared')
        return
    if os.path.lexists(admin):
        if record.get('git_phase') != 'admin-deleting':
            if fingerprint(admin, Budget(10000, 24), inspect_protected=False)['digest'] != saved['original']['digest']:
                raise SafetyError('Administrative registration changed before deletion')
            with open(admin / 'gitdir', encoding='utf-8', errors='surrogateescape') as stream:
                if stream.read(4097).strip() != str(path / '.git'):
                    raise SafetyError('Administrative gitdir no longer names exact quarantine')
            with open(admin / 'HEAD', encoding='utf-8', errors='surrogateescape') as stream:
                value = stream.read(4097).strip()
            branch = context['branch']
            if value != ('ref: ' + branch if branch != 'detached' else context['head']):
                raise SafetyError('Administrative HEAD/branch changed')
        else:
            _admin_subset(record, saved)
        record['git_phase'] = 'admin-deleting'
        state.write_journal(record)
        with directory_fd(admin.parent) as fd:
            remove_tree_fd(fd, admin.name, saved['original']['records'])
    elif record.get('git_phase') != 'admin-deleting':
        raise SafetyError('Registration absent without durable deletion intent')
    if any(canonical(row['worktree']) == path for row in registrations(common)):
        raise SafetyError('Exact registration remains after removal')
    record['git_phase'] = 'registration-purged'
    state.write_journal(record)


def reconcile(record, state, process):
    original, target = canonical(record['original']), canonical(record['quarantine'])
    exists_original, exists_target = os.path.lexists(original), os.path.lexists(target)
    if record['status'] == 'purging':
        if not exists_target:
            finish_registration(record, state, process)
            record['status'] = 'purged'
        return  # existing contents need a fresh second approval, never automatic deletion
    if exists_original == exists_target:
        raise SafetyError('Ambiguous worktree lifecycle paths; neither repair nor removal is inferred')
    location = original if exists_original else target
    blockers = process.blockers(location) + process.blockers(record['candidate']['context']['admin_dir']) + process.blockers(record['candidate']['context']['common_dir'])
    if blockers:
        raise SafetyError('; '.join(blockers))
    saved = record.get('admin_snapshots', [])
    if saved:
        verify_snapshot(saved[-1], state, record)
    fp = worktree_fingerprint(location, record['config'], not exists_original)
    if fp['digest'] != record['fingerprint']['digest']:
        raise SafetyError('Interrupted worktree contents changed; retain for manual recovery')
    _registry_at(record, location)
    _sync(record, location, state) if record.get('recovery_ref') else None
    record['status'] = ('restored' if record['status'] == 'restoring' else 'aborted') if exists_original else 'quarantined'


def purge(record, state, process):
    context = record['candidate']['context']
    path = canonical(record['quarantine'])
    common = _recovery_ref(record)
    saved = next((item for item in reversed(record.get('admin_snapshots', [])) if item['phase'] == 'purge'), None)
    if saved and record.get('git_phase') == 'content-purge-authorized':
        # Interrupted approved content purge: tracked-file absence is expected.
        # Executor independently verified the surviving subset. Fresh Git proof,
        # exact admin snapshot and activity still apply before continuing.
        verify_snapshot(saved, state, record)
        if fingerprint(context['admin_dir'], Budget(10000, 24), inspect_protected=False)['digest'] != saved['original']['digest']:
            raise SafetyError('Administrative registration changed during interrupted content purge')
        row = next((row for row in registrations(common) if canonical(row['worktree']) == path), None)
        if not row or row.get('HEAD') != context['head'] or row.get('locked'):
            raise SafetyError('Interrupted worktree registry/HEAD changed')
        merge_proof(common, context['head'], record['config'])
        pointer = [record['git_pointer_record']]
    else:
        _registry_at(record, path)
        fp, current = policy(path, record['config'], state.path, process, context, relocated=True)
        if fp['digest'] != record['fingerprint']['digest']:
            raise SafetyError('Quarantined worktree changed; purge refused')
        saved = admin_snapshot(record, state, 'purge')
        full = fingerprint(path, Budget(record['config']['max_files'], record['config']['max_depth']), inspect_protected=False, normalize_root=True)
        pointer = [entry for entry in full['records'] if entry[0] == '.git']
        if len(pointer) != 1 or any(entry[0].startswith('.git/') for entry in full['records']):
            raise SafetyError('Worktree Git pointer changed shape')
        record['git_pointer_record'] = pointer[0]
        record['git_phase'] = 'content-purge-authorized'
        state.write_journal(record)
    blockers = process.blockers(context['admin_dir']) + process.blockers(common)
    if blockers:
        raise SafetyError('; '.join(blockers))
    with directory_fd(path.parent) as fd:
        remove_tree_fd(fd, path.name, record['fingerprint']['records'] + pointer)
    record['git_phase'] = 'content-purged'
    state.write_journal(record)
    finish_registration(record, state, process)
