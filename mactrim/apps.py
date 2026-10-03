"""App ownership evidence: absence is a hypothesis, never deletion authority."""
import os
from pathlib import Path
import plistlib
import re
import subprocess
import time
from xml.parsers.expat import ExpatError

from .measurement import measure
from .safety import Budget, SafetyError, ancestor_identity, canonical, clean, fingerprint, protected, within


def services():
    try:
        result = subprocess.run(['/bin/launchctl', 'list'], capture_output=True, timeout=10)
        if result.returncode or result.stderr or len(result.stdout) > 4 * 1024 * 1024:
            raise SafetyError('Service ownership inventory unavailable')
        labels = set()
        for line in result.stdout.decode(errors='replace').splitlines()[1:]:
            fields = line.split(None, 2)
            if len(fields) != 3:
                raise SafetyError('Service ownership inventory malformed')
            labels.add(fields[2])
        return labels, []
    except (OSError, SafetyError, subprocess.TimeoutExpired) as exc:
        return set(), [clean(exc)]


def inventory(config, cancel=None):
    bundles, aliases, issues, coverage = {}, {}, [], []
    if not config['app_roots']:
        issues.append('No installed-app inventory roots configured')
    limit = min(config['max_files'], config['budgets']['apps'])
    for root in config['app_roots']:
        root = canonical(root)
        used = 0
        root_issues = []
        def inspect(path, depth, parent_owner=None):
            nonlocal used
            if cancel is not None and cancel.is_set():
                raise SafetyError('App inventory cancelled')
            used += 1
            if used > limit or depth > config['max_depth']:
                raise SafetyError('App inventory budget/depth exhausted')
            ancestor_identity(path)
            if path.suffix.lower() in {'.app', '.appex', '.xpc', '.bundle'}:
                info = path / 'Contents' / 'Info.plist'
                if not info.exists():
                    info = path / 'Info.plist'
                if info.is_symlink() or not info.is_file():
                    raise SafetyError('Bundle identity metadata unavailable: ' + clean(path))
                with open(info, 'rb') as stream:
                    data = plistlib.load(stream)
                if not isinstance(data, dict):
                    raise SafetyError('Bundle identity plist must be a dictionary: ' + clean(path))
                identifier = data.get('CFBundleIdentifier')
                if not isinstance(identifier, str):
                    raise SafetyError('Bundle ID unavailable: ' + clean(path))
                name = str(data.get('CFBundleDisplayName', data.get('CFBundleName', path.stem)))
                version = str(data.get('CFBundleShortVersionString', data.get('CFBundleVersion', 'unknown')))
                bundles.setdefault(identifier, []).append({'path': str(path), 'name': name, 'version': version, 'helper_of': parent_owner})
                aliases.setdefault(name, set()).add(identifier)
                aliases.setdefault(path.stem, set()).add(identifier)
                # Helpers/extensions retain ownership even if their parent has
                # moved or uses a separate bundle ID.
                for relative in ('Contents/Library/LoginItems', 'Contents/PlugIns', 'Contents/XPCServices', 'Contents/Helpers'):
                    directory = path / relative
                    if directory.exists():
                        inspect(directory, depth + 1, identifier)
                return
            with os.scandir(path) as stream:
                for entry in stream:
                    used += 1
                    if used > limit:
                        raise SafetyError('App inventory budget exhausted')
                    if entry.is_symlink():
                        if entry.name.endswith(('.app', '.appex', '.xpc')):
                            root_issues.append('Symlink bundle identity uncertain: ' + clean(entry.path))
                        continue
                    if entry.is_dir(follow_symlinks=False):
                        inspect(Path(entry.path), depth + 1, parent_owner)
        if root.exists():
            try:
                inspect(root, 0)
            except (OSError, ValueError, SafetyError, ExpatError, plistlib.InvalidFileException) as exc:
                root_issues.append(clean(exc))
        else:
            root_issues.append('Inventory root absent: ' + clean(root))
        issues.extend(root_issues)
        coverage.append({'category': 'apps', 'root': str(root), 'status': 'partial' if root_issues else 'measured', 'entries': used, 'limit': limit, 'issues': root_issues})
    for name, bundle in config.get('app_aliases', {}).items():
        aliases.setdefault(name, set()).add(bundle)
    for bundle, declaration in config.get('retired_apps', {}).items():
        for name in declaration['aliases']:
            aliases.setdefault(name, set()).add(bundle)
    labels, service_issues = services()
    issues.extend(service_issues)
    return {'bundles': bundles, 'aliases': aliases, 'services': labels, 'issues': issues, 'complete': not issues, 'coverage': coverage}


def owner_for(path, owners):
    name = canonical(path).name
    stripped = re.sub(r'\.(plist|savedState)$', '', name, flags=re.IGNORECASE)
    if re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2,}', stripped):
        return stripped, 'Exact bundle-ID filename'
    matches = owners['aliases'].get(stripped, set())
    if len(matches) == 1:
        return next(iter(matches)), 'Observed bundle name / explicit historical owner alias'
    return None, 'Unknown or shared human folder alias'


def service_owner(label):
    # macOS application.<bundle-id>.<instance> labels retain app ownership.
    value = label.removeprefix('application.')
    if label.startswith('application.'):
        parts = value.split('.')
        while parts and parts[-1].isdigit():
            parts.pop()
        value = '.'.join(parts)
    return value


def ownership(bundle, owners, process):
    if bundle.startswith('com.apple.') or bundle.startswith('system.'):
        return 'system', ['Apple/system ownership; absence is not an uninstall signal']
    if bundle in owners['bundles']:
        return 'installed', ['Installed app/helper/extension owns this exact bundle ID']
    family = bundle.rsplit('.', 1)[0]
    relatives = [identifier for identifier in owners['bundles'] if identifier.startswith(bundle + '.') or bundle.startswith(identifier + '.') or identifier.rsplit('.', 1)[0] == family]
    if relatives:
        return 'shared', ['Installed helper/vendor family remains: ' + ', '.join(sorted(relatives)[:8])]
    related = lambda identifier: identifier == bundle or identifier.startswith(bundle + '.') or identifier.rsplit('.', 1)[0] == family
    if any(related(service_owner(label)) for label in owners['services']):
        return 'running', ['Relevant launch service retains ownership']
    if any(any(related(identifier) for identifier in re.findall(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2,}', command)) for command in process.commands.values()):
        return 'running', ['Live process argv references this owner; command details are not exported']
    if not owners['complete']:
        return 'uncertain', ['Incomplete app/helper/service inventory; owner absence is unknown']
    if any(bundle in owners['aliases'].get(alias, set()) and any(('/' + alias + '.app/') in command or ('/' + alias + '/') in command for command in process.commands.values()) for alias in owners['aliases']):
        return 'running', ['Live process uses an observed or explicitly mapped owner alias']
    if any(label.startswith('application.') and not re.fullmatch(r'[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2,}', service_owner(label)) for label in owners['services']):
        return 'uncertain', ['Unresolved running application service ownership']
    return 'likely-retired', ['No exact owner/helper/service found in bounded inventory; external apps/plugins remain possible']


def confirmed_owner(path, bundle, config, state, process, owners=None):
    path = canonical(path)
    owners = owners or inventory(config)
    detected, _ = owner_for(path, owners)
    declaration = config['retired_apps'].get(bundle, {})
    if detected != bundle or not declaration.get('confirmed') or str(path) not in declaration.get('paths', []):
        raise SafetyError('Retired owner and this exact scope have not been explicitly confirmed')
    roots = [canonical(root) for root in config['app_data_roots'] if path.parent == canonical(root)]
    if not roots:
        raise SafetyError('App item is outside its exact app data record root')
    owner_state, reasons = ownership(bundle, owners, process)
    if owner_state != 'likely-retired':
        raise SafetyError('; '.join(reasons))
    if roots[0].name.lower() not in {'caches', 'preferences', 'application support', 'logs', 'saved application state', 'containers'}:
        raise SafetyError('App record root role is unknown')
    reason = protected(path, state, allow_app_data=True)
    if reason:
        raise SafetyError(reason)
    blockers = process.blockers(path)
    if blockers:
        raise SafetyError('; '.join(blockers))
    return roots[0]


def policy(path, bundle, config, state, process, owners=None, cancel=None):
    path = canonical(path)
    root = confirmed_owner(path, bundle, config, state, process, owners)
    fp = fingerprint(path, Budget(config['max_files'], config['max_depth'], cancel), state=state, allow_app_data=True)
    if root.name.lower() == 'caches' and fp['newest_ns'] / 1e9 > time.time() - config['cache_days'] * 86400:
        raise SafetyError('Owned cache is recent; no stale regeneration evidence')
    fp["allow_app_data"] = True
    return fp


def detect(config, state, process, cancel=None, progress=None):
    from .scanner import candidate
    owners = inventory(config, cancel)
    items, coverage = [], list(owners['coverage'])
    budget = min(config['max_files'], config['budgets']['apps'])
    for root in config['app_data_roots']:
        root = canonical(root)
        issues, used = [], 0
        if not root.exists():
            coverage.append({'category': 'apps', 'root': str(root), 'status': 'absent', 'issues': []})
            continue
        try:
            ancestor_identity(root)
            with os.scandir(root) as stream:
                for entry in stream:
                    used += 1
                    if used > budget or cancel is not None and cancel.is_set():
                        raise SafetyError('App records budget exhausted or cancelled')
                    path = Path(entry.path)
                    if entry.is_symlink():
                        continue
                    bundle, provenance = owner_for(path, owners)
                    if bundle is None:
                        continue
                    owner_state, evidence = ownership(bundle, owners, process)
                    if owner_state in {'system', 'installed', 'running'}:
                        continue  # retain owners; do not call normal records remnants
                    size = measure(path, budget, config['max_depth'], cancel=cancel).summary()
                    context = {'bundle_id': bundle, 'owner_status': owner_state, 'inventory_complete': owners['complete'], 'record_root': str(root), 'role': root.name}
                    blockers = ['Owner absence alone is insufficient; confirm retired owner and exact scope, or review manually']
                    kind = 'app-leftover' if owner_state == 'likely-retired' else 'possible-remnant'
                    try:
                        size = policy(path, bundle, config, state, process, owners, cancel=cancel)
                        blockers = []
                        kind = 'retired-app-data'
                        evidence.append('Explicit confirmed retired owner and exact scope')
                    except (OSError, SafetyError) as exc:
                        blockers.append(clean(exc))
                    item = candidate(path, kind, context, size, [provenance] + evidence, blockers, 'Prefer app uninstaller; preferences/support may be unique data. Cache quarantine frees zero bytes.')
                    items.append(item)
                    if progress:
                        progress(item)
        except (OSError, SafetyError) as exc:
            issues.append(clean(exc))
        coverage.append({'category': 'apps', 'root': str(root), 'status': 'partial' if issues else 'measured', 'entries': used, 'limit': budget, 'issues': issues})
    for bundle, copies in owners['bundles'].items():
        if len(copies) < 2 or bundle.startswith('com.apple.'):
            continue
        numeric = [tuple(int(part) for part in item['version'].split('.')) if re.fullmatch(r'\d+(?:\.\d+)*', item['version']) else None for item in copies]
        width = max((len(value) for value in numeric if value), default=0)
        versions = [value + (0,) * (width - len(value)) if value else None for value in numeric]
        highest = max((value for value in versions if value), default=None)
        for item, version in zip(copies, versions):
            older = version is not None and highest is not None and version < highest
            kind = 'older-app' if older else 'duplicate-app'
            measured = measure(item['path'], budget, config['max_depth'], cancel=cancel).summary()
            report = candidate(item['path'], kind, {'bundle_id': bundle, 'copies': copies}, measured,
                               ['Bundle ID ' + bundle, 'Observed version ' + item['version']],
                               ['App removal is manual; ' + ('numeric version is older' if older else 'equal/unknown version does not establish an older app')], 'Review compatibility and use Finder/app uninstaller')
            items.append(report)
            if progress:
                progress(report)
    return items, owners, coverage
