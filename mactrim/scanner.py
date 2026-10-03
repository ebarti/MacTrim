"""Bounded provenance discovery. Everything uncertain remains report-only."""
import hashlib
import os
from pathlib import Path
import plistlib
import re
import stat
import subprocess
import time

from . import activity
from .config import validate
from .safety import (Budget, SafetyError, ancestor_identity, canonical, clean, digest,
                     file_hash, fingerprint, overlap, protected, within)
from .state import SCHEMA

REPO_ARTIFACTS = {".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache", "node_modules"}
PYTHON_SPECS = ("pyproject.toml", "requirements.txt", "Pipfile", "poetry.lock", "uv.lock", "setup.py", "setup.cfg")
NODE_LOCKS = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json")
USER_CACHES = {"pip": "python -m pip cache purge", "uv": "uv cache clean", "npm": "npm cache clean --force"}
REPORT_NAMES = {"reports", "screenshots", "logs", "test-results", "coverage", ".coverage", "htmlcov", "dist", "data", "tmp"}


def git(repo, *arguments):
    env = os.environ.copy()
    env.update({"GIT_OPTIONAL_LOCKS": "0", "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
                "GIT_TERMINAL_PROMPT": "0"})
    # Disable project fsmonitor commands. Built-in reads only; no project scripts.
    result = subprocess.run(["/usr/bin/git", "--no-optional-locks", "-c", "core.fsmonitor=false",
                             "-c", "core.untrackedCache=false", "-C", str(repo)] + list(arguments),
                            capture_output=True, env=env, timeout=20)
    if result.returncode or len(result.stdout) > 16 * 1024 * 1024 or result.stderr:
        raise SafetyError("Git evidence unavailable: %s" % clean(result.stderr.decode(errors="replace")[:300]))
    return result.stdout


def git_evidence(repo, path):
    repo, path = canonical(repo), canonical(path)
    relative = path.relative_to(repo).as_posix()
    # NUL paths, no pathspec magic from adversarial filenames.
    tracked = git(repo, "ls-files", "-z", "--", ":(literal)" + relative)
    if tracked:
        raise SafetyError("Artifact contains tracked data")
    # check-ignore status 1 is meaningful and is handled without git()'s status requirement.
    result = subprocess.run(["/usr/bin/git", "--no-optional-locks", "-c", "core.fsmonitor=false", "-C", str(repo),
                             "check-ignore", "-q", "--", relative], capture_output=True, timeout=15,
                            env=dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull))
    if result.returncode != 0 or result.stderr:
        raise SafetyError("Artifact is not proven Git-ignored")
    top = git(repo, "rev-parse", "--show-toplevel").decode(errors="surrogateescape").strip()
    if canonical(top) != repo:
        raise SafetyError("Repository boundary changed")
    reflog = git(repo, "reflog", "--all", "--format=%gD", "--date=unix").decode(errors="replace")
    times = [int(value) for value in re.findall(r"@\{(\d+)\}", reflog)]
    if not times:
        raise SafetyError("No reflog activity evidence; timestamp alone is insufficient")
    dirty = git(repo, "status", "--porcelain=v1", "-z", "--untracked-files=normal")
    if dirty:
        raise SafetyError("Repository has source or index changes; preserve its environment")
    return {"latest_reflog": max(times), "ignored": True, "tracked": False, "source_clean": True}


def entries(path, budget, depth=0):
    """One bounded directory enumeration; each entry consumes the shared budget."""
    ancestor_identity(path)
    root_device = os.lstat(path).st_dev
    if not os.lstat(path).st_mode & 0o444:
        raise SafetyError("Inaccessible directory: %s" % clean(path))
    values = []
    with os.scandir(path) as stream:
        for entry in stream:
            budget.consume(depth)
            st = entry.stat(follow_symlinks=False)
            if st.st_dev != root_device:
                raise SafetyError("Mount boundary: %s" % clean(entry.path))
            values.append((Path(entry.path), st))
    return sorted(values, key=lambda pair: str(pair[0]))


def source_activity(repo, config, budget):
    newest = 0
    artifacts = []
    reviews = []
    def walk(path, depth):
        nonlocal newest
        for child, st in entries(path, budget, depth):
            if child.name == ".git":
                continue
            if stat.S_ISLNK(st.st_mode):
                newest = max(newest, st.st_mtime_ns)
                continue
            if child.name in REPO_ARTIFACTS and stat.S_ISDIR(st.st_mode):
                artifacts.append(child)
                continue
            if child.name in REPORT_NAMES:
                reviews.append(child)
            if protected(child):
                # Presence of unique protected source still contributes source activity;
                # its content is never read, and doesn't authorize removing that data.
                newest = max(newest, st.st_mtime_ns)
                continue
            newest = max(newest, st.st_mtime_ns)
            if stat.S_ISDIR(st.st_mode):
                walk(child, depth + 1)
    walk(repo, 0)
    return newest, artifacts, reviews


def repo_policy(path, repo, config, state, process, budget=None):
    path, repo = canonical(path), canonical(repo)
    if not any(within(repo, root) for root in config["repo_roots"]) or not within(path, repo) or path == repo:
        raise SafetyError("Repository candidate is outside approved roots")
    ancestor_identity(repo)
    if path.name not in REPO_ARTIFACTS:
        raise SafetyError("Unknown generated artifact")
    evidence = git_evidence(repo, path)
    latest, _, _ = source_activity(repo, config, budget or Budget(config["max_files"], config["max_depth"]))
    cutoff = time.time() - config["repo_days"] * 86400
    if latest / 1e9 > cutoff or evidence["latest_reflog"] > cutoff:
        raise SafetyError("Project source or Git reflog activity is recent")
    spec_names = NODE_LOCKS if path.name == "node_modules" else PYTHON_SPECS
    specs = [str(repo / name) for name in spec_names if (repo / name).is_file() and not (repo / name).is_symlink()]
    if not specs:
        raise SafetyError("No dependency specification/lockfile proves regeneration")
    if path.name in {".venv", "venv"}:
        cfg = path / "pyvenv.cfg"
        if not cfg.is_file() or cfg.is_symlink():
            raise SafetyError("Environment lacks regular pyvenv.cfg")
    blockers = process.blockers(repo)
    if blockers:
        raise SafetyError("; ".join(blockers))
    fp = fingerprint(path, budget or Budget(config["max_files"], config["max_depth"]), state=state)
    if fp["newest_ns"] / 1e9 > cutoff:
        raise SafetyError("Artifact itself is recently modified")
    regen = "Install dependencies from " + ", ".join(Path(spec).name for spec in specs)
    if path.name == "__pycache__":
        regen = "Python recreates bytecode when importing source"
    elif path.name in {".pytest_cache", ".mypy_cache", ".ruff_cache"}:
        regen = "The corresponding test/type/lint tool recreates its cache"
    return fp, ["Allowlisted generated artifact", "Git-ignored; no tracked data; clean source/index",
                "%s-day source, reflog and artifact inactivity proxies" % config["repo_days"],
                "No observed project process use", regen], regen


def cache_policy(path, config, state, process, budget=None):
    path = canonical(path)
    if path.name not in USER_CACHES or str(path.parent) not in config["cache_roots"]:
        raise SafetyError("Unrecognized user cache provenance")
    if (path.parent / path.name).is_symlink():
        raise SafetyError("Cache root is a symlink")
    layout = {child.name for child, _ in entries(path, budget or Budget(config["max_files"], config["max_depth"]))}
    if path.name == "pip":
        if not layout or not layout <= {"http", "http-v2", "wheels", "selfcheck"}:
            raise SafetyError("Pip cache layout is unproven or contains unexpected unique data")
    elif path.name == "uv":
        marker = path / "CACHEDIR.TAG"
        if not marker.is_file() or marker.is_symlink():
            raise SafetyError("uv cache lacks a regular CACHEDIR.TAG provenance marker")
        with open(marker, "rb") as stream:
            if not stream.read(64).startswith(b"Signature: 8a477f597d28d172789f06886806bc55"):
                raise SafetyError("uv cache provenance marker is invalid")
        if any(name not in {"CACHEDIR.TAG", ".gitignore", ".lock"} and not re.fullmatch(r"[a-z]+-v\d+", name) for name in layout):
            raise SafetyError("uv cache contains unexpected unique data")
    elif path.name == "npm":
        # Whole npm roots usually include logs; retain them rather than infer
        # that diagnostic evidence is disposable.
        if layout != {"_cacache"}:
            raise SafetyError("npm root contains logs or unproven data; use npm's cache controls manually")
        child = path / "_cacache"
        if child.is_symlink() or not child.is_dir():
            raise SafetyError("npm content-addressed cache is unproven")
    blockers = process.blockers(path)
    if blockers:
        raise SafetyError("; ".join(blockers))
    fp = fingerprint(path, budget or Budget(config["max_files"], config["max_depth"]), state=state)
    if fp["newest_ns"] / 1e9 > time.time() - config["cache_days"] * 86400:
        raise SafetyError("Cache activity is recent")
    return fp, ["Recognized %s download cache layout" % path.name, "%s-day inactivity proxy" % config["cache_days"],
                "No observed process use", "Package downloads regenerate this cache"], USER_CACHES[path.name]


def xcode_policy(path, config, state, process, budget=None):
    path = canonical(path)
    allowed = Path.home() / "Library" / "Developer" / "Xcode" / "DerivedData"
    if path.parent != allowed or not any(within(allowed, root) for root in config["cache_roots"]):
        raise SafetyError("DerivedData is outside explicitly scoped cache roots")
    info = path / "info.plist"
    if not info.is_file() or info.is_symlink():
        raise SafetyError("DerivedData has no regular workspace provenance plist")
    with open(info, "rb") as stream:
        value = plistlib.load(stream)
    workspace = value.get("WorkspacePath")
    if not isinstance(workspace, str):
        raise SafetyError("DerivedData workspace provenance is unknown")
    project = canonical(workspace).parent
    matches = [root for root in config["repo_roots"] if within(project, root)]
    if not matches:
        raise SafetyError("Associated Xcode project is outside repository roots")
    repo = project
    while not (repo / ".git").exists() and any(within(repo.parent, root) for root in matches):
        repo = repo.parent
    latest, _, _ = source_activity(repo, config, budget or Budget(config["max_files"], config["max_depth"]))
    # No Git ignored rule needed for an external Apple-owned generated directory;
    # source Git/reflog activity must still be established.
    reflog = git(repo, "reflog", "--all", "--format=%gD", "--date=unix").decode(errors="replace")
    times = [int(value) for value in re.findall(r"@\{(\d+)\}", reflog)]
    cutoff = time.time() - config["repo_days"] * 86400
    if not times or max(times) > cutoff or latest / 1e9 > cutoff or git(repo, "status", "--porcelain=v1", "-z"):
        raise SafetyError("Associated source/reflog is recent, dirty or unproven")
    blockers = process.blockers(repo) + process.blockers(path)
    if blockers:
        raise SafetyError("; ".join(blockers))
    fp = fingerprint(path, budget or Budget(config["max_files"], config["max_depth"]), state=state)
    if fp["newest_ns"] / 1e9 > cutoff:
        raise SafetyError("DerivedData is recent")
    return fp, ["Xcode DerivedData info.plist associates " + clean(workspace), "Old clean source + Git reflog", "No observed Xcode/project use"], "Xcode rebuilds DerivedData; indexes/builds may take time"


def duplicate_git_guard(path):
    """Preserve tracked source, including when duplicate root is inside a repo."""
    path = canonical(path)
    for parent in path.parents:
        marker = parent / ".git"
        if marker.exists() or marker.is_symlink():
            ancestor_identity(parent)
            relative = path.relative_to(parent).as_posix()
            if git(parent, "ls-files", "-z", "--", ":(literal)" + relative):
                raise SafetyError("Tracked repository data is protected from duplicate cleanup")
            return


def candidate(path, kind, context, fp=None, evidence=None, blockers=None, hint=""):
    path = str(canonical(path))
    fp = fp or {"digest": None, "logical": 0, "allocated": 0, "entries": 0}
    return {"id": digest([path, kind, fp["digest"]])[:12], "path": path, "kind": kind, "context": context,
            "fingerprint": fp, "evidence": evidence or [], "blockers": blockers or [],
            "eligible": not blockers and fp["digest"] is not None, "hint": hint}


def apps_inventory(config, budget):
    inventory = {}
    issues = []
    for root in config["app_roots"]:
        root = canonical(root)
        if not root.exists():
            continue
        try:
            def walk(path, level):
                if level > min(config["discovery_depth"], 3):
                    raise SafetyError("App inventory depth limit reached")
                for child, st in entries(path, budget, level):
                    if stat.S_ISLNK(st.st_mode):
                        if child.suffix == ".app":
                            issues.append("Symlink app bundle inventory is uncertain: " + clean(child))
                        continue
                    if not stat.S_ISDIR(st.st_mode):
                        continue
                    if child.suffix.lower() == ".app":
                        info = child / "Contents" / "Info.plist"
                        ancestor_identity(info.parent)
                        if info.is_symlink():
                            raise SafetyError("App Info.plist is a symlink")
                        with open(info, "rb") as stream:
                            data = plistlib.load(stream)
                        bundle = data.get("CFBundleIdentifier")
                        version = str(data.get("CFBundleShortVersionString", data.get("CFBundleVersion", "unknown")))
                        if isinstance(bundle, str):
                            inventory.setdefault(bundle, []).append({"path": str(child), "version": version})
                        else:
                            issues.append("App has no bundle ID: " + clean(child))
                    else:
                        walk(child, level + 1)
            walk(root, 0)
        except (OSError, ValueError, SafetyError) as exc:
            issues.append("App inventory incomplete: " + clean(exc))
    return inventory, issues


class Scanner:
    def __init__(self, config, state, process=None):
        self.config = validate(dict(config), state.path)
        self.state = state
        self.process = process if process is not None else activity.snapshot()
        self.budget = Budget(config["max_files"], config["max_depth"])
        self.items = []
        self.issues = []
        self.repositories = set()
        self.coverage = []

    def report(self, path, kind, reason, context=None, evidence=None, hint=""):
        fp = None
        try:
            fp = fingerprint(path, self.budget, inspect_protected=False)
            fp.pop("records", None)
        except (OSError, SafetyError) as exc:
            self.issues.append("Cannot fully inspect %s: %s" % (clean(path), clean(exc)))
            reason += "; descendant inspection incomplete"
        self.items.append(candidate(path, kind, context or {}, fp, evidence, [reason], hint))

    def repo(self, repo):
        repo = canonical(repo)
        if str(repo) in self.repositories:
            return
        self.repositories.add(str(repo))
        try:
            _, artifacts, reviews = source_activity(repo, self.config, self.budget)
        except (OSError, SafetyError) as exc:
            self.issues.append("Repository inspection incomplete %s: %s" % (clean(repo), clean(exc)))
            return
        for path in artifacts:
            try:
                fp, evidence, hint = repo_policy(path, repo, self.config, self.state.path, self.process, self.budget)
                self.items.append(candidate(path, "repo-artifact", {"repo": str(repo)}, fp, evidence, [], hint))
            except (OSError, SafetyError, subprocess.TimeoutExpired) as exc:
                self.report(path, "repo-artifact", clean(exc), {"repo": str(repo)}, hint="Retain unless repository provenance, regeneration and inactivity are established")
        for path in reviews:
            self.report(path, "unique-artifact", "Potential unique source, data, log, screenshot or report; age is insufficient", {"repo": str(repo)}, hint="Inspect/export any unique evidence manually")

    def discover_repos(self):
        for root in self.config["repo_roots"]:
            root = canonical(root)
            if not root.exists():
                self.coverage.append({"root": str(root), "status": "absent"})
                continue
            try:
                device = os.lstat(root).st_dev
                def walk(path, level):
                    if (path / ".git").exists():
                        self.repo(path)
                        return
                    for child, st in entries(path, self.budget, level):
                        if not stat.S_ISDIR(st.st_mode) or stat.S_ISLNK(st.st_mode) or protected(child, self.state.path):
                            continue
                        if st.st_dev != device:
                            self.issues.append("Skipped repository mount boundary: " + clean(child))
                            continue
                        if level >= self.config["discovery_depth"]:
                            self.issues.append("Repository discovery depth exhausted at " + clean(child))
                            continue
                        if child.name not in REPO_ARTIFACTS:
                            walk(child, level + 1)
                walk(root, 0)
                self.coverage.append({"root": str(root), "status": "bounded scan"})
            except (OSError, SafetyError) as exc:
                self.issues.append("Repo root incomplete %s: %s" % (clean(root), clean(exc)))

    def caches(self):
        for root in self.config["cache_roots"]:
            root = canonical(root)
            if not root.exists():
                continue
            try:
                for path, st in entries(root, self.budget):
                    if stat.S_ISLNK(st.st_mode):
                        self.issues.append("Skipped cache symlink " + clean(path))
                        continue
                    if not stat.S_ISDIR(st.st_mode):
                        continue
                    if path.name in USER_CACHES:
                        try:
                            fp, evidence, hint = cache_policy(path, self.config, self.state.path, self.process, self.budget)
                            self.items.append(candidate(path, "user-cache", {}, fp, evidence, [], hint))
                        except (OSError, SafetyError) as exc:
                            self.report(path, "user-cache", clean(exc), hint=USER_CACHES[path.name])
                    elif root.name == "DerivedData" and root.parent.name == "Xcode":
                        try:
                            fp, evidence, hint = xcode_policy(path, self.config, self.state.path, self.process, self.budget)
                            self.items.append(candidate(path, "xcode-cache", {}, fp, evidence, [], hint))
                        except (OSError, SafetyError, ValueError, subprocess.TimeoutExpired) as exc:
                            self.report(path, "xcode-cache", clean(exc), hint="Use Xcode Settings → Locations to inspect DerivedData")
                    else:
                        # Unknown app cache records are report-only, regardless of age.
                        self.report(path, "app-cache", "Unknown application cache provenance; manual review only", hint="Prefer the owning application's cache controls")
            except (OSError, SafetyError) as exc:
                self.issues.append("Cache root incomplete %s: %s" % (clean(root), clean(exc)))

    def duplicates(self):
        sizes = {}
        device_by_root = {}
        for root in self.config["duplicate_roots"]:
            root = canonical(root)
            if not root.exists():
                self.issues.append("Duplicate root absent: " + clean(root))
                continue
            try:
                device_by_root[str(root)] = os.lstat(root).st_dev
                def walk(path, depth):
                    for child, st in entries(path, self.budget, depth):
                        if protected(child, self.state.path) or stat.S_ISLNK(st.st_mode):
                            continue
                        if st.st_dev != device_by_root[str(root)]:
                            self.issues.append("Skipped duplicate mount boundary: " + clean(child))
                            continue
                        if stat.S_ISDIR(st.st_mode):
                            walk(child, depth + 1)
                        elif stat.S_ISREG(st.st_mode) and st.st_size and st.st_nlink == 1 and not getattr(st, "st_flags", 0) & 0x40000000:
                            sizes.setdefault(st.st_size, []).append((child, root))
                walk(root, 0)
            except (OSError, SafetyError) as exc:
                self.issues.append("Duplicate root incomplete %s: %s" % (clean(root), clean(exc)))
        for paths in sizes.values():
            if len(paths) < 2:
                continue
            hashes = {}
            for path, root in paths:
                try:
                    duplicate_git_guard(path)
                    hashed = file_hash(path)
                    fp = fingerprint(path, self.budget, state=self.state.path)
                    hashes.setdefault(hashed, []).append((path, root, fp))
                except (OSError, SafetyError) as exc:
                    self.issues.append("Duplicate hash incomplete %s: %s" % (clean(path), clean(exc)))
            for hashed, group in hashes.items():
                if len(group) < 2:
                    continue
                # Keeper is immutable in the signed plan and never a selectable candidate.
                group.sort(key=lambda item: str(item[0]))
                keeper, keeper_root, keeper_fp = group[0]
                for path, root, fp in group[1:]:
                    blockers = self.process.blockers(path) + self.process.blockers(keeper)
                    context = {"root": str(root), "keeper": str(keeper), "keeper_root": str(keeper_root), "keeper_fingerprint": keeper_fp, "sha256": hashed}
                    self.items.append(candidate(path, "duplicate", context, fp,
                                                ["Streamed SHA-256 matches retained file", "Fixed keeper: " + clean(keeper), "Regular files; hard links excluded"],
                                                blockers, "Keep the visible retained copy; review metadata before selecting"))

    def apps(self):
        inventory, issues = apps_inventory(self.config, self.budget)
        self.issues.extend(issues)
        for bundle, copies in inventory.items():
            if len(copies) > 1:
                def version(item):
                    return tuple(int(token) if token.isdigit() else -1 for token in re.findall(r"\d+|[^\d.]+", item["version"]))
                ordered = sorted(copies, key=version, reverse=True)
                for item in ordered[1:]:
                    self.report(item["path"], "older-app", "App bundle removal is manual; versions can be incomparable",
                                {"bundle_id": bundle, "copies": ordered},
                                ["Bundle ID " + clean(bundle), "Version " + clean(item["version"]), "Highest observed version " + clean(ordered[0]["version"])],
                                "Review app compatibility and use Finder/application uninstaller")
        for root in self.config["app_data_roots"]:
            root = canonical(root)
            if not root.exists():
                continue
            try:
                for path, st in entries(root, self.budget):
                    bundle = path.name.removesuffix(".plist")
                    if bundle.count(".") >= 2 and bundle not in inventory:
                        self.report(path, "possible-remnant", "Bundle ID not seen in bounded app inventory; external apps/plugins remain possible",
                                    {"bundle_id": bundle, "app_inventory_complete": not issues}, hint="Use the owning app's uninstaller; preferences/support may contain unique data")
            except (OSError, SafetyError) as exc:
                self.issues.append("App data inventory incomplete: " + clean(exc))
        return inventory

    def run(self):
        self.discover_repos()
        self.caches()
        self.duplicates()
        inventory = self.apps()
        if self.config["system_reports"]:
            for path in ("/Library/Updates", "/Library/Application Support/Apple/AssetCache"):
                if Path(path).exists():
                    self.report(path, "macos-managed", "macOS update staging / Content Caching is report-only", hint="Use System Settings → General → Storage / Sharing → Content Caching; never remove staging manually")
        # Avoid overlapping claims and totals. Most specific action is withheld.
        by_path = {}
        for item in self.items:
            old = by_path.get(item["path"])
            if old is None or item["eligible"]:
                by_path[item["path"]] = item
        self.items = sorted(by_path.values(), key=lambda item: item["path"])
        for index, item in enumerate(self.items):
            for other in self.items[:index]:
                if overlap(item["path"], other["path"]) and item["path"] != other["path"]:
                    item["blockers"].append("Overlaps another displayed candidate")
                    other["blockers"].append("Overlaps another displayed candidate")
                    item["eligible"] = other["eligible"] = False
        # An incomplete traversal can hide process/provenance evidence: fail closed globally.
        if self.issues:
            for item in self.items:
                if item["eligible"]:
                    item["eligible"] = False
                    item["blockers"].append("Scan coverage is incomplete; resolve listed scan issues")
        counted = []
        logical = allocated = 0
        inode_seen = set()
        for item in sorted(self.items, key=lambda row: len(Path(row["path"]).parts)):
            if any(within(item["path"], root) for root in counted):
                continue
            records = item["fingerprint"].get("records", [])
            if records:
                for _, record, *tail in records:
                    inode = tuple(record[:2])
                    if record[2] == stat.S_IFREG and inode not in inode_seen:
                        logical += record[6]
                        # allocation stored per-candidate; hard-linked records excluded.
                        inode_seen.add(inode)
                allocated += item["fingerprint"]["allocated"]
            else:
                logical += item["fingerprint"]["logical"]
                allocated += item["fingerprint"]["allocated"]
            counted.append(item["path"])
        return {"schema": SCHEMA, "created_at": time.time(), "state": str(self.state.path), "config": self.config,
                "activity": self.process.summary(), "coverage": self.coverage, "issues": self.issues,
                "apps": inventory, "candidates": self.items,
                "totals": {"logical": logical, "allocated": allocated, "quarantine_frees_bytes": 0,
                           "note": "Estimates only; APFS clones/compression/snapshots affect physical reclamation"}}


def validate_policy(item, config, state, process):
    """Re-derive eligibility, never accept manifest labels as authorization."""
    validate(dict(config), state)
    reason = protected(item["path"], state)
    if reason:
        raise SafetyError(reason)
    if not item.get("eligible") or item.get("blockers"):
        raise SafetyError("Report-only / blocked candidate cannot be selected")
    if item["kind"] == "repo-artifact":
        return repo_policy(item["path"], item["context"]["repo"], config, state, process)[0]
    if item["kind"] == "user-cache":
        return cache_policy(item["path"], config, state, process)[0]
    if item["kind"] == "xcode-cache":
        return xcode_policy(item["path"], config, state, process)[0]
    if item["kind"] == "duplicate":
        context = item["context"]
        if not any(within(item["path"], root) for root in config["duplicate_roots"]) or not any(within(context["keeper"], root) for root in config["duplicate_roots"]):
            raise SafetyError("Duplicate/keeper outside explicit roots")
        if protected(context["keeper"], state) or overlap(item["path"], context["keeper"]):
            raise SafetyError("Duplicate keeper is unsafe")
        for path in (item["path"], context["keeper"]):
            duplicate_git_guard(path)
            blockers = process.blockers(path)
            if blockers:
                raise SafetyError("; ".join(blockers))
            if file_hash(path) != context["sha256"]:
                raise SafetyError("Duplicate content/keeper changed")
        keeper_fp = fingerprint(context["keeper"], Budget(config["max_files"], config["max_depth"]), state=state)
        if keeper_fp["digest"] != context["keeper_fingerprint"]["digest"]:
            raise SafetyError("Duplicate keeper fingerprint changed")
        return fingerprint(item["path"], Budget(config["max_files"], config["max_depth"]), state=state)
    raise SafetyError("Unknown action kind; reports cannot authorize mutation")
