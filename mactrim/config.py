"""Small JSON configuration; explicit duplicate roots only."""
import json
from pathlib import Path

from .safety import SafetyError, canonical, overlap, protected

DEFAULT_STATE = Path.home() / "Library" / "Application Support" / "MacTrim"


def defaults():
    home = Path.home()
    return {"repo_roots": [str(home / item) for item in ("Developer", "Projects", "src", "Github")],
            "worktree_roots": [str(home / ".codex" / "worktrees"), str(home / ".codex-workspaces" / "worktrees")],
            "duplicate_roots": [], "cache_roots": [str(home / "Library" / "Caches"), str(home / ".cache"), str(home / ".npm")],
            "app_roots": ["/Applications", "/System/Applications", str(home / "Applications")],
            "app_data_roots": [str(home / "Library" / item) for item in ("Caches", "Preferences", "Application Support", "Logs", "Saved Application State", "Containers")],
            "repo_days": 90, "cache_days": 30, "max_files": 100000, "max_depth": 24,
            "discovery_depth": 4, "system_reports": True,
            "budgets": {"repositories": 20000, "worktrees": 20000, "caches": 20000, "duplicates": 20000, "apps": 10000, "system": 5000},
            "storage_max_files": 50000, "storage_max_depth": 16, "github_squash": True,
            "worktree_default_ref": "", "retired_apps": {}, "app_aliases": {},
            "storage_cache": {"enabled": True, "max_bytes": 16 * 1024 * 1024, "reconcile_seconds": 7 * 86400},
            "history": {"enabled": True, "max_bytes": 16 * 1024 * 1024, "max_snapshots": 60, "max_days": 60, "auto_interval_seconds": 3600}}


def validate(config, state):
    expected = defaults()
    if set(config) != set(expected):
        raise SafetyError("Unknown or missing configuration keys")
    for name in ("repo_days", "cache_days", "max_files", "max_depth", "discovery_depth", "storage_max_files", "storage_max_depth"):
        if type(config[name]) is not int or not 1 <= config[name] <= (1000000 if name in {"max_files", "storage_max_files"} else 36500 if name.endswith("days") else 64):
            raise SafetyError("Invalid positive configuration value: %s" % name)
    cache = config['storage_cache']
    if not isinstance(cache, dict) or set(cache) != set(expected['storage_cache']) or type(cache['enabled']) is not bool:
        raise SafetyError('Invalid Storage cache configuration')
    if type(cache['max_bytes']) is not int or not 1 <= cache['max_bytes'] <= 16 * 1024 * 1024 or type(cache['reconcile_seconds']) is not int or not 1 <= cache['reconcile_seconds'] <= 30 * 86400:
        raise SafetyError('Storage cache limits out of bounds')
    history = config["history"]
    if not isinstance(history, dict) or set(history) != set(expected["history"]) or type(history["enabled"]) is not bool:
        raise SafetyError("Invalid history configuration")
    for name, maximum in (("max_bytes", 16 * 1024 * 1024), ("max_snapshots", 60), ("max_days", 60), ("auto_interval_seconds", 86400 * 60)):
        if type(history[name]) is not int or not 1 <= history[name] <= maximum:
            raise SafetyError("History limit out of bounds: " + name)
    if not isinstance(config["budgets"], dict) or set(config["budgets"]) != set(expected["budgets"]) or any(type(value) is not int or not 1 <= value <= 1000000 for value in config["budgets"].values()):
        raise SafetyError("Invalid per-category entry budgets")
    if type(config["github_squash"]) is not bool or not isinstance(config["worktree_default_ref"], str):
        raise SafetyError("Invalid worktree proof configuration")
    if not isinstance(config["retired_apps"], dict) or not isinstance(config["app_aliases"], dict):
        raise SafetyError("App owner mappings must be JSON objects")
    import re
    for bundle, declaration in config["retired_apps"].items():
        if not isinstance(bundle, str) or not re.fullmatch(r"[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+){2,}", bundle) or not isinstance(declaration, dict) or set(declaration) != {"confirmed", "paths", "aliases"}:
            raise SafetyError("Retired app requires bundle ID and exact confirmed/paths/aliases declaration")
        if type(declaration["confirmed"]) is not bool or not isinstance(declaration["paths"], list) or not isinstance(declaration["aliases"], list) or not all(isinstance(value, str) for value in declaration["paths"] + declaration["aliases"]):
            raise SafetyError("Invalid retired app exact scopes")
        declaration["paths"] = [str(canonical(value)) for value in declaration["paths"]]
    if any(not isinstance(key, str) or not isinstance(value, str) for key, value in config["app_aliases"].items()):
        raise SafetyError("App alias mapping must map names to bundle IDs")
    if type(config["system_reports"]) is not bool:
        raise SafetyError("system_reports must be a boolean")
    for name in ("repo_roots", "worktree_roots", "duplicate_roots", "cache_roots", "app_roots", "app_data_roots"):
        roots = config[name]
        if not isinstance(roots, list) or len(roots) > 100 or not all(isinstance(root, str) and root for root in roots):
            raise SafetyError("Invalid root list: %s" % name)
        config[name] = sorted(set(str(canonical(root)) for root in roots))
        if name in ("repo_roots", "worktree_roots", "duplicate_roots", "cache_roots"):
            for root in config[name]:
                reason = protected(root, state)
                if reason:
                    raise SafetyError("Unsafe scan root %s: %s" % (root, reason))
        for index, root in enumerate(config[name]):
            if any(overlap(root, other) for other in config[name][:index]):
                raise SafetyError("Overlapping roots in %s" % name)
    return config


def read_config(path, state, validate_now=True):
    config = defaults()
    if path:
        try:
            with open(path, "r", encoding="utf-8") as stream:
                supplied = json.load(stream)
        except (OSError, ValueError) as exc:
            raise SafetyError("Cannot read JSON config: %s" % exc) from exc
        if not isinstance(supplied, dict) or set(supplied) - set(config):
            raise SafetyError("Config must contain known JSON keys")
        config.update(supplied)
    return validate(config, state) if validate_now else config
