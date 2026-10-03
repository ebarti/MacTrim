"""Small JSON configuration; explicit duplicate roots only."""
import json
from pathlib import Path

from .safety import SafetyError, canonical, overlap, protected

DEFAULT_STATE = Path.home() / "Library" / "Application Support" / "MacTrim"


def defaults():
    home = Path.home()
    return {"repo_roots": [str(home / item) for item in ("Developer", "Projects", "src", "Github")],
            "duplicate_roots": [], "cache_roots": [str(home / "Library" / "Caches")],
            "app_roots": ["/Applications", "/System/Applications", str(home / "Applications")],
            "app_data_roots": [str(home / "Library" / item) for item in ("Caches", "Preferences", "Application Support")],
            "repo_days": 90, "cache_days": 30, "max_files": 100000, "max_depth": 24,
            "discovery_depth": 4, "system_reports": True}


def validate(config, state):
    expected = defaults()
    if set(config) != set(expected):
        raise SafetyError("Unknown or missing configuration keys")
    for name in ("repo_days", "cache_days", "max_files", "max_depth", "discovery_depth"):
        if type(config[name]) is not int or not 1 <= config[name] <= (1000000 if name == "max_files" else 36500 if name.endswith("days") else 64):
            raise SafetyError("Invalid positive configuration value: %s" % name)
    if type(config["system_reports"]) is not bool:
        raise SafetyError("system_reports must be a boolean")
    for name in ("repo_roots", "duplicate_roots", "cache_roots", "app_roots", "app_data_roots"):
        roots = config[name]
        if not isinstance(roots, list) or len(roots) > 100 or not all(isinstance(root, str) and root for root in roots):
            raise SafetyError("Invalid root list: %s" % name)
        config[name] = sorted(set(str(canonical(root)) for root in roots))
        if name in ("repo_roots", "duplicate_roots", "cache_roots"):
            for root in config[name]:
                reason = protected(root, state)
                if reason:
                    raise SafetyError("Unsafe scan root %s: %s" % (root, reason))
        for index, root in enumerate(config[name]):
            if any(overlap(root, other) for other in config[name][:index]):
                raise SafetyError("Overlapping roots in %s" % name)
    return config


def read_config(path, state):
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
    return validate(config, state)
