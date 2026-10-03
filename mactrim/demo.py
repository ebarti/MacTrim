"""Disposable demo fixture only: no scanning of the user's existing files."""
import json
import os
from pathlib import Path
import plistlib
import subprocess
import time

from .config import defaults
from .safety import SafetyError, ancestor_identity, canonical, directory_fd


def create(destination):
    root = canonical(destination)
    ancestor_identity(root.parent)
    with directory_fd(root.parent) as fd:
        try:
            os.mkdir(root.name, 0o700, dir_fd=fd)
        except FileExistsError as exc:
            raise SafetyError("Demo destination already exists; choose a new absent directory") from exc
    project = root / "projects" / "old-weather-tool"
    project.mkdir(parents=True)
    (project / ".gitignore").write_text(".venv/\n__pycache__/\n.pytest_cache/\nreports/\n", encoding="utf-8")
    (project / "pyproject.toml").write_text('[project]\nname="demo-weather-tool"\nversion="0.0.0"\ndependencies=[]\n', encoding="utf-8")
    (project / "weather.py").write_text('print("Disposable MacTrim demo source")\n', encoding="utf-8")
    env = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull,
               GIT_AUTHOR_DATE="2020-01-01T00:00:00+0000", GIT_COMMITTER_DATE="2020-01-01T00:00:00+0000")
    for command in (["init", "-q"], ["add", "."], ["-c", "user.name=MacTrim demo", "-c", "user.email=demo@invalid.example", "commit", "-qm", "Disposable fixture source"]):
        subprocess.run(["/usr/bin/git", "-C", str(project)] + command, env=env, check=True, capture_output=True)
    (project / ".venv" / "bin").mkdir(parents=True)
    (project / ".venv" / "pyvenv.cfg").write_text("home = /usr/bin\ninclude-system-site-packages = false\n", encoding="utf-8")
    (project / ".venv" / "bin" / "fixture-package").write_bytes(b"reproducible fixture content\n" * 1000)
    (project / "__pycache__").mkdir()
    (project / "__pycache__" / "weather.cpython-39.pyc").write_bytes(b"demo bytecode\n" * 100)
    (project / "reports").mkdir()
    (project / "reports" / "unique-observation.txt").write_text("Keep this unique report: age is insufficient.\n", encoding="utf-8")
    duplicates = root / "duplicates"
    duplicates.mkdir()
    for name in ("01-keeper.txt", "02-copy.txt", "03-copy.txt"):
        (duplicates / name).write_bytes(b"A retained equivalent proves these demo copies redundant.\n" * 200)
    (duplicates / "private.sqlite").write_bytes(b"protected database -- never hashed")
    (duplicates / "linked-a.txt").write_bytes(b"hardlinked content")
    os.link(duplicates / "linked-a.txt", duplicates / "linked-b.txt")
    caches = root / "caches"
    (caches / "pip" / "http-v2").mkdir(parents=True)
    (caches / "pip" / "http-v2" / "fixture.body").write_bytes(b"regenerable download\n" * 500)
    (caches / "com.example.retiredapp").mkdir()
    (caches / "com.example.retiredapp" / "unknown.cache").write_bytes(b"uncertain provenance")
    apps = root / "applications"
    for name, version in (("Editor Current.app", "2.0"), ("Editor Older.app", "1.5")):
        contents = apps / name / "Contents"
        contents.mkdir(parents=True)
        with open(contents / "Info.plist", "wb") as stream:
            plistlib.dump({"CFBundleIdentifier": "com.example.editor", "CFBundleShortVersionString": version}, stream)
    preferences = root / "preferences"
    preferences.mkdir()
    (preferences / "com.example.retiredapp.plist").write_bytes(plistlib.dumps({"unique-preference": "retain"}))
    old = time.time() - 180 * 86400
    for parent, dirs, files in os.walk(root, topdown=False, followlinks=False):
        if ".git" in Path(parent).parts:
            continue
        for name in files + dirs:
            path = Path(parent) / name
            if name != ".git":
                os.utime(path, (old, old), follow_symlinks=False)
        os.utime(parent, (old, old), follow_symlinks=False)
    config = defaults()
    config.update(worktree_roots=[], repo_roots=[str(root / "projects")], duplicate_roots=[str(duplicates)], cache_roots=[str(caches)],
                  app_roots=[str(apps)], app_data_roots=[str(caches), str(preferences)], system_reports=False)
    config_path = root / "config.json"
    config_path.write_text(json.dumps(config, indent=2) + "\n", encoding="utf-8")
    return {"root": str(root), "config": str(config_path), "state": str(root / "state"),
            "note": "Only disposable fixture files were created. Real macOS activity checks still apply; incomplete access leaves candidates report-only."}
