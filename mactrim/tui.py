"""Text presentation helpers and the native Textual entry point."""
import json
import sys
from .safety import SafetyError, clean


def human(number):
    value = float(number)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return "%0.1f %s" % (value, unit)
        value /= 1024


def details(item):
    lines = ["FULL PATH", clean(item["path"]), "", "CLASSIFICATION", clean(item["kind"]),
             "Actionable" if item["eligible"] else "Report only / blocked", "",
             "ESTIMATED SIZE", "Logical %s  /  Allocated %s" % (human(item["fingerprint"]["logical"]), human(item["fingerprint"]["allocated"])),
             "Quarantine frees 0 bytes", "", "EVIDENCE"]
    lines += ["- " + clean(value) for value in item["evidence"]] or ["No provenance established"]
    if item["context"]:
        lines += ["", "OWNERSHIP / GIT SCOPE"] + [clean(key) + ": " + clean(json.dumps(value, ensure_ascii=True)) for key, value in item["context"].items()]
    if item["context"].get("keeper"):
        lines += ["", "PROTECTED KEEPER", clean(item["context"]["keeper"]), "SHA-256 " + item["context"]["sha256"]]
    if item["blockers"]:
        lines += ["", "BLOCKERS"] + ["- " + clean(value) for value in item["blockers"]]
    lines += ["", "REGENERATION / REVIEW", clean(item["hint"]), "", "FINGERPRINT", str(item["fingerprint"]["digest"])]
    return lines


def review(plan, state, config=None, storage_root="/", output=None, initial_tab="cleanup", initial_full=False):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise SafetyError("TUI requires an interactive terminal. Use review PLAN --details or scan --output PLAN.")
    try:
        from .ui import MacTrimApp
    except ImportError as exc:
        raise SafetyError("Install the project environment (see README) or run mactrim-launch: " + clean(exc)) from exc
    MacTrimApp(plan=plan, state=state, config=config, storage_root=storage_root,
               output=output, initial_tab=initial_tab, initial_full=initial_full).run()
    return 0
