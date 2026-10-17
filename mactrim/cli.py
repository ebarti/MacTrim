"""CLI for bounded scan, readable review and separately approved lifecycle actions."""
import argparse
import json
import os
from pathlib import Path
import sys

from . import __version__
from .config import DEFAULT_STATE, defaults, read_config, validate
from .demo import create
from .executor import Executor, approval_for, selection
from .safety import SafetyError, canonical, clean, directory_fd, json_bytes
from .scanner import Scanner
from .state import State, load_manifest
from .tui import details, human, review


def parser():
    command = argparse.ArgumentParser(prog="mactrim", description="Evidence-led Mac cleanup. Read-only scan; reversible quarantine; separately approved purge.")
    command.add_argument("--version", action="version", version="MacTrim " + __version__)
    command.add_argument("--state", type=Path, default=DEFAULT_STATE, help="Private state/quarantine directory on the source volume")
    command.add_argument("--config", type=Path, help="JSON configuration (see config-example.json)")
    children = command.add_subparsers(dest="command")
    scan = children.add_parser("scan", help="Bounded read-only discovery and optional signed JSON export")
    scan.add_argument("--repo-root", action="append", help="Replace default repository roots; may repeat")
    scan.add_argument("--worktree-root", action="append", help="Replace default registered-worktree action roots")
    scan.add_argument("--duplicate-root", action="append", help="Explicit duplicate scope; may repeat; no implicit home hashing")
    scan.add_argument("--cache-root", action="append", help="Replace default cache roots; may repeat")
    scan.add_argument("--no-defaults", action="store_true", help="Scan only explicit flag/config scopes; no system/app default roots")
    scan.add_argument("--repo-days", type=int, help="Positive repository inactivity days (default 90)")
    scan.add_argument("--cache-days", type=int, help="Positive recognized-cache inactivity days (default 30)")
    scan.add_argument("--max-files", type=int, help="Traversal entry budget (default 100000)")
    scan.add_argument("--max-depth", type=int, help="Traversal depth limit (default 24)")
    scan.add_argument("--output", type=Path, help="Create signed JSON manifest at an absent path")
    scan.add_argument("--json", action="store_true", help="Print signed JSON instead of table")
    scan.add_argument("--tui", action="store_true", help="Open native TUI with background discovery")
    children.add_parser("tui", help="Open Cleanup and Storage tabs; background read-only discovery")
    storage = children.add_parser("storage", help="Metadata-only root storage explorer; no cleanup authority")
    storage.add_argument("path", nargs="?", default="/", type=Path)
    storage.add_argument("--json", action="store_true", help="Print bounded metadata dataset without a terminal")
    storage.add_argument("--max-files", type=int, default=50000, help="Metadata entries per root subtree (default 50000; max 1000000)")
    storage.add_argument("--max-depth", type=int, default=16)
    history = children.add_parser("history", help="Tiny local directory history; capture/list/compare/clear")
    history_sub = history.add_subparsers(dest="history_action", required=True)
    capture = history_sub.add_parser("capture", help="One metadata walk; directory-only compressed snapshot")
    capture.add_argument("path", nargs="?", default="/", type=Path)
    capture.add_argument("--max-files", type=int)
    capture.add_argument("--max-depth", type=int)
    history_sub.add_parser("list", help="List verified observations and actual allocated footprint")
    comparison = history_sub.add_parser("compare", help="Compare explicit IDs or latest compatible observations")
    comparison.add_argument("earlier", nargs="?")
    comparison.add_argument("later", nargs="?")
    comparison.add_argument("--metric", choices=["logical", "allocated"], default="allocated")
    history_sub.add_parser("clear", help="Delete only verified owned history records; unknown entries block")
    read = children.add_parser("review", help="Read a signed manifest; open TUI or textual details")
    read.add_argument("manifest", type=Path)
    read.add_argument("--tui", action="store_true")
    read.add_argument("--details", action="store_true")
    read.add_argument("--id", action="append", help="Display particular candidate IDs")
    for name in ("dry-run", "apply"):
        action = children.add_parser(name, help="Revalidate explicit selection" if name == "dry-run" else "Atomically quarantine an exactly approved selection")
        action.add_argument("manifest", type=Path)
        action.add_argument("--select", required=True, action="append", help="Candidate ID; may repeat or use comma-separated IDs")
        if name == "apply":
            action.add_argument("--approve", help="Exact phrase shown by dry-run; otherwise interactive typing required")
    quarantine = children.add_parser("quarantine", help="List/reconcile owned quarantine journals")
    quarantine.add_argument("action", choices=["list"])
    quarantine.add_argument("--json", action="store_true")
    restore = children.add_parser("restore", help="Restore verified item to absent original path; no overwrite")
    restore.add_argument("id")
    purge = children.add_parser("purge", help="Permanent deletion of one verified owned quarantine item; SECOND approval")
    purge.add_argument("id")
    purge.add_argument("--approve", help="Exact PURGE phrase; otherwise display and require interactive typing")
    demo = children.add_parser("demo", help="Create disposable showcase fixtures in a new absent directory")
    demo.add_argument("destination", type=Path)
    config = children.add_parser("config", help="Print supported default JSON configuration")
    config.add_argument("--output", type=Path)
    return command


def output_json(value):
    print(json.dumps(value, indent=2, ensure_ascii=True))


def export(path, value):
    path = canonical(path)
    with directory_fd(path.parent) as fd:
        try:
            out = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        except FileExistsError as exc:
            raise SafetyError("Export path already exists; choose a new absent file") from exc
        try:
            payload = json.dumps(value, indent=2, ensure_ascii=True).encode() + b"\n"
            offset = 0
            while offset < len(payload):
                offset += os.write(out, payload[offset:])
            os.fsync(out)
        finally:
            os.close(out)
        os.fsync(fd)


def show(plan, identifiers=None, full=False):
    print("MacTrim  |  Evidence-led Mac cleanup")
    totals = plan["totals"]
    print("%s logical / %s allocated estimate. Quarantine frees 0 bytes." % (human(totals["logical"]), human(totals["allocated"])))
    print("Activity: %s (current UID, non-zombie processes; other accounts unobserved)" % ("complete" if plan["activity"]["complete"] else "INCOMPLETE; mutation blocked"))
    for issue in plan["activity"]["issues"] + plan["issues"]:
        print("! " + clean(issue))
    print()
    if not plan["candidates"]:
        print("No candidates found within the configured bounds.")
    known = {item["id"] for item in plan["candidates"]}
    if identifiers and set(identifiers) - known:
        raise SafetyError("Unknown review candidate ID")
    for item in plan["candidates"]:
        if identifiers and item["id"] not in identifiers:
            continue
        print("%s  %s  %-14s  %10s  %s" % (item["id"], "READY " if item["eligible"] else "REVIEW", item["kind"], human(item["fingerprint"]["allocated"]), clean(item["path"])))
        if full:
            for line in details(item):
                print("  " + line)
            print()
        elif item["blockers"]:
            print("  " + clean(item["blockers"][0]))
        elif item["context"].get("keeper"):
            print("  Protected keeper: " + clean(item["context"]["keeper"]))
    print("\nEstimates are not promised savings: APFS clones, compression and snapshots affect reclamation.")


def typed(expected, supplied):
    if supplied is not None:
        return supplied
    print("Required exact approval: " + expected)
    if not sys.stdin.isatty():
        raise SafetyError("No interactive terminal. Pass --approve with the exact displayed phrase after review.")
    try:
        return input("Type it exactly (Ctrl-C cancels): ")
    except EOFError as exc:
        raise SafetyError("Approval cancelled") from exc


def selected(values):
    return [part.strip() for value in values for part in value.split(",") if part.strip()]


def main(argv=None):
    arguments = parser().parse_args(argv)
    arguments.command = arguments.command or "tui"
    try:
        if arguments.command == "config":
            data = defaults()
            if arguments.output:
                export(arguments.output, data)
            else:
                output_json(data)
            return 0
        if arguments.command == "demo":
            output_json(create(arguments.destination))
            return 0
        if arguments.command == "storage" and arguments.json:
            from .measurement import measure, capacities
            if not 1 <= arguments.max_files <= 1000000 or not 1 <= arguments.max_depth <= 64:
                raise SafetyError("Storage bounds must be positive (files <= 1000000; depth <= 64)")
            node = measure(arguments.path, arguments.max_files, arguments.max_depth, storage=True,
                           independent_children=canonical(arguments.path) == Path("/"))
            output_json({"measurement": node.export(), "filesystems": capacities("/"), "note": "Metadata only; incomplete totals are lower bounds; no deletion rights"})
            return 0
        # Reject a non-TTY TUI before scanning or creating state.
        if (getattr(arguments, "tui", False) or arguments.command in {"tui", "storage"}) and (not sys.stdin.isatty() or not sys.stdout.isatty()):
            raise SafetyError("TUI requires an interactive terminal. Use textual review --details or scan --output.")
        if arguments.command == "storage":
            config = read_config(arguments.config, arguments.state, validate_now=False)
            config["storage_max_files"] = arguments.max_files
            config["storage_max_depth"] = arguments.max_depth
            config = validate(config, arguments.state)
            return review(None, State(arguments.state).prepare(), config=config, storage_root=arguments.path, initial_tab="storage")
        state = State(arguments.state).prepare()
        if arguments.command == "history":
            from .history import History
            from .measurement import measure, capacities
            config = read_config(arguments.config, state.path, validate_now=False)
            if arguments.history_action == "capture":
                for argument, key in (("max_files", "storage_max_files"), ("max_depth", "storage_max_depth")):
                    if getattr(arguments, argument) is not None:
                        config[key] = getattr(arguments, argument)
            config = validate(config, state.path)
            history = History(state, config)
            if arguments.history_action == "capture":
                node = measure(arguments.path, config['storage_max_files'], config['storage_max_depth'], storage=True,
                               independent_children=canonical(arguments.path) == Path('/'))
                output_json(history.capture(node, capacities('/')))
            elif arguments.history_action == "list":
                output_json(history.list())
            elif arguments.history_action == "compare":
                output_json(history.compare(arguments.earlier, arguments.later, arguments.metric))
            else:
                output_json(history.clear())
            return 0
        if arguments.command == "tui":
            config = read_config(arguments.config, state.path)
            return review(None, state, config=config)
        if arguments.command == "scan":
            # Apply explicit replacements before validating default roots.
            config = read_config(arguments.config, state.path, validate_now=False)
            if arguments.no_defaults:
                supplied = {}
                if arguments.config:
                    with open(arguments.config, "r", encoding="utf-8") as stream:
                        supplied = json.load(stream)
                for key in ("repo_roots", "worktree_roots", "duplicate_roots", "cache_roots", "app_roots", "app_data_roots"):
                    if key not in supplied:
                        config[key] = []
                if "system_reports" not in supplied:
                    config["system_reports"] = False
            for flag, key in (("repo_root", "repo_roots"), ("worktree_root", "worktree_roots"), ("duplicate_root", "duplicate_roots"), ("cache_root", "cache_roots")):
                value = getattr(arguments, flag)
                if value is not None:
                    config[key] = value
            for key in ("repo_days", "cache_days", "max_files", "max_depth"):
                value = getattr(arguments, key)
                if value is not None:
                    config[key] = value
            config = validate(config, state.path)
            if arguments.tui:
                return review(None, state, config=config, output=arguments.output)
            with state.lock():
                plan = Scanner(config, state).run()
                envelope = state.sign(plan)
                if arguments.output:
                    export(arguments.output, envelope)
            if arguments.json:
                output_json(envelope)
            else:
                show(plan)
                if arguments.output:
                    print("Signed plan: " + clean(canonical(arguments.output)))
            if arguments.tui:
                return review(plan, state)
            return 0
        executor = Executor(state)
        if arguments.command in {"review", "dry-run", "apply"}:
            plan = load_manifest(arguments.manifest, state)
            if arguments.command == "review":
                if arguments.tui:
                    return review(plan, state)
                show(plan, arguments.id, arguments.details)
            elif arguments.command == "dry-run":
                output_json(executor.dry_run(plan, selected(arguments.select)))
            else:
                identifiers = selected(arguments.select)
                items = selection(plan, identifiers)
                expected = approval_for(plan, items)
                approval = typed(expected, arguments.approve)
                result = executor.apply(plan, identifiers, approval)
                output_json(result)
                return 2 if any(row["status"] == "blocked" for row in result["outcomes"]) else 0
        elif arguments.command == "quarantine":
            records = executor.list()
            if arguments.json:
                output_json(records)
            elif not records:
                print("Quarantine is empty. No items have been moved.")
            else:
                for record in records:
                    print("%s  %-12s %s" % (record["id"], record["status"], clean(record["original"])))
                    if record["status"] in {"quarantined", "purging"}:
                        print("  Second approval to delete: " + executor.purge_approval(record))
                print("Quarantine frees 0 bytes. Restore keeps data; purge permanently removes approved owned items.")
        elif arguments.command == "restore":
            output_json(executor.restore(arguments.id))
        elif arguments.command == "purge":
            with state.lock():
                executor.recover()
                record = executor._record(arguments.id)
                expected = executor.purge_approval(record)
            approval = typed(expected, arguments.approve)
            output_json(executor.purge(arguments.id, approval))
        return 0
    except (SafetyError, OSError, ValueError, KeyError, TypeError) as exc:
        print("MacTrim blocked: " + clean(exc), file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nMacTrim cancelled. Interrupted moves are recovered from the durable journal on the next quarantine list.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
