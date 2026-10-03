"""Explicit approval, independent revalidation, atomic quarantine and recovery."""
import os
from pathlib import Path
import secrets
import stat
import time

from . import activity
from .safety import (Budget, SafetyError, ancestor_identity, canonical, clean, digest,
                     directory_fd, file_hash, fingerprint, overlap, protected,
                     remove_tree_fd, rename_exclusive)
from .scanner import apps_inventory, validate_policy


def approval_for(plan, items):
    token = digest([plan["schema"], plan["created_at"],
                    [[item["id"], item["fingerprint"]["digest"]] for item in sorted(items, key=lambda row: row["id"])]])[:12]
    return "QUARANTINE %s %s" % (len(items), token)


def selection(plan, identifiers):
    if not identifiers:
        raise SafetyError("Select one or more explicit candidate IDs; nothing is selected by default")
    if len(identifiers) != len(set(identifiers)):
        raise SafetyError("Repeated selection ID")
    found = {item["id"]: item for item in plan["candidates"]}
    if any(identifier not in found for identifier in identifiers):
        raise SafetyError("Unknown candidate ID")
    items = [found[identifier] for identifier in identifiers]
    for index, item in enumerate(items):
        if not item.get("eligible") or item.get("blockers"):
            raise SafetyError("Report-only candidate is unselectable: " + clean(item["path"]))
        if any(overlap(item["path"], other["path"]) for other in items[:index]):
            raise SafetyError("Overlapping selected paths")
        for other in items:
            if other["kind"] == "duplicate" and overlap(item["path"], other["context"]["keeper"]):
                raise SafetyError("A duplicate keeper cannot be included in the selection")
    return items


def _fp(path, state, config, quarantine=False, algorithm=None, allow_app_data=False):
    if algorithm == "git-worktree.v1":
        from .worktrees import worktree_fingerprint
        return worktree_fingerprint(path, config, quarantine)
    return fingerprint(path, Budget(config["max_files"], config["max_depth"]), allow_app_data=allow_app_data,
                       inspect_protected=not quarantine, state=None if quarantine else state.path)


def _free(path):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize


def _matches(path, expected, state, config, quarantine=False):
    return _fp(path, state, config, quarantine, expected.get("algorithm"), expected.get("allow_app_data", False))["digest"] == expected["digest"]


class Executor:
    def __init__(self, state, activity_provider=None, crash_hook=None):
        self.state = state
        self.activity_provider = activity_provider or activity.snapshot
        self.crash_hook = crash_hook

    def _hook(self, event, record):
        if self.crash_hook:
            self.crash_hook(event, record)

    def _activity(self):
        process = self.activity_provider()
        if not process.complete:
            raise SafetyError("Activity evidence incomplete: " + "; ".join(process.issues))
        return process

    def _validate(self, plan, item, process):
        self.state.verify()
        if plan.get("cancelled") or not plan["activity"]["complete"]:
            raise SafetyError("Original plan has incomplete scan or activity evidence; rescan")
        if time.time() - plan["created_at"] > 86400 or plan["created_at"] > time.time() + 5:
            raise SafetyError("Plan is stale or from the future; scan again (maximum age 24 hours)")
        ancestors = ancestor_identity(canonical(item["path"]).parent)
        if item["kind"] == "xcode-cache":
            _, issues = apps_inventory(plan["config"], Budget(plan["config"]["max_files"], plan["config"]["max_depth"]))
            if issues:
                raise SafetyError("Fresh app inventory is incomplete")
        current = validate_policy(item, plan["config"], self.state.path, process)
        if current["digest"] != item["fingerprint"]["digest"]:
            raise SafetyError("Candidate or descendant changed; scan again: " + clean(item["path"]))
        if current["identity"][0] != os.lstat(self.state.path / "quarantine").st_dev:
            raise SafetyError("Cross-volume quarantine is refused; choose private --state on the source volume and rescan")
        if ancestors != ancestor_identity(canonical(item["path"]).parent):
            raise SafetyError("Candidate ancestors changed during validation")
        return ancestors, current

    def _intent(self, plan, item, approval, ancestors, current, identifier):
        # The inventory is stored once, not duplicated inside candidate metadata.
        candidate_metadata = {key: value for key, value in item.items() if key != "fingerprint"}
        return {"schema": "mactrim.journal.v1", "id": identifier,
                "status": "pending", "created_at": time.time(), "updated_at": time.time(),
                "original": item["path"], "quarantine": str(self.state.path / "quarantine" / identifier),
                "fingerprint": current, "candidate": candidate_metadata, "config": plan["config"],
                "approval": approval, "plan_digest": digest(plan), "source_ancestors": ancestors,
                "free_before": _free(self.state.path), "outcomes": []}

    def dry_run(self, plan, identifiers):
        items = selection(plan, identifiers)
        with self.state.lock():
            self.recover()
            process = self._activity()
            for item in items:
                ancestors, current = self._validate(plan, item, process)
                self.state.journal_payload(self._intent(plan, item, approval_for(plan, items), ancestors, current, "0" * 32))
        return {"approval": approval_for(plan, items), "selected": [item["id"] for item in items],
                "logical": sum(item["fingerprint"]["logical"] for item in items),
                "allocated": sum(item["fingerprint"]["allocated"] for item in items),
                "quarantine_frees_bytes": 0, "note": "Quarantine frees zero bytes; purge is a separate approval"}

    def apply(self, plan, identifiers, approval):
        items = selection(plan, identifiers)
        expected = approval_for(plan, items)
        if approval != expected:
            raise SafetyError("Exact approval required: " + expected)
        results = []
        with self.state.lock():
            self.recover()
            process = self._activity()
            # Preflight the whole selection before moving any item.
            for item in items:
                ancestors, current = self._validate(plan, item, process)
                self.state.journal_payload(self._intent(plan, item, expected, ancestors, current, "0" * 32))
            free_before = _free(self.state.path)
            for item in items:
                try:
                    # Fresh snapshot per item prevents a stale multi-item preflight.
                    process = self._activity()
                    ancestors, current = self._validate(plan, item, process)
                    identifier = secrets.token_hex(16)
                    record = self._intent(plan, item, approval, ancestors, current, identifier)
                    self.state.write_journal(record)  # durable intent BEFORE rename
                    self._hook("before_move", record)
                    path = canonical(item["path"])
                    if item["kind"] == "git-worktree":
                        from .worktrees import move
                        move(record, self.state, process=process)
                    else:
                        with directory_fd(path.parent) as source_fd, directory_fd(self.state.path / "quarantine") as target_fd:
                            if ancestor_identity(path.parent) != ancestors:
                                raise SafetyError("Ancestor changed before move")
                            # Independent recheck with held source parent, then atomic exclusive move.
                            if _fp(path, self.state, plan["config"], algorithm=current.get("algorithm"), allow_app_data=item["kind"] == "retired-app-data")["digest"] != current["digest"]:
                                raise SafetyError("Candidate changed immediately before move")
                            rename_exclusive(source_fd, path.name, target_fd, identifier)
                    self._hook("after_move", record)
                    if not _matches(record["quarantine"], current, self.state, plan["config"], True):
                        record["status"] = "conflicted"
                        record["outcomes"].append("Moved object failed fingerprint verification; retained for manual recovery")
                        self.state.write_journal(record)
                        raise SafetyError("Moved object changed; retained in quarantine, no deletion authorized")
                    if ancestor_identity(path.parent) != ancestors:
                        record["status"] = "conflicted"
                        record["outcomes"].append("Source ancestors changed after move; retained for manual recovery")
                        self.state.write_journal(record)
                        raise SafetyError("Source ancestry changed after move; inspect journal")
                    record["status"] = "quarantined"
                    record["updated_at"] = time.time()
                    record["free_after"] = _free(self.state.path)
                    record["free_delta"] = record["free_after"] - record["free_before"]
                    record["outcomes"].append("Atomic move verified; quarantine frees zero bytes")
                    self.state.write_journal(record)
                    results.append({"id": identifier, "path": item["path"], "status": "quarantined", "free_delta": record["free_delta"]})
                except (OSError, SafetyError) as exc:
                    # Any completed prefix remains safely journaled; stop after the first failure.
                    results.append({"path": item["path"], "status": "blocked", "reason": clean(exc)})
                    break
            return {"outcomes": results, "free_delta_observed": _free(self.state.path) - free_before,
                    "quarantine_frees_bytes": 0, "note": "Observed free-space movement includes journal writes and unrelated filesystem activity"}

    def _record(self, identifier):
        records = self.state.journals()
        matches = [record for record in records if record["id"] == identifier]
        if len(matches) != 1:
            raise SafetyError("Unknown quarantine journal ID")
        record = matches[0]
        if record["quarantine"] != str(self.state.path / "quarantine" / identifier):
            raise SafetyError("Journal target is outside its owned quarantine slot")
        if protected(record["original"], self.state.path, allow_app_data=record["candidate"]["kind"] == "retired-app-data"):
            raise SafetyError("Journal original path is protected")
        return record

    def recover(self):
        """Reconcile intents only. Never infer authorization for deletion or overwrite."""
        self.state.verify()
        records = self.state.journals()
        for record in records:
            if record["status"] not in {"pending", "restoring", "purging"}:
                continue
            if record["candidate"]["kind"] == "git-worktree":
                try:
                    from .worktrees import reconcile
                    reconcile(record, self.state, self._activity())
                except (OSError, SafetyError) as exc:
                    record["status"] = "conflicted"
                    record["outcomes"].append("Git lifecycle needs manual inspection: " + clean(exc))
                record["updated_at"] = time.time()
                self.state.write_journal(record)
                continue
            identifier = record["id"]
            if record["quarantine"] != str(self.state.path / "quarantine" / identifier):
                raise SafetyError("Unsafe journal quarantine path")
            original = canonical(record["original"])
            quarantined = canonical(record["quarantine"])
            original_exists = os.path.lexists(original)
            quarantined_exists = os.path.lexists(quarantined)
            try:
                if record["status"] == "purging":
                    if not quarantined_exists:
                        record["status"] = "purged"
                    else:
                        # A partial purge requires a fresh second typed approval to resume.
                        continue
                elif original_exists and not quarantined_exists and _matches(original, record["fingerprint"], self.state, record["config"]):
                    record["status"] = "restored" if record["status"] == "restoring" else "aborted"
                elif quarantined_exists and not original_exists and _matches(quarantined, record["fingerprint"], self.state, record["config"], True):
                    record["status"] = "quarantined"
                else:
                    record["status"] = "conflicted"
                    record["outcomes"].append("Ambiguous interrupted operation; inspect original and quarantine manually")
            except (OSError, SafetyError):
                record["status"] = "conflicted"
                record["outcomes"].append("Interrupted operation failed safety/fingerprint check")
            record["updated_at"] = time.time()
            record["outcomes"].append("Reconciled interrupted journal intent")
            self.state.write_journal(record)
        return self.state.journals()

    def list(self):
        with self.state.lock():
            return self.recover()

    def restore(self, identifier):
        with self.state.lock():
            self.recover()
            record = self._record(identifier)
            if record["status"] != "quarantined":
                raise SafetyError("Only a verified quarantined item can be restored")
            original = canonical(record["original"])
            ancestors = ancestor_identity(original.parent)
            if os.path.lexists(original):
                raise SafetyError("Restore destination exists; no overwrite is permitted")
            process = self._activity()
            root = record["candidate"]["context"].get("repo", original)
            blockers = process.blockers(root) + process.blockers(record["quarantine"])
            if record["candidate"]["kind"] == "git-worktree":
                from .worktrees import bound_common
                context = record["candidate"]["context"]
                bound_common(context)
                blockers += process.blockers(context["admin_dir"]) + process.blockers(context["common_dir"])
            if blockers:
                raise SafetyError("; ".join(blockers))
            if not _matches(record["quarantine"], record["fingerprint"], self.state, record["config"], True):
                raise SafetyError("Quarantine fingerprint changed; restore refused")
            if os.lstat(original.parent).st_dev != os.lstat(record["quarantine"]).st_dev:
                raise SafetyError("Restore is cross-volume")
            record["status"] = "restoring"
            record["updated_at"] = time.time()
            self.state.write_journal(record)
            self._hook("before_restore", record)
            if record["candidate"]["kind"] == "git-worktree":
                from .worktrees import move
                move(record, self.state, restore=True, process=process)
            else:
                with directory_fd(self.state.path / "quarantine") as source_fd, directory_fd(original.parent) as target_fd:
                    if ancestor_identity(original.parent) != ancestors:
                        raise SafetyError("Restore ancestor changed")
                    rename_exclusive(source_fd, identifier, target_fd, original.name)
            self._hook("after_restore", record)
            if not _matches(original, record["fingerprint"], self.state, record["config"]):
                record["status"] = "conflicted"
                self.state.write_journal(record)
                raise SafetyError("Restored object changed during operation; inspect journal")
            record["status"] = "restored"
            record["updated_at"] = time.time()
            record["outcomes"].append("Restored to absent original path; no overwrite")
            self.state.write_journal(record)
            return {"id": identifier, "status": "restored", "path": str(original)}

    def purge_approval(self, record):
        return "PURGE %s %s" % (record["id"], record["fingerprint"]["digest"][:12])

    def _purge_residual(self, record):
        current = _fp(record["quarantine"], self.state, record["config"], True, record["fingerprint"].get("algorithm"))
        if record["status"] == "quarantined":
            if current["digest"] != record["fingerprint"]["digest"]:
                raise SafetyError("Quarantine changed; purge refused")
            return
        # Interrupted purge: only an identity-verified SUBSET of the original owned
        # inventory may remain. Never remove newly created/replaced descendants.
        expected = {entry[0]: entry[1:] for entry in record["fingerprint"]["records"]}
        for entry in current["records"]:
            relative, st, *tail = entry
            previous = expected.get(relative)
            if previous is None:
                raise SafetyError("Unexpected descendant after interrupted purge")
            before, *before_tail = previous
            if st[2] == stat.S_IFDIR:
                if st[:6] != before[:6] or st[9] > before[9]:
                    raise SafetyError("Directory identity changed after interrupted purge")
            elif st != before or tail != before_tail:
                raise SafetyError("File changed after interrupted purge")

    def purge(self, identifier, approval):
        with self.state.lock():
            self.recover()
            record = self._record(identifier)
            if record["status"] not in {"quarantined", "purging"}:
                raise SafetyError("Only verified owned quarantine items can be purged")
            expected = self.purge_approval(record)
            if approval != expected:
                raise SafetyError("Second exact approval required: " + expected)
            process = self._activity()
            original = record["original"]
            root = record["candidate"]["context"].get("repo", original)
            blockers = process.blockers(root) + process.blockers(record["quarantine"])
            if blockers:
                raise SafetyError("; ".join(blockers))
            if record["candidate"]["kind"] == "duplicate":
                keeper = record["candidate"]["context"]["keeper"]
                context = record["candidate"]["context"]
                if protected(keeper, self.state.path) or process.blockers(keeper):
                    raise SafetyError("Duplicate keeper is unsafe or active")
                if file_hash(record["quarantine"]) != context["sha256"]:
                    raise SafetyError("Quarantined duplicate content changed; purge refused")
                if file_hash(keeper) != context["sha256"] or not _matches(keeper, context["keeper_fingerprint"], self.state, record["config"]):
                    raise SafetyError("Duplicate keeper changed; purge refused")
            if record["candidate"]["kind"] == "retired-app-data":
                from .apps import confirmed_owner
                confirmed_owner(original, record["candidate"]["context"]["bundle_id"], record["config"], self.state.path, process)
            self._purge_residual(record)
            before = _free(self.state.path)
            record["status"] = "purging"
            record["purge_approval"] = approval
            record["updated_at"] = time.time()
            self.state.write_journal(record)
            self._hook("before_purge", record)
            if record["candidate"]["kind"] == "git-worktree":
                from .worktrees import purge
                purge(record, self.state, process)
            else:
                with directory_fd(self.state.path / "quarantine") as fd:
                    # Revalidate again after the durable intent, including root identity.
                    self._purge_residual(record)
                    remove_tree_fd(fd, identifier, record["fingerprint"]["records"])
            self._hook("after_purge", record)
            record["status"] = "purged"
            record["updated_at"] = time.time()
            record["purge_free_delta"] = _free(self.state.path) - before
            record["outcomes"].append("Exact second approval; verified owned quarantine item purged")
            self.state.write_journal(record)
            return {"id": identifier, "status": "purged", "free_delta_observed": record["purge_free_delta"],
                    "note": "Observed delta, not guaranteed reclamation; snapshots/clones/unrelated activity affect it"}
