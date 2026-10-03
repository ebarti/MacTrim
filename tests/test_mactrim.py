import copy
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from mactrim.activity import Activity, parse_lsof, snapshot
from mactrim.config import read_config
from mactrim.demo import create
from mactrim.executor import Executor, approval_for, selection
from mactrim.safety import (Budget, SafetyError, clean, directory_fd, file_hash,
                           fingerprint, rename_exclusive)
from mactrim.scanner import Scanner, git
from mactrim.state import State, load_manifest

COMPLETE = Activity(True)


class Fixtures(unittest.TestCase):
    def setUp(self):
        evidence = Path.cwd() / "evidence"
        evidence.mkdir(mode=0o700, exist_ok=True)
        if evidence.is_symlink() or not evidence.is_dir() or evidence.stat().st_uid != os.getuid():
            raise RuntimeError("Fixture parent must be a real directory owned by the test user")
        self.temporary = Path(tempfile.mkdtemp(prefix="test-", dir=evidence))
        self.root = self.temporary / "fixture"
        create(self.root)
        self.state = State(self.root / "state").prepare()
        self.config = read_config(self.root / "config.json", self.state.path)
        self.plan = Scanner(self.config, self.state, COMPLETE).run()
        self.executor = Executor(self.state, activity_provider=lambda: COMPLETE)

    def tearDown(self):
        # Only this test's freshly-created disposable root is removed.
        shutil.rmtree(self.temporary)

    def item(self, kind="duplicate"):
        matches = [item for item in self.plan["candidates"] if item["kind"] == kind and item["eligible"]]
        self.assertTrue(matches, [(item["kind"], item["blockers"]) for item in self.plan["candidates"]])
        return matches[0]

    def move(self, item=None, executor=None):
        item = item or self.item()
        executor = executor or self.executor
        result = executor.apply(self.plan, [item["id"]], approval_for(self.plan, [item]))
        self.assertEqual(result["outcomes"][0]["status"], "quarantined", result)
        self.assertEqual(result["quarantine_frees_bytes"], 0)
        return result["outcomes"][0]["id"]

    def fixture_commit(self, repo):
        env = dict(os.environ, GIT_AUTHOR_DATE="2020-01-01T00:00:00+0000", GIT_COMMITTER_DATE="2020-01-01T00:00:00+0000")
        subprocess.run(["/usr/bin/git", "-C", str(repo), "-c", "user.name=Fixture", "-c", "user.email=test@invalid.example", "commit", "-qm", "Fixture change"], check=True, capture_output=True, env=env)

    def test_discovery_provenance_reports_duplicates_and_no_hardlinks(self):
        self.assertEqual(self.plan["issues"], [])
        kinds = {item["kind"] for item in self.plan["candidates"]}
        self.assertTrue({"repo-artifact", "duplicate", "possible-remnant", "older-app", "unique-artifact", "user-cache"} <= kinds)
        duplicates = [item for item in self.plan["candidates"] if item["kind"] == "duplicate"]
        self.assertEqual(len(duplicates), 2)
        self.assertTrue(all(item["context"]["keeper"].endswith("01-keeper.txt") for item in duplicates))
        self.assertFalse(any("linked-" in item["path"] or item["path"].endswith(".sqlite") for item in self.plan["candidates"]))
        reports = [item for item in self.plan["candidates"] if item["kind"] in {"possible-remnant", "older-app", "unique-artifact"}]
        self.assertTrue(all(not item["eligible"] for item in reports))

    def test_signed_manifest_tampering_and_foreign_state(self):
        path = self.root / "plan.json"
        envelope = self.state.sign(self.plan)
        path.write_text(json.dumps(envelope))
        self.assertEqual(load_manifest(path, self.state), self.plan)
        envelope["body"]["candidates"][0]["eligible"] = True
        path.write_text(json.dumps(envelope))
        with self.assertRaisesRegex(SafetyError, "altered"):
            load_manifest(path, self.state)
        foreign = State(self.root / "foreign-state").prepare()
        with self.assertRaises(SafetyError):
            load_manifest(path, foreign)

    def test_malformed_manifests_fail_closed(self):
        path = self.root / "plan.json"
        for value in ([], {}, {"body": {}, "signature": "x"}, self.state.sign({"schema": "v999"}), self.state.sign(dict(self.plan, candidates=[None]))):
            path.write_text(json.dumps(value))
            with self.assertRaises(SafetyError):
                load_manifest(path, self.state)

    def test_no_default_selection_or_report_selection(self):
        with self.assertRaisesRegex(SafetyError, "explicit"):
            selection(self.plan, [])
        report = next(item for item in self.plan["candidates"] if not item["eligible"])
        with self.assertRaisesRegex(SafetyError, "Report-only"):
            selection(self.plan, [report["id"]])

    def test_exact_approval_and_zero_bytes_before_purge(self):
        item = self.item()
        with self.assertRaisesRegex(SafetyError, "Exact approval"):
            self.executor.apply(self.plan, [item["id"]], "yes")
        self.assertTrue(Path(item["path"]).exists())
        result = self.executor.dry_run(self.plan, [item["id"]])
        self.assertEqual(result["quarantine_frees_bytes"], 0)
        self.assertTrue(Path(item["path"]).exists())

    def test_apply_restore_original_hash(self):
        item = self.item()
        expected = file_hash(item["path"])
        identifier = self.move(item)
        self.assertFalse(Path(item["path"]).exists())
        record = self.executor.list()[0]
        self.assertEqual(record["status"], "quarantined")
        self.assertEqual(file_hash(record["quarantine"]), expected)
        self.assertEqual(self.executor.restore(identifier)["status"], "restored")
        self.assertEqual(file_hash(item["path"]), expected)
        self.assertFalse(Path(record["quarantine"]).exists())

    def test_restore_never_overwrites_conflict(self):
        item = self.item()
        identifier = self.move(item)
        Path(item["path"]).write_text("New unique data")
        with self.assertRaisesRegex(SafetyError, "destination exists"):
            self.executor.restore(identifier)
        self.assertEqual(Path(item["path"]).read_text(), "New unique data")
        self.assertTrue(Path(self.executor.list()[0]["quarantine"]).exists())

    def test_second_approval_purge_bounds(self):
        item = self.item()
        keeper = Path(item["context"]["keeper"])
        identifier = self.move(item)
        record = self.executor.list()[0]
        with self.assertRaisesRegex(SafetyError, "Second exact"):
            self.executor.purge(identifier, record["approval"])
        self.assertTrue(Path(record["quarantine"]).exists())
        self.assertEqual(self.executor.purge(identifier, self.executor.purge_approval(record))["status"], "purged")
        self.assertFalse(Path(record["quarantine"]).exists())
        self.assertTrue(keeper.exists())
        with self.assertRaises(SafetyError):
            self.executor.purge("../../elsewhere", "yes")

    def test_purge_altered_quarantine_retains_data(self):
        identifier = self.move()
        record = self.executor.list()[0]
        Path(record["quarantine"]).write_text("New data")
        with self.assertRaisesRegex(SafetyError, "changed"):
            self.executor.purge(identifier, self.executor.purge_approval(record))
        self.assertEqual(Path(record["quarantine"]).read_text(), "New data")

    def test_duplicate_keeper_changed_before_move_and_before_purge(self):
        item = self.item()
        keeper = Path(item["context"]["keeper"])
        keeper.write_text("Changed equivalent")
        with self.assertRaisesRegex(SafetyError, "content/keeper changed"):
            self.executor.dry_run(self.plan, [item["id"]])
        self.assertTrue(Path(item["path"]).exists())
        self.plan = Scanner(self.config, self.state, COMPLETE).run()
        # Restore original fixture content and rescan to establish a fresh equivalence.
        keeper.write_bytes(Path(item["path"]).read_bytes())
        self.plan = Scanner(self.config, self.state, COMPLETE).run()
        item = self.item()
        identifier = self.move(item)
        keeper.write_text("Keeper disappeared semantically")
        record = self.executor.list()[0]
        with self.assertRaisesRegex(SafetyError, "keeper changed"):
            self.executor.purge(identifier, self.executor.purge_approval(record))
        self.assertTrue(Path(record["quarantine"]).exists())

    def test_changed_descendant_even_with_restored_mtime(self):
        item = self.item("repo-artifact")
        artifact = Path(item["path"])
        file = next(path for path in artifact.rglob("*") if path.is_file())
        original = file.stat()
        file.write_bytes(b"x" * original.st_size)
        os.utime(file, ns=(original.st_atime_ns, original.st_mtime_ns))
        with self.assertRaisesRegex(SafetyError, "descendant changed"):
            self.executor.dry_run(self.plan, [item["id"]])
        self.assertTrue(artifact.exists())

    def test_symlink_candidate_swap(self):
        item = self.item()
        original = Path(item["path"])
        real = original.with_name("moved-real.txt")
        original.rename(real)
        original.symlink_to(real)
        with self.assertRaises(SafetyError):
            self.executor.dry_run(self.plan, [item["id"]])
        self.assertTrue(real.exists())

    def test_symlink_ancestor_swap(self):
        item = self.item()
        parent = Path(item["path"]).parent
        saved = parent.with_name("moved-duplicates")
        parent.rename(saved)
        parent.symlink_to(saved, target_is_directory=True)
        with self.assertRaises(SafetyError):
            self.executor.dry_run(self.plan, [item["id"]])
        self.assertTrue((saved / Path(item["path"]).name).exists())

    def test_new_active_project_process_blocks_all_repo_artifacts(self):
        item = self.item("repo-artifact")
        repo = item["context"]["repo"]
        active = Activity(True, paths=[(12345, "fixture-worker", str(Path(repo) / "weather.py"), "3")])
        executor = Executor(self.state, activity_provider=lambda: active)
        with self.assertRaisesRegex(SafetyError, "Active PID"):
            executor.dry_run(self.plan, [item["id"]])
        self.assertTrue(Path(item["path"]).exists())

    def test_incomplete_lsof_blocks_mutation(self):
        item = self.item()
        executor = Executor(self.state, activity_provider=lambda: Activity(False, issues=["lsof missed process"]))
        with self.assertRaisesRegex(SafetyError, "incomplete"):
            executor.dry_run(self.plan, [item["id"]])

    def test_git_tracked_data_blocks_artifact_and_duplicate(self):
        item = self.item("repo-artifact")
        repo = Path(item["context"]["repo"])
        child = next(path for path in Path(item["path"]).rglob("*") if path.is_file())
        subprocess.run(["/usr/bin/git", "-C", str(repo), "add", "-f", "--", str(child)], check=True, capture_output=True)
        self.fixture_commit(repo)
        with self.assertRaisesRegex(SafetyError, "tracked data"):
            self.executor.dry_run(self.plan, [item["id"]])
        # Tracked files inside a duplicate root are also protected.
        self.config["duplicate_roots"] = [str(repo)]
        new_plan = Scanner(self.config, self.state, COMPLETE).run()
        self.assertFalse(any(row["kind"] == "duplicate" and row["path"] == str(child) for row in new_plan["candidates"]))

    def test_ignored_requirement_not_just_untracked_or_old(self):
        item = self.item("repo-artifact")
        repo = Path(item["context"]["repo"])
        ignore = repo / ".gitignore"
        ignore.write_text("")
        subprocess.run(["/usr/bin/git", "-C", str(repo), "add", ".gitignore"], check=True, capture_output=True)
        self.fixture_commit(repo)
        with self.assertRaisesRegex(SafetyError, "not proven Git-ignored"):
            self.executor.dry_run(self.plan, [item["id"]])

    def test_overlap_and_keeper_selection(self):
        item = self.item()
        second = copy.deepcopy(item)
        second["id"] = "other"
        second["path"] = str(Path(item["path"]).parent)
        altered = dict(self.plan, candidates=self.plan["candidates"] + [second])
        with self.assertRaisesRegex(SafetyError, "Overlapping"):
            selection(altered, [item["id"], "other"])
        second["path"] = item["context"]["keeper"]
        with self.assertRaisesRegex(SafetyError, "keeper"):
            selection(altered, [item["id"], "other"])

    def test_budget_and_permissions_are_visible_and_block_eligibility(self):
        config = dict(self.config, max_files=1)
        result = Scanner(config, self.state, COMPLETE).run()
        self.assertTrue(result["issues"])
        self.assertTrue(any("budget" in issue.lower() for issue in result["issues"]))
        self.assertFalse(any(item["eligible"] for item in result["candidates"]))
        cache = self.root / "caches" / "pip" / "http-v2"
        cache.chmod(0)
        try:
            result = Scanner(self.config, self.state, COMPLETE).run()
            self.assertTrue(any(any(word in issue.lower() for word in ("incomplete", "inaccessible", "permission")) for issue in result["issues"]))
            self.assertFalse(any(item["eligible"] for item in result["candidates"]))
        finally:
            cache.chmod(0o700)

    def test_crash_after_atomic_move_recovers_journal(self):
        item = self.item()
        def crash(event, record):
            if event == "after_move":
                raise SystemExit("simulated power loss")
        executor = Executor(self.state, activity_provider=lambda: COMPLETE, crash_hook=crash)
        with self.assertRaises(SystemExit):
            executor.apply(self.plan, [item["id"]], approval_for(self.plan, [item]))
        self.assertFalse(Path(item["path"]).exists())
        self.assertEqual(self.state.journals()[0]["status"], "pending")
        records = self.executor.list()
        self.assertEqual(records[0]["status"], "quarantined")
        self.executor.restore(records[0]["id"])
        self.assertTrue(Path(item["path"]).exists())

    def test_crash_before_move_aborts_without_touching_source(self):
        item = self.item()
        def crash(event, record):
            if event == "before_move":
                raise SystemExit()
        executor = Executor(self.state, activity_provider=lambda: COMPLETE, crash_hook=crash)
        with self.assertRaises(SystemExit):
            executor.apply(self.plan, [item["id"]], approval_for(self.plan, [item]))
        self.assertTrue(Path(item["path"]).exists())
        self.assertEqual(self.executor.list()[0]["status"], "aborted")

    def test_crash_after_restore_recovers(self):
        identifier = self.move()
        def crash(event, record):
            if event == "after_restore":
                raise SystemExit()
        executor = Executor(self.state, activity_provider=lambda: COMPLETE, crash_hook=crash)
        with self.assertRaises(SystemExit):
            executor.restore(identifier)
        self.assertEqual(self.executor.list()[0]["status"], "restored")

    def test_crash_partial_purge_subset_and_new_descendant_guard(self):
        item = self.item("repo-artifact")
        identifier = self.move(item)
        record = self.executor.list()[0]
        quarantined = Path(record["quarantine"])
        if quarantined.name == "__pycache__":
            self.fail("Fixture should choose .venv first")
        first = next(path for path in quarantined.rglob("*") if path.is_file())
        first.unlink()  # Simulate interrupted deletion after durable purging intent.
        record["status"] = "purging"
        self.state.write_journal(record)
        unexpected = quarantined / "new-unique.txt"
        unexpected.write_text("Never delete this unexpected data")
        with self.assertRaisesRegex(SafetyError, "Unexpected descendant"):
            self.executor.purge(identifier, self.executor.purge_approval(record))
        self.assertTrue(unexpected.exists())
        unexpected.unlink()  # disposable fixture's own newly-created test data
        self.assertEqual(self.executor.purge(identifier, self.executor.purge_approval(record))["status"], "purged")

    def test_state_symlink_wrong_mode_and_lock(self):
        other = self.root / "link-state"
        other.symlink_to(self.state.path, target_is_directory=True)
        with self.assertRaises(SafetyError):
            State(other).prepare()
        self.state.path.chmod(0o755)
        try:
            with self.assertRaisesRegex(SafetyError, "private"):
                self.state.verify()
        finally:
            self.state.path.chmod(0o700)
        with self.state.lock():
            with self.assertRaisesRegex(SafetyError, "holds the state lock"):
                with self.state.lock():
                    pass

    def test_exclusive_rename_never_clobbers(self):
        a, b = self.root / "source", self.root / "target"
        a.write_text("source")
        b.write_text("target")
        with directory_fd(self.root) as fd:
            with self.assertRaises(SafetyError):
                rename_exclusive(fd, a.name, fd, b.name)
        self.assertEqual(a.read_text(), "source")
        self.assertEqual(b.read_text(), "target")

    def test_oversized_journal_blocks_whole_selection_before_rename(self):
        items = [item for item in self.plan["candidates"] if item["kind"] == "duplicate"]
        with patch("mactrim.state.MAX_JOURNAL_BYTES", 1024):
            with self.assertRaisesRegex(SafetyError, "recoverable size bound"):
                self.executor.apply(self.plan, [item["id"] for item in items], approval_for(self.plan, items))
            with self.assertRaisesRegex(SafetyError, "recoverable size bound"):
                self.executor.dry_run(self.plan, [items[0]["id"]])
        self.assertTrue(all(Path(item["path"]).exists() for item in items))
        self.assertFalse(any((self.state.path / "quarantine").iterdir()))
        self.assertEqual(self.state.journals(), [])

    def test_journal_reserves_completion_capacity_and_single_inventory(self):
        item = self.item()
        ancestors, current = self.executor._validate(self.plan, item, COMPLETE)
        record = self.executor._intent(self.plan, item, approval_for(self.plan, [item]), ancestors, current, "0" * 32)
        self.assertNotIn("fingerprint", record["candidate"])
        from mactrim.safety import json_bytes
        size = len(json_bytes(self.state.sign(record)))
        with patch("mactrim.state.MAX_JOURNAL_BYTES", size + 100), patch("mactrim.state.JOURNAL_COMPLETION_RESERVE", 101):
            with self.assertRaisesRegex(SafetyError, "recoverable size bound"):
                self.state.write_journal(record)
        self.assertEqual(self.state.journals(), [])

    def test_same_length_root_rewrite_restored_mtime_cannot_be_purged(self):
        identifier = self.move()
        record = self.executor.list()[0]
        path = Path(record["quarantine"])
        original = path.stat()
        path.write_bytes(b"X" * original.st_size)
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        with self.assertRaisesRegex(SafetyError, "changed"):
            self.executor.purge(identifier, self.executor.purge_approval(record))
        self.assertTrue(path.exists())
        self.assertEqual(path.read_bytes(), b"X" * original.st_size)

    def test_same_length_root_rewrite_cannot_be_restored(self):
        identifier = self.move()
        record = self.executor.list()[0]
        path = Path(record["quarantine"])
        original = path.stat()
        path.write_bytes(b"X" * original.st_size)
        os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        with self.assertRaisesRegex(SafetyError, "fingerprint changed"):
            self.executor.restore(identifier)
        self.assertTrue(path.exists())
        self.assertFalse(Path(record["original"]).exists())

    def test_same_length_source_rewrite_after_validation_cannot_move(self):
        item = self.item()
        path = Path(item["path"])
        def change(event, record):
            if event == "before_move":
                original = path.stat()
                path.write_bytes(b"X" * original.st_size)
                os.utime(path, ns=(original.st_atime_ns, original.st_mtime_ns))
        executor = Executor(self.state, activity_provider=lambda: COMPLETE, crash_hook=change)
        result = executor.apply(self.plan, [item["id"]], approval_for(self.plan, [item]))
        self.assertEqual(result["outcomes"][0]["status"], "blocked")
        self.assertTrue(path.exists())
        self.assertFalse(any((self.state.path / "quarantine").iterdir()))

    def test_new_descendant_at_final_purge_boundary_is_preserved(self):
        identifier = self.move(self.item("repo-artifact"))
        record = self.executor.list()[0]
        from mactrim.safety import remove_tree_fd as real_remove
        unique = Path(record["quarantine"]) / "new-unique-report.txt"
        def insert_then_remove(fd, name, approved):
            unique.write_text("Preserve this unapproved report")
            return real_remove(fd, name, approved)
        with patch("mactrim.executor.remove_tree_fd", side_effect=insert_then_remove):
            with self.assertRaisesRegex(SafetyError, "Unexpected descendant"):
                self.executor.purge(identifier, self.executor.purge_approval(record))
        self.assertTrue(unique.exists())
        self.assertEqual(unique.read_text(), "Preserve this unapproved report")
        self.assertEqual(self.state.journals()[0]["status"], "purging")

    def test_cache_fingerprints_share_scan_budget(self):
        root = self.root / "tiny-caches"
        for name in ("pip", "uv"):
            path = root / name
            path.mkdir(parents=True)
            (path / "a.cache").write_text("old")
            old = time.time() - 180 * 86400
            os.utime(path / "a.cache", (old, old))
            os.utime(path, (old, old))
        config = dict(self.config, repo_roots=[], duplicate_roots=[], app_roots=[], app_data_roots=[], cache_roots=[str(root)], max_files=3)
        scanner = Scanner(config, self.state, COMPLETE)
        plan = scanner.run()
        self.assertGreater(scanner.budget.used, 3)
        self.assertTrue(any("budget" in issue.lower() for issue in plan["issues"]))
        self.assertFalse(any(item["eligible"] for item in plan["candidates"]))

    def test_hardlink_fingerprint_refusal_and_terminal_sanitizing(self):
        path = self.root / "duplicates" / "linked-a.txt"
        with self.assertRaisesRegex(SafetyError, "Hard-linked"):
            fingerprint(path)
        text = clean("name\x1b[2J\n\r\u202efile")
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\n", text)
        self.assertNotIn("\u202e", text)
        self.assertIn("\\u001b", text)

    def test_credentials_and_env_variants_are_never_hashed_or_candidates(self):
        root = self.root / "credentials-fixture"
        for directory in ("a", "b"):
            (root / directory).mkdir(parents=True)
            for filename in (".env", ".env.local", ".env.production", "auth.json", ".netrc", ".npmrc", "credentials.json", "id_rsa"):
                (root / directory / filename).write_text("FAKE_FIXTURE_TOKEN=never-a-real-secret")
        config = dict(self.config, repo_roots=[], cache_roots=[], app_roots=[], app_data_roots=[], duplicate_roots=[str(root)])
        with patch("mactrim.scanner.file_hash", side_effect=AssertionError("Protected credential content must not be read")):
            result = Scanner(config, self.state, COMPLETE).run()
        self.assertEqual(result["candidates"], [])

    def test_active_environment_argv_blocks_despite_global_executable(self):
        item = self.item("repo-artifact")
        repo = item["context"]["repo"]
        # Original failure: cwd is outside project, binary symlink resolves globally,
        # startup files are closed. ps command still names the actual env invocation.
        active = Activity(True, paths=[(12345, "Python", "/private/tmp", "cwd"), (12345, "Python", "/usr/bin/python3", "txt")], commands={12345: str(Path(repo) / ".venv" / "bin" / "python") + " -c 'import time; time.sleep(30)'"})
        self.assertTrue(active.blockers(repo))
        executor = Executor(self.state, activity_provider=lambda: active)
        with self.assertRaisesRegex(SafetyError, "argv references"):
            executor.dry_run(self.plan, [item["id"]])
        self.assertTrue(Path(item["path"]).exists())

    def test_non_tty_tui_friendly_failure(self):
        result = subprocess.run([sys_executable(), "-m", "mactrim", "--state", str(self.root / "unused-state"), "scan", "--no-defaults", "--tui"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertIn("interactive terminal", result.stderr)
        self.assertFalse((self.root / "unused-state").exists())


class ActivityParser(unittest.TestCase):
    def test_valid_complete_snapshot_has_cwd_open_and_executable(self):
        data = b"p10\0ctest\0\nfcwd\0tDIR\0n/fixture\0\nftxt\0tREG\0n/fixture/bin/python\0\nf3\0tREG\0n/fixture/cache/a\0\n"
        result = parse_lsof(data, {10})
        self.assertTrue(result.complete, result.issues)
        self.assertEqual(len(result.paths), 3)
        self.assertEqual(len(result.blockers("/fixture")), 3)
        self.assertFalse(result.blockers("/fixture2"))

    def test_missing_cwd_truncation_error_and_missing_process_fail_closed(self):
        for data, pids, stderr, code in ((b"p10\0ctest\0\n", {10}, b"", 0), (b"p10\0fcwd\0n/fixture", {10}, b"", 0), (b"p10\0fcwd\0tDIR\0n/fixture\0\n", {10, 11}, b"", 0), (b"p10\0fcwd\0tDIR\0n/fixture\0\n", {10}, b"permission", 1)):
            self.assertFalse(parse_lsof(data, pids, stderr, code).complete)

    def test_revoked_only_known_non_filesystem_types_can_be_ignored(self):
        base = b"p10\0ctest\0\nfcwd\0tDIR\0n/fixture\0\nf3\0"
        for kind in (b"CHR", b"KQUEUE"):
            self.assertTrue(parse_lsof(base + b"t" + kind + b"\0n(revoked)\0\n", {10}).complete)
        for kind in (b"REG", b"DIR", b"?"):
            self.assertFalse(parse_lsof(base + b"t" + kind + b"\0n(revoked)\0\n", {10}).complete)

    def test_unresolved_regular_or_directory_name_fails_closed(self):
        base = b"p10\0ctest\0\nfcwd\0tDIR\0n/fixture\0\nf3\0"
        for kind in (b"REG", b"DIR"):
            self.assertFalse(parse_lsof(base + b"t" + kind + b"\0n(unknown)\0\n", {10}).complete)

    def test_missing_descriptor_names_fail_at_next_fd_pid_and_eof(self):
        base = b"p10\0ctest\0\nfcwd\0tDIR\0n/fixture\0\n"
        for kind in (b"REG", b"DIR"):
            incomplete = base + b"f3\0t" + kind + b"\0\n"
            for suffix in (b"", b"f4\0tCHR\0n/dev/null\0\n", b"p11\0cnext\0\nfcwd\0tDIR\0n/fixture\0\n"):
                self.assertFalse(parse_lsof(incomplete + suffix, {10}).complete)

    def test_process_birth_is_not_hidden_by_stable_intersection(self):
        output = b"p10\0ctest\0\nfcwd\0tDIR\0n/fixture\0\n"
        result = subprocess.CompletedProcess([], 0, output, b"")
        with patch("mactrim.activity.sys.platform", "darwin"), patch("mactrim.activity._pids", side_effect=[{10}, {10, 11}]), patch("mactrim.activity.subprocess.run", return_value=result):
            observed = snapshot()
        self.assertFalse(observed.complete)
        self.assertTrue(any("missed" in issue for issue in observed.issues))


def sys_executable():
    import sys
    return sys.executable


if __name__ == "__main__":
    unittest.main()
