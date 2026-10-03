# MacTrim

MacTrim helps review space on a Mac, with evidence explaining what can be regenerated or retained elsewhere. It offers a Python CLI and a keyboard review UI, a reversible same-volume quarantine, and a separately approved permanent purge.

**Quarantine frees zero bytes.** Logical and allocated sizes are estimates; APFS clones, compression, snapshots and other disk activity prevent a promised saving. MacTrim records the observed free-space delta rather than claiming it reclaimed the displayed size.

Python 3.9+ and the standard library are sufficient. Run from this directory with `python3 -m mactrim`; no global installation or dependencies are needed. Mutation requires macOS and its built-in `lsof`, `ps`, and Git for repository evidence. Help is available through `python3 -m mactrim --help` and each command's `--help`.

## Try the disposable demo

These commands create a **new, absent** fixture directory and scan only its contents. The Git repository created inside the demo is disposable, has no remote and only establishes source/reflog evidence.

```sh
python3 -m mactrim demo ./demo
python3 -m mactrim --state ./demo/state --config ./demo/config.json scan --output ./demo/plan.json
python3 -m mactrim --state ./demo/state review ./demo/plan.json --tui
python3 -m mactrim --state ./demo/state review ./demo/plan.json --details
```

The demo contains an old ignored environment and bytecode, unique reports, a recognizable pip cache, uncertain app records, two versions of an app, duplicate copies with a fixed keeper, excluded hard links, and a protected database. It uses the **real activity collector**. On a Mac with missing live-process evidence or inaccessible descriptors, those items correctly stay report-only; there is no CLI override. Run the fixture tests to exercise mutation and recovery with injected complete activity snapshots.

TUI controls: `j/k` or arrows navigate, `Space` selects an actionable item, `s` sorts by size/path, `f` cycles all/actionable/report filters, `/` searches, `d` opens full details, `[` and `]` scroll the side detail, `v` validates selection, `a` requests the exact typed move approval, and `q` exits. Nothing is selected by default. Reports cannot be selected. The detail view shows full path, evidence, blockers, keeper, regeneration/review hints and fingerprint. The terminal must be at least 60 columns by 12 rows; 95+ columns adds the side pane. A non-interactive terminal gets a friendly error and can use textual review instead.

## Scan boundaries and eligibility

The default scan targets `~/Developer`, `~/Projects`, `~/src`, and `~/Github`, `~/Library/Caches`, and a bounded inventory of `/Applications`, `/System/Applications`, `~/Applications`, and app cache/preferences/support names. Missing default directories are reported/skipped. **Duplicates have no default roots and require explicit scope.** No broad home content hashing is performed. App plist reads provide bundle metadata; Git reads establish repository activity. Duplicate content is streamed only inside the explicit duplicate roots.

Traversal never follows symlinks or crosses filesystem devices. The default shared budget is 100,000 enumerated entries, maximum depth 24, and repository discovery depth 4. Candidate fingerprint inspection counts toward the same scan budget. Permission failures, malformed app metadata, truncated evidence and budget exhaustion are visible; any incomplete scan prevents eligibility. Selection and execution have additional per-item inspection bounds. Some protected report-only inventories can remain incomplete.

```sh
python3 -m mactrim --state ./private-state scan --no-defaults \
  --repo-root "$HOME/Projects/example" \
  --duplicate-root "$HOME/Downloads/review-this-folder" \
  --max-files 20000 --max-depth 16 --output ./plan.json
python3 -m mactrim --state ./private-state review ./plan.json --details
```

`--no-defaults` clears default roots unless explicitly present in the supplied JSON config. Root flags replace their corresponding root list; repeat flags to add scopes. Configuration is JSON, supports only the fields shown by `python3 -m mactrim config`, and rejects invalid values and overlapping roots within a detector. See [config-example.json](config-example.json). Its duplicate roots are deliberately empty. `--output` creates an absent file without overwriting an existing file or symlink.

| Detector | Required evidence / behavior |
| --- | --- |
| `.venv`, `venv` | Regular `pyvenv.cfg`, project dependency specification, Git ignored status, no tracked descendants, clean source/index, and source/reflog/artifact inactivity of at least 90 days. No observed process use of any part of the project. |
| `__pycache__`, `.pytest_cache`, `.mypy_cache`, `.ruff_cache` | Same repository inactivity/ignored/tracked/source checks, project dependency specification, plus an allowlisted regenerable artifact kind. |
| `node_modules` | Same repository checks plus an npm/yarn/pnpm lockfile. Source and Git/worktree metadata are preserved. |
| User download caches | At least 30 days old, current-user ownership, no observed usage, and known layout: pip's `http`, `http-v2`, `wheels`, `selfcheck`; uv's cache tag and versioned stores; npm root only when it exclusively contains `_cacache`. Unexpected records or npm diagnostic logs keep the whole root report-only. Prefer the package manager's own cache controls. |
| Xcode DerivedData | Opt-in `--cache-root "$HOME/Library/Developer/Xcode/DerivedData"`; regular `info.plist` links to source inside configured repository roots; clean old source/reflog, old artifact, complete fresh app inventory, no project/cache use. Xcode recreates builds/indexes. |
| Duplicate files | Regular, nonempty, single-link files; size grouping, streamed SHA-256 and stable identity. Lexicographically first full path is the **fixed visible keeper**; it cannot be selected and is rehashed before move/purge. Metadata can differ even when bytes match; review it. Tracked repository source is excluded. |
| App remnants | Bundle ID absent from the bounded installed-app inventory is uncertain; external apps/plugins remain possible. Cache/preferences/support records stay report-only. |
| Older apps | Same bundle ID with older observed version; version schemes may be incomparable. Manual review only; no application removal. |
| Reports, screenshots, logs, arbitrary `dist`, `data`, `tmp` | Potentially unique evidence; report-only. Age and size are insufficient. |
| `/Library/Updates`, Apple Content Caching | Report-only; use macOS controls. No update-staging removal. |

Cloud-managed paths/placeholders, credentials (including `.env` variants, `auth.json`, netrc/npmrc, private keys), Photos/library bundles, applications, backups, Git internals, databases, system paths, simulator device data, Docker disks and VM images are protected. Hard-linked candidates are refused, so their size is never counted twice. Symlinks *inside* a regenerable artifact may be inventoried and moved as links; their targets are never followed, hashed, restored over or purged. A candidate cannot encompass MacTrim's own state. Overlapping displayed candidates are withheld, and overlapping selections or selected duplicate keepers are refused.

## Activity coverage

Before scanning and again before mutation, MacTrim compares fresh `ps` inventories with `lsof` cwd/open-file/executable records for the **current UID's live, non-zombie processes**. `ps` argv references also catch an environment's Python executable when a symlink resolves outside the project and startup files have already closed. Newly born live processes absent from `lsof` are blockers. Commands and environment variables are not exported; blockers contain a PID/app/fd or an indication that argv references the scope. The collector does not inspect environment variables.

System/other-user process visibility is outside this unprivileged check. This is a snapshot, not a guarantee against a process starting immediately afterward; use cleanup when the project/application is closed. Mutation only accepts current-user-owned objects and never elevates privileges. Unknown, inaccessible REG/DIR descriptors and missing cwd are blockers. Revoked CHR/KQUEUE descriptors are ignored only when their type is explicitly known; type resets at each descriptor. An unknown revoked handle stays blocked. `lsof` failure, stderr, timeout, malformed/truncated output, and incomplete enumeration all fail closed.

If a blocker names an app with an inaccessible or revoked descriptor, close or restart that app **manually**, then rescan. MacTrim does not stop processes or relax checks. A process that hides its environment identity from both argv and visible filesystem handles cannot be identified by this collector; the tool cannot establish total machine-wide inactivity.

## Exact approval and quarantine

A plan is signed by a private local state key and bound to schema, roots, selected IDs and fingerprints. Imported/tampered plans and plans from other states are refused. Plans expire after 24 hours. Labels in JSON never grant authority: execution re-derives provenance, age, Git status, content equivalence, ownership, permissions, process use, ancestor safety, and volume identity. Changed descendants or changed/missing keepers require a new scan.

```sh
python3 -m mactrim --state ./private-state dry-run ./plan.json --select CANDIDATE_ID
python3 -m mactrim --state ./private-state apply ./plan.json --select CANDIDATE_ID
```

Use the actual ID shown by review. Repeated `--select` flags or comma-separated IDs select several items. `dry-run` validates the complete selection and prints an exact `QUARANTINE <count> <fingerprint-token>` phrase; it moves nothing. `apply` asks you to type that phrase exactly. For deliberate automation, `--approve` accepts the exact phrase; `yes`/`--force` is not an approval. A non-interactive invocation without it fails. The approval is specific to that plan and selection.

State defaults to `~/Library/Application Support/MacTrim`. It uses owned 0700 directories and 0600 files; unsafe modes, symlink ancestors, hard-linked state files, and concurrent state locks are refused. To clean another volume, create a private state directory **on that source volume** and rescan with `--state`; cross-volume copying is unsupported. Root `/Volumes` remains a protected scope in this initial version, so external-volume cleanup is intentionally unavailable even with same-volume state. No fallback changes a safe rename into a copy or overwrite.

The executor first validates the whole selection, then rechecks before each item. Oversized journals are refused during full-selection preflight; the 32 MiB journal bound reserves 64 KiB for later completion outcomes and stores the inventory once. It writes and fsyncs per-item intent before an atomic exclusive `renameatx_np` on macOS, fsyncs both parent directories, verifies the moved object and records the result. Unrelated filesystem activity can change free space; the journal saves observed before/after values. If a multi-item operation later fails, the completed prefix stays safely quarantined and the remaining paths stay in place.

## Restore, purge and interrupted operations

```sh
python3 -m mactrim --state ./private-state quarantine list
python3 -m mactrim --state ./private-state restore JOURNAL_ID
python3 -m mactrim --state ./private-state purge JOURNAL_ID
```

Restore requires the exact verified item, safe ancestors, complete fresh activity, and an **absent original destination**; an existing file/directory/symlink is never overwritten. Purge requires a **second**, distinct exact `PURGE <journal-id> <fingerprint-token>` approval. It is restricted to the signed journal's private quarantine slot, checks original identities/content and duplicate keeper again, and only deletes approved inventory entries. Unexpected/replaced descendants are retained. No age-only or automatic purge exists.

`quarantine list` reconciles an interrupted move or restore by checking both paths and fingerprints. A crash after rename but before journal completion is recoverable; an ambiguous state becomes `conflicted` and requires manual inspection, with no automatic deletion. An interrupted purge retains `purging` status; a new exact second approval is needed to resume a verified remaining subset. New/changed descendants block resumption. Keep the entire state directory and signing key to retain recovery access; manually discarding it loses the tool's journal and restore authority.

The private state and filesystem ownership are the trust boundary: a hostile process running as your same account can read your key and alter private files. MacTrim does not claim protection from compromise of the account or filesystem. Inspection/rename/destructive syscalls cannot freeze applications or the filesystem. Use it on inactive, reviewed scopes and keep backups of unique data.

## Verification and references

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q mactrim tests
```

Tests mutate only freshly created disposable fixtures below `evidence/`. They cover metadata/content changes with restored mtime, ancestor/symlink swaps, activity coverage and argv, Git tracked/ignored rules, credential/hardlink exclusions, exact approvals, overlap/keepers, scan budgets/permissions, exclusive rename, crash recovery, restore conflicts, immutable purge bounds and partial-purge resumption. Activity injection is internal to fixture tests and cannot be selected from the CLI. Actual macOS read-only activity and actual curses PTY checks are recorded separately in delivery evidence. No actual user data was cleaned during delivery and no global installation was performed.

Use Apple's supported tools for managed storage: [Free up storage space on your Mac](https://support.apple.com/en-us/102624) and [Set up Content Caching](https://support.apple.com/guide/mac-help/set-up-content-caching-on-mac-mchl3b6c3720/mac). The UI uses Python's standard [curses](https://docs.python.org/3/library/curses.html) module.
