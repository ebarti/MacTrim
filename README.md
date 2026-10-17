# MacTrim

A colorful terminal app for evidence-led Mac cleanup, root storage exploration, and lightweight local storage history. Cleanup moves only explicitly selected, freshly validated items into same-volume quarantine. Nothing is selected initially. Quarantine frees **zero bytes**; permanent deletion requires a separate exact approval.

## Run

Python 3.9+ and macOS are required for cleanup activity evidence. Textual 8.2.8 and Rich power the native widgets. Install dependencies in the project environment:

```sh
cd /path/to/MacTrim
python3 -m venv .venv
.venv/bin/python -m pip install -e .
./mactrim-launch
```

The executable launcher works from a fresh shell and any working directory; it uses this project's `.venv` without changing global packages or shell configuration. The installed environment in this delivery uses Python 3.12. Core CLI/reporting and safety tests also support Python 3.9. `./mactrim-launch --help` lists commands. `python3 -m mactrim` remains available; native UI commands need the project dependencies.

Cleanup, Storage, and History / Growth are separate tabs. Discovery and measurement run in background workers, publish partial results, and support cancellation. Keyboard shortcuts appear in the footer. Cleanup offers search, status filter, sorting, category counts, full evidence/blockers, selected totals, fresh validation, and an exact typed approval dialog. Reports cannot be selected. Storage's chart and sortable list share measured nodes: Enter drills down; Parent, Root, Refresh, logical/allocated mode and breadcrumbs support navigation. Entry and depth controls plus “Deeper ×10” provide larger cancellable captures (up to 1,000,000 entries per root subtree and depth 64); drill into a partial region for finer attribution. These are metadata limits, independent of History’s 5000 aggregate limit. Storage and History never grant cleanup authority.

```sh
./mactrim-launch tui
./mactrim-launch storage /
./mactrim-launch storage / --json --max-files 1000 --max-depth 8
./mactrim-launch storage /private/tmp --max-files 1000000 --max-depth 64
./mactrim-launch --config config-example.json scan --tui
```

`NO_COLOR` is honored. A true-color terminal gives the richest appearance; semantic status labels remain available without colors. Small terminals retain native keyboard navigation and scrolling.

## Cleanup evidence

Repository artifacts require allowlisted regeneration, ignored/untracked contents, dependency specifications, clean source/index, source/reflog/artifact inactivity, owned no-follow paths, and complete current-user activity coverage. Recognized pip, uv and npm download caches require proven layouts and stale activity; npm logs are retained. Unknown reports, screenshots, logs, app data and update staging stay report-only. Credentials, databases, backups, cloud placeholders, protected scopes, hardlinks and special objects cannot become mutation targets merely because they are old.

Registered linked Git worktrees are a separate category, including default Codex worktree roots. A merged HEAD is stale independently of age. MacTrim proves ancestry against a resolved default target, or an authenticated GitHub merged PR with exact head and retained merge-commit proof. Local refs have explicit freshness limitations; unavailable/squash-mismatched evidence stays review-only. Primary/current, out-of-scope, dirty, untracked, meaningful ignored, active, locked, sparse, hidden-index, submodule and unique-commit worktrees are protected. Ignored Python environments need a tracked regeneration specification and recognized layout; unknown installed state is preserved. Git checkout/index/common-directory binding and common/admin identities and ancestors are checked afresh. Pointer recovery holds the captured admin descriptor and validates every remaining administrative entry, including the captured HEAD/branch, before replay writes; a replaced registry or changed metadata causes a conflict and remains intact.

App ownership includes bundle IDs, helpers/extensions, current-user services, normalized `application.<bundle>.<instance>` labels, vendor families, and observed/explicit historical human aliases. Apple/system components do not become uninstall guesses. Missing/incomplete ownership stays uncertain; live helpers and shared families retain ownership. Equal or unknown versions are duplicate app copies, not “older” versions. Preferences/support remain manual unless configuration explicitly confirms the retired owner **and exact scope**; ownership is checked again before apply and purge. App bundles and macOS update/content-caching records remain manual reports. Prefer the app's uninstaller and [Apple's storage controls](https://support.apple.com/guide/mac-help/free-up-storage-space-mh26887/mac) or [Content Caching controls](https://support.apple.com/guide/mac-help/manage-content-caching-mchl9388ba1b/mac).

Cheap metadata measurement is separate from eligible fingerprints and explicit duplicate hashing. Per-category/root/subtree budgets expose partial coverage without letting a large repository starve worktrees, caches, apps or duplicates. Unrelated partial roots do not veto a proven selected scope; cancelled plans and incomplete activity block actions. Explicit CLI overrides are applied before root validation. Storage defaults to 50,000 metadata visits per root subtree and fairly partitions its fixed budget across useful home/project/temp siblings and measures immediate files first. At `/`, up to 64 front-door children receive independent entry budgets; APFS aliases remain skipped. A large early subtree cannot consume later siblings’ reserved share. Unused quota then refines the largest partial regions, counting repeated visits against the same bound; it replaces earlier totals rather than adding them. A partial directory remains unknown for History deltas, even when refinement observes more bytes. Partial measurements describe observed bytes, not a complete disk breakdown. Increase the visible entry/depth controls or scope a smaller root when useful. Different collector/budget policies establish separate History baselines.

## Scan and signed lifecycle

```sh
./mactrim-launch --state /same-volume/private-state scan \
  --no-defaults --repo-root /explicit/projects --worktree-root /explicit/worktrees \
  --duplicate-root /explicit/duplicates --cache-root /explicit/caches \
  --output /absent/plan.json
./mactrim-launch --state /same-volume/private-state review /absent/plan.json --details
./mactrim-launch --state /same-volume/private-state dry-run /absent/plan.json --select CANDIDATE_ID
./mactrim-launch --state /same-volume/private-state apply /absent/plan.json \
  --select CANDIDATE_ID --approve 'QUARANTINE 1 EXACT_TOKEN_FROM_DRY_RUN'
./mactrim-launch --state /same-volume/private-state quarantine list
./mactrim-launch --state /same-volume/private-state restore JOURNAL_ID
./mactrim-launch --state /same-volume/private-state purge JOURNAL_ID --approve 'PURGE JOURNAL_ID EXACT_TOKEN'
```

Use the exact phrase printed by the command. Without `--approve`, an interactive terminal asks for it. Duplicate roots are opt-in, protected keepers are verified again, and overlapping selections are refused. Re-scan after upgrading old configuration/manifest contracts. Plans expire after 24 hours. Exports refuse existing paths; restore requires an absent original destination and never overwrites new data.

State is private, owned, signed and locked. Mutations independently validate the manifest, scope, ownership, ancestors, descendants, activity, immutable approved inventories and keepers. Journals are fsynced before transitions and bounded for recovery. Failed multi-item actions report any safely journaled completed prefix and stop. Interrupted operations are reconciled on quarantine list; unexpected contents or ambiguous states remain intact for manual inspection.

Worktree lifecycle uses an exclusive descriptor-anchored rename to the **exact** quarantine/restore slot. A durable private administrative snapshot and retained `refs/mactrim/recovery/<journal-id>` protect the Git registry. The selected `.git` pointer must retain its captured admin resolution after relocation; unsupported relative layouts are refused. Only the captured admin `gitdir` back-pointer is reconciled: an exclusive move preserves displaced pointer bytes, then an identity/content-verified, separately fsynced replacement enters an absent slot. Git's common-registry repair traversal is not invoked, and unrelated `.git` files/registrations remain unchanged. Ambient `GIT_*` settings, project hooks, fsmonitor and executable filters are isolated/disabled for Git queries and recovery refs.

Worktree purge deletes only the approved content inventory through held descriptors, then only the captured administrative inventory after a durable **content-purged** milestone. New/replaced entries are preserved; the admin snapshot remains private for recovery. Missing contents while merely purge-authorized are ambiguous and cannot trigger registration deletion. Branches, shared objects, recovery refs and unrelated registrations are retained; no broad prune or recursive Git removal runs. Administrative snapshots have a 64 MiB bound. Partial approved content deletion requires fresh second approval to continue; ambiguous/changed registry states require manual recovery.

Activity coverage is limited to the current UID's non-zombie processes, cwd/open/executable paths and conservative argv scope references. Bounded before/after process inventories reconcile exits and retry surviving births; persistent unknown/revoked descriptors still block mutation. This is not full-machine coverage, and another UID can use data without being observed. If lsof reports a PID/app/fd with inaccessible or missing type/name, manually close/restart that app and rescan. MacTrim has no activity bypass, no sudo and no forced app termination. TOCTOU remains possible with hostile concurrent same-user writers; private state and every supported boundary preserve unexpected contents and refuse ambiguous actions.

## Storage and small history

Storage performs metadata-only, bounded no-follow traversal, including protected/system-owned directories read-only. It never reads/hashes file contents or hydrates dataless/cloud placeholders. Inode accounting prevents hardlink/firmlink double counting. Virtual `/dev` trees and the redundant `/System/Volumes/Data` traversal are skipped; `/Users` and `/Applications` remain visible across the System/Data device split. True nested mounts are bounded. Measured, partial, denied, skipped, cancelled and unknown are explicit; incomplete byte estimates are lower bounds. Directory allocation estimates differ from filesystem used/free capacity. APFS clones, compression, snapshots and shared volume capacity prevent promised physical savings. System and Data capacity observations are displayed separately and never added.

History automatically captures suitable **already completed** Storage measurements, at most once per compatible scope/policy per hour. It does not schedule scans, launch services or send notifications. Manual capture runs one metadata walk; “Capture current” reuses the existing Storage dataset with no extra walk. Signed compressed snapshots retain directory aggregates only: no per-file inventories, file copies, content hashes or logs. Up to 5000 useful aggregates retain root/ancestors. Defaults cap history at **16 MiB total allocated**, including temporary files, 60 snapshots and 60 days. Config can reduce limits, disable capture or clear verified records. Pruning/reservation precede atomic writes; encoded/decompressed/entry bounds prevent unbounded input. Unknown, altered, symlink or unsafe records block writes/clear and are preserved. Valid interrupted writes are recoverable. History failures do not stop cleanup or browsing.

```sh
./mactrim-launch history capture / --max-files 10000 --max-depth 16
./mactrim-launch history list
./mactrim-launch history compare                 # latest compatible pair
./mactrim-launch history compare EARLIER_ID LATER_ID --metric logical
./mactrim-launch history clear                   # verified owned history records only
```

History shows dates, graph/list deltas, percentages, capacity trends, actual footprint/limit and drill-through to Storage. Only compatible scopes/policies and complete, stable directory observations establish deltas. Missing/partial observations are unknown. A directory is newly observed unless retained complete parent enumeration proves earlier absence; parent/child deltas overlap and must not be summed. Filesystem usage can trend while directory attribution remains incomplete. Current recently modified/created allocated bytes are **activity clues, not measured growth**. A first baseline cannot reconstruct previous directory usage or establish a cause for earlier growth.

Configuration is JSON: `./mactrim-launch config` prints all supported keys. See `config-example.json` for root/budget/history settings. `retired_apps` entries require `confirmed`, exact `paths`, and historical `aliases`; this is explicit authorization for those app scopes, not blanket root authorization. For example:

```json
{"retired_apps": {"net.vendor.RetiredTool": {"confirmed": true,
 "paths": ["~/Library/Preferences/net.vendor.RetiredTool.plist"], "aliases": ["RetiredTool"]}}}
```

An installed/shared/running/uncertain owner still blocks this declaration. Store runtime state outside the source checkout; it is never uploaded with the project.

## Disposable verification

```sh
./mactrim-launch demo /new/absent/disposable-demo
.venv/bin/python -m unittest discover -s tests -v
```

Tests create and remove only owned disposable fixtures. They cover original changed-content/credentials/activity/journal/keeper/restore/purge invariants; typed worktrees, hostile hooks/environment/filters, registry and pointer races/crashes; app helpers/services/incomplete metadata; independent quotas and cancellation; APFS alias/storage budgets; compact history comparison/retention/input races; and native Textual Pilot interactions. The demo's Git init/commit stays inside its disposable repository; no remote publication or real cleanup occurs. Real CLI activity evidence may leave all demo actions blocked; fixture-injected activity tests are separate evidence and there is no production bypass.
