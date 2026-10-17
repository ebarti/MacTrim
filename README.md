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

Cleanup, Storage, and History / Growth are separate tabs. Discovery and measurement run in background workers, publish partial results, and support cancellation. Keyboard shortcuts appear in the footer. Cleanup offers search, status filter, sorting, category counts, full evidence/blockers, selected totals, fresh validation, and an exact typed approval dialog. Reports cannot be selected. Storage's chart and sortable list share measured nodes: Enter drills down; Parent, Root, Refresh, logical/allocated mode and breadcrumbs support navigation. Storage measures every accessible entry with no entry/depth cutoff. Full rescan forces a fresh baseline; Refresh uses native filesystem events. Directory/file rows are paged independently of measurement. History retains up to 5000 directory aggregates. Storage and History never grant cleanup authority.

Scan cancellation uses **Ctrl+X** on the Cleanup or Storage tab, or that tab's Cancel button. A confirmation names the target scan (and Storage path): **Y** stops it; **N**, **Esc**, or the default No button keeps it running. Esc alone never cancels a scan. Cleanup and Storage can run independently; cancelling one leaves the other running. Interrupted Storage progress is not saved; its previous saved index is preserved.

```sh
./mactrim-launch tui
./mactrim-launch storage /
./mactrim-launch storage / --json --max-files 1000 --max-depth 8
./mactrim-launch storage /private/tmp --full
./mactrim-launch --config config-example.json scan --tui
```

`NO_COLOR` is honored. A true-color terminal gives the richest appearance; semantic status labels remain available without colors. Small terminals retain native keyboard navigation and scrolling.

## Cleanup evidence

Repository artifacts require allowlisted regeneration, ignored/untracked contents, dependency specifications, clean source/index, source/reflog/artifact inactivity, owned no-follow paths, and complete current-user activity coverage. Recognized pip, uv and npm download caches require proven layouts and stale activity; npm logs are retained. Unknown reports, screenshots, logs, app data and update staging stay report-only. Credentials, databases, backups, cloud placeholders, protected scopes, hardlinks and special objects cannot become mutation targets merely because they are old.

Registered linked Git worktrees are a separate category, including default Codex worktree roots. A merged HEAD is stale independently of age. MacTrim proves ancestry against a resolved default target, or an authenticated GitHub merged PR with exact head and retained merge-commit proof. Local refs have explicit freshness limitations; unavailable/squash-mismatched evidence stays review-only. Primary/current, out-of-scope, dirty, untracked, meaningful ignored, active, locked, sparse, hidden-index, submodule and unique-commit worktrees are protected. Ignored Python environments need a tracked regeneration specification and recognized layout; unknown installed state is preserved. Git checkout/index/common-directory binding and common/admin identities and ancestors are checked afresh. Pointer recovery holds the captured admin descriptor and validates every remaining administrative entry, including the captured HEAD/branch, before replay writes; a replaced registry or changed metadata causes a conflict and remains intact.

App ownership includes bundle IDs, helpers/extensions, current-user services, normalized `application.<bundle>.<instance>` labels, vendor families, and observed/explicit historical human aliases. Apple/system components do not become uninstall guesses. Missing/incomplete ownership stays uncertain; live helpers and shared families retain ownership. Equal or unknown versions are duplicate app copies, not “older” versions. Preferences/support remain manual unless configuration explicitly confirms the retired owner **and exact scope**; ownership is checked again before apply and purge. App bundles and macOS update/content-caching records remain manual reports. Prefer the app's uninstaller and [Apple's storage controls](https://support.apple.com/guide/mac-help/free-up-storage-space-mh26887/mac) or [Content Caching controls](https://support.apple.com/guide/mac-help/manage-content-caching-mchl9388ba1b/mac).

Cheap metadata measurement is separate from eligible fingerprints and explicit duplicate hashing. Per-category/root/subtree budgets expose partial coverage without letting a large repository starve worktrees, caches, apps or duplicates. Unrelated partial roots do not veto a proven selected scope; cancelled plans and incomplete activity block actions. Explicit CLI overrides are applied before root validation. Storage uses a complete directory inventory by default; explicit JSON preview bounds remain available for diagnostics. Cleanup keeps its independent evidence budgets. Different collectors and declared exclusion policies establish separate History baselines.

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

## Standalone macOS binary

The native arm64 onefile build produces `dist/mactrim`; execution requires no separately installed Python or project environment. Copy that executable to a user-owned location and run its absolute path, or `./mactrim` from its containing directory. The existing source launcher remains available.

Build on an arm64 Mac with CPython 3.12.12:

```sh
.venv/bin/python scripts/build_binary.py
./dist/mactrim --version
./dist/mactrim
```

The script requires a clean committed checkout, installs hash-pinned build/runtime wheels only in `build/binary-venv`, and emits `dist/mactrim.build.json` with source revision, dependency pins, architecture, artifact hash and size. It uses optimization level 0. Only required code, interpreter/libraries and Textual/Rich version metadata are collected; project runtime state, evidence, fixtures and tests are excluded. This is a pinned build procedure, not a promise of byte-identical results across toolchains or Macs.

The delivered configuration targets Apple Silicon arm64. Intel or universal builds require appropriate Python/library architectures and a separately configured and verified build; they are not covered by this delivery. The executable is locally ad-hoc signed, not Apple Developer signed or notarized. See [PyInstaller's architecture/signing notes](https://pyinstaller.org/en/stable/feature-notes.html#macos-multi-arch-support).

[Onefile startup](https://pyinstaller.org/en/stable/operating-mode.html#how-the-one-file-program-works) extracts bundled libraries to a temporary `_MEI…` directory, so it needs temporary disk space and starts more slowly than the source launcher. Normal exit removes its extraction directory; a crash or forced termination can leave remnants. Inspect a remnant's ownership and association with an exited process before manual removal; do not clear shared temporary directories. MacTrim state and bounded History remain separate from extraction and are never bundled. Git evidence and activity still require the macOS system tools; unavailable evidence stays fail-closed.

Run the disposable outside-repository checks with `.venv/bin/python scripts/verify_binary.py dist/mactrim --report evidence/binary-smoke.json`. The harness removes only its owned fixtures, executes the binary with no Python on PATH, poisons Python environment paths, opens the real three-tab terminal UI on a fixture scope, checks native event replay across process restarts, and records real activity refusals without replacing the production activity provider.

The onefile parent repeats scanner arguments. MacTrim excludes only that argv evidence after proving a direct parent in fresh same-user process inventories, identical full scanner arguments, and both executable descriptors matching the running binary's device/inode. Actual cwd/open/executable paths, interpreter scope, unrelated processes and incomplete coverage still block actions; missing proof keeps the conservative blocker.


### Complete Storage inventory

Storage now measures every accessible entry under its metadata-only traversal policy, without a file-count or depth cutoff. The graph uses filesystem-used bytes at `/` for allocated percentages; directory sums and the signed accounting difference remain estimates because APFS clones, snapshots and inaccessible regions differ from namespace totals. Denied regions show explicit reasons; intentional symlink, cloud placeholder, alias and mount exclusions do not falsely mark the parent incomplete.

During a scan, Storage publishes observed bytes, actual metadata visits, the current directory and processing phase. Unfinished totals are explicitly lower bounds; filesystem capacity appears before directory enumeration finishes. Live graph/list rows show the first 500 immediate directories, while totals include all observations. Final graph ranking and paged browsing use the completed inventory. Progress snapshots are bounded independently of traversal so rendering does not repeatedly copy the whole directory tree.

Drilling into directories, returning to a parent and changing the displayed root do not cancel or replace an active scan. The scan keeps its original scope, progress and saved-index destination while publishing a bounded live view of the displayed directory. A directory not yet observed shows that it is waiting for details. Completion preserves the displayed directory and saves the original scan root. Refresh and Full rescan explicitly start measurements; navigation alone reuses observations.

Dependency trees named `node_modules`, `.venv`, `venv`, `.tox`, `.nox` and `__pypackages__` appear as **LAZY** directory summaries. Their full logical/allocated totals, entry counts, exclusions and coverage are measured, but their descendant directory objects are not retained in the main inventory. Obtaining an initial recursive total still requires inspecting descendant metadata; folder metadata alone does not contain that total. Journal-verified unchanged summaries can be reused later, including after restarting the app. Existing detailed indexes remain readable and can donate their measured totals without forcing a new baseline merely to change detail granularity.

Opening a LAZY directory loads its internal directory view on demand. If the main scan is running, that request waits for its completion without cancelling it. Details are retained for browsing in the current app session and load again if opened in a later session. Detail scans never replace the main saved index or capture a second whole-scope History baseline. Refreshing a descendant view also preserves the main index. Deferred children are explicitly absent from detail coverage; History never treats an unexpanded summary as proof that an unseen descendant was created or deleted.

The same lazy summaries apply to any directory deeper than eight levels below the current scan root. The scan root is depth 0; depths 1–8 retain ordinary detail, and depth 9 becomes a measured summary whose deeper descendants are deferred. Opening that summary makes it the root of a separate detail view, with another eight levels available before the next lazy boundary. This is a detail-retention rule: descendant bytes still contribute to the measured totals, and the metadata traversal has no depth cutoff.

Event-region matching uses a path-component trie: O(E × L) to index E changed paths of depth L, then O(L) per directory query. Ancestor and descendant overlap both invalidate reuse; sibling prefixes do not. Reconciliation checks cancellation between directories and before committing the directory index. An in-flight operating-system call must return before cooperative cancellation can complete.

The list shows pages of 500 immediate entries. Paging limits presentation, never measurement. The complete collector retains directories rather than a node for every file. `mactrim storage / --json` is complete by default; explicit `--max-files` / `--max-depth` opt into the legacy bounded JSON preview. Those legacy config values continue to govern previews only. Cleanup retains its separate discovery/evidence budgets and approval protocol.

History uses a new complete measurement policy. Existing sampled snapshots are preserved and cannot be used to assert growth against complete observations. Full rescan has no quota controls; Cancel leaves unvisited regions unknown.


### Incremental refresh and retained footprint

The first scan enumerates metadata for all accessible entries. A folder has no stored recursive size: its total requires summing descendant file allocation and directory metadata. Subsequent refreshes replay macOS persistent FSEvents, remeasure changed directories, reuse verified unchanged directory aggregates, and update ancestor totals. In-place file edits do not change parent-directory timestamps, so timestamps alone never authorize skipping a subtree. Navigation uses the last observation and labels it as cached; Refresh verifies events.

Storage records an event checkpoint before enumeration and reads the persistent macOS journal afterward. A cached refresh also reads changes since the saved checkpoint before reusing unchanged subtrees. Each journal reader runs in a separate process and closes before the next metadata walk; no listener remains open for an hours-long scan. Directory-level notifications are batched by macOS with a one-second delivery latency. A reader waits for `HistoryDone`, flushes delivery, and finishes pending processing before returning its paths and watermark. Measurements replace affected folder totals and recompute ancestor totals; replaying an edit already seen by the scan never adds its bytes twice. The following walk starts its change interval at the replay's covered watermark, so edits after the reader closes are still replayed. Checkpoints and directory trees commit together, and checkpoints never advance past unprocessed changes.

Journal readers are bound to the measured device with `FSEventStreamCreateRelativeToDevice`, rather than combining histories from every mounted volume. A historical gap from an excluded volume cannot invalidate the measured device's index. Volume-relative callback paths are mapped back to the selected directory namespace, including APFS Data aliases. A split root with an immutable System volume watches writable Data changes and validates both volume-history identities. Mount/unmount notifications invalidate the affected namespace and its parent; they are counted separately from dropped events. Actual dropped delivery, wrapped event IDs and watched-root changes still require reconciliation.

Indexes made with the older host-wide reader require one new baseline before incremental reuse. Their saved observations remain intact until replacement succeeds. The index checks the event source, volume-history UUIDs and path mapping along with its checkpoint. This migration does not change the directory measurement policy used by History comparisons.

The native callback copies incoming arrays into a pending queue; a separate processor handles path normalization and exclusions. Pending and dirty path collections each have a 2 MiB estimated path-storage allowance. Crossing either allowance coarsens invalidation to the watched root, requiring remeasurement without losing coverage; these allowances never cap a scan or index. Historical replay has no five-second completion limit: delivery progress keeps the protocol alive, while an idle deadline, cancellation, pipe EOF and bounded shutdown still stop stalled or abandoned readers. MacTrim writes no additional event log to disk.

Native events remain advisory. Event gaps, changed volume identity, invalid/missing cache, unsupported native access and periodic reconciliation fall back to complete measurement. Changes affecting hardlink/alias accounting trigger global reconciliation. Hot writers leave affected totals explicitly partial and their History growth unknown. Notifications include a short delivery settling window; this is an interval observation, not an atomic filesystem snapshot. A full scan is due after seven days on the next use; there is no daemon or scheduled task. Apple's current references document [dropped-event reconciliation](https://developer.apple.com/documentation/coreservices/kfseventstreameventflaguserdropped) and [delivery batching](https://developer.apple.com/documentation/coreservices/1443980-fseventstreamcreate).

Refresh reads the saved checkpoint when its scope, policy and event-history identity are compatible. If a full measurement is required, the running view shows **FULL** and its actual reason immediately, rather than waiting for completion. Causes such as a changed event-history UUID, unverified continuity, a different scope, a future checkpoint, a due periodic sweep or hardlink accounting are distinguished. A changed history UUID means the saved event IDs belong to a different stream and must not authorize skipping changed data; the previous observation remains saved until its replacement is committed.

Completed scans automatically save observations, including partial results. A dropped or failed delivery is retried once with a fresh journal reader at the same checkpoint before deciding that reconciliation is required. Recovery keeps the completed measurement and remeasures only reported changes. If both deliveries report a gap, one full repair sweep remains necessary; if history is still uncertain afterward, the directory observation is saved with reuse disabled. Coalesced events remeasure their named subtree without declaring the whole stream lost. The finished screen separately reports **INDEX SAVED**, **OBSERVATION SAVED** (reconciliation required), **TOTALS SAVED ONLY** (legacy truncated index), or **INDEX NOT SAVED** with its reason. Cancelling still preserves only the prior committed index.

Storage uses native directory-level journal records because it stores directory aggregates. An unrecovered interval requires one explicit full repair sweep during the current scan; changes overlapping hardlink accounting also require a global sweep, while unrelated changes permit scoped reuse. Continuously changing regions remain uncertain after that repair rather than causing endless restarts. **Coverage** shows the exact observed permission failures, unstable paths and tracking problems. `--full` requests an unlimited traversal; it cannot override macOS privacy restrictions. For protected personal folders, grant Full Disk Access to the app that launches MacTrim in System Settings → Privacy & Security. This does not require granting access to your coding editor. Full Disk Access does not override Unix file permissions; ordinary Unix permission failures may require separately running a read-only scan with elevated access. **PARTIAL** describes measurement coverage, while **INDEX SAVED** describes index persistence and reuse. A permission-limited observation can retain a reusable index, reuse accessible unchanged directories and retry denied directories on refresh; it need not discard its index or restart every directory from zero.

The current authenticated compressed directory index uses **automatic sizing**: the main directory tree and explicitly deferred dependency summaries are retained with parent links, without a directory-count or decoded-size ceiling. Records stream to disk rather than creating a second serialized copy of the entire tree in memory. It stores no per-file inventory or contents. One committed generation is retained; atomic replacement temporarily needs space for both generations. `storage_cache.max_bytes: null` enables automatic sizing. An optional explicit byte budget refuses a replacement that does not fit and preserves the previous index; it never substitutes root-only totals. Actual allocated index bytes and directory count appear in Storage. Legacy signed indexes remain readable. History separately retains at most 16 MiB, 60 snapshots, and 60 days. These limits exclude the executable, onefile extraction, cleanup journals and quarantined user data. Scanner cache/history are excluded from directory totals and reported separately. Clear cache removes only verified owned index data; corruption and unexpected paths are preserved.

`storage_cache` settings in `config-example.json` control enablement, an optional explicit storage budget and reconciliation interval. `storage --no-cache` disables the index; `storage --json --clear-cache` clears it; `storage --full` forces full reconciliation. `storage / --json --full --capture-history` saves the same observation as a History baseline without another filesystem walk. Historical growth cannot be reconstructed before the first recorded baseline. Recent modification/creation clues on reused directories reflect their last full observation; Full rescan refreshes those clues.

Journal and receiver diagnostics appear in Storage and JSON (`measurement.refresh.events`) and are saved with the latest index: replay attempts, recovered deliveries, committed checkpoint, journal source/device/mount, separate mount-change count, callback/event counts, maximum callback duration, pending-path high-water estimate, pending dirty regions, broader invalidations, drop-signal count and last flags. These are fixed-size counters, not per-file history or a growing log. Drop signals do not reveal the number of lost notifications. If both reader attempts fail after a walk, MacTrim preserves that measurement, marks coverage uncertain and saves it with incremental reuse disabled. The next refresh reconciles it; receiver failure never automatically repeats a completed walk.
