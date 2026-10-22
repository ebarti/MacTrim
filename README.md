# MacTrim

A native Rust storage explorer, change-tracking service and reviewed cleanup tool
for macOS. The terminal UI uses Ratatui and Crossterm. The executable includes its
runtime and SQLite; running it does not require Python, Cargo or an interpreter.

## Build and run

Build from source with the pinned Rust toolchain:

```sh
./scripts/build-binary
./dist/mactrim storage /
```

`./mactrim-launch` builds the binary if it is missing and then runs it. With no
arguments, MacTrim opens Storage at `/`. A noninteractive invocation can use
`storage / --json`; this starts or connects to the service and returns its current
status. It does not wait for a complete first scan.

The client starts a detached, per-user storage service on first use. **`q` closes
only the UI. The service continues scanning and automatically saves each
completed measurement.** Reopening connects to that same process and saved tree.
The default state directory is:

```text
~/Library/Application Support/MacTrimRust
```

Use a separate `--state /absolute/path` for a different root or a disposable
trial. State must be private to the current user. The Rust implementation uses a
new format; the previous application's personal state is preserved and is not
imported. A new Rust baseline is necessary once.

```sh
./dist/mactrim --state /absolute/trial/state storage /absolute/trial/files
./dist/mactrim status
./dist/mactrim doctor /
./dist/mactrim build-info
```

`build-info` reports the executable checksum and, for packaged builds, the source
revision and source checksum. `dist/build.json` records the packaged artifact.

## Storage and navigation

- **Enter / Right** opens a directory; **Left** goes to its parent; **g** returns
  to the service root. Browsing does not replace or cancel a background scan.
- **r** refreshes using journal changes and retries inaccessible scopes. **R**
  asks for confirmation before a full rescan. A full scan is also necessary when
  the saved event history cannot establish continuity or shared-file accounting
  requires it. The UI shows the current phase rather than silently resetting.
- **m** switches allocated/logical size. **[ / ]** changes presentation pages.
  Ranking happens across all immediate children before paging. Selection follows
  a path when incoming sizes reorder rows, including across page boundaries.
- **Ctrl+X** opens a **Y/N** pause confirmation. **Esc alone never cancels a scan.**
  A pause survives a service restart; Refresh resumes pending measurement.
  Automatic interruptions for changed filesystem history retry pending work
  without pausing the service. A cancelled worker finishing after Refresh
  cannot undo the resume. `status` records the latest interruption reason and
  time across restarts; actual measurement or save failures remain errors.
- **Tab / F1–F4** switches Storage, Cleanup, History/Growth and Quarantine/Recovery.

Sizes include accessible descendants at every depth. Dependency folders such as
`node_modules`, `.venv`, `venv`, `.tox`, `.nox` and `__pypackages__`, and directories
beyond eight browsing levels, retain recursive totals while their internal
browsing rows are loaded on demand. Opening one requests separate detail;
measurement of the global tree retains its original scope and progress.

There is no constant-time API that supplies an arbitrary directory's recursive
size. The first baseline must inspect descendant metadata, as `du` does. File
contents are not read. Initial totals are observed lower bounds until the
corresponding measurement finishes. Previously saved totals remain available
while changed regions are measured.

`MEASURED` means measurement completed for that scope; `LAZY` means its recursive
size is measured and internal browsing detail is collapsed. `PARTIAL` or `DENIED`
shows an actual coverage problem and its first failing path/error. `SKIPPED`
identifies an excluded alias, special mount or policy boundary. A partial result
is still saved and can be updated incrementally. A saved index is not a claim
that macOS permitted every directory to be read.

Logical size is `st_size`; allocated size is `st_blocks × 512`. Regular hardlinks
are counted once across a full measurement. Symlinks are not followed. Duplicate
APFS Data aliases and unrelated mounted volumes are excluded from the `/` scope.
Sparse files, APFS clones, compression, snapshots and shared-volume accounting
mean directory allocation estimates need not equal physical filesystem usage.
MacTrim displays filesystem capacity separately. It does not assert that their
difference is removable data or that reclaiming an estimate will free that many
physical bytes.

## Event tracking, persistence and History

The native receiver runs separately from traversal, file-list queries and the UI.
It does no disk I/O inside the FSEvents callback. A durable received cursor covers
either committed measurements or pending invalidated regions in SQLite.

Changes invalidate cached directory totals. They are not byte deltas. The service
remeasures affected retained subtrees and updates their ancestors using persistent
ordered maps from `im`. Unaffected map branches and their measurements are reused.
It does not depend on directory modification timestamps to detect in-place file
edits. Hardlinks or namespace changes can require a global reconciliation.

Reported delivery gaps trigger replay from the durable checkpoint. A repeated
gap or changed history identity records a full-scope invalidation before moving
the receiver to a fresh anchor. Queue pressure broadens pending work rather than
dropping affected paths. Nonconsecutive event IDs alone are not counted as drops.
An idle periodic reconciliation every seven days covers advisory-event blind
spots. **No filesystem notification API makes a mutable filesystem a perfect
snapshot or guarantees that every possible omission can be detected.**

The saved index is a compressed directory tree with parent/name links, plus
compressed changed-node deltas in SQLite. Deltas compact when their accumulated
bytes reach the measured checkpoint size. There is no directory-count or byte
ceiling that discards index records, and no stored inventory of ordinary files.
A synchronous transaction commits replacement measurements, History changes and
covered pending work together. An interrupted candidate cannot acknowledge newer
changes. A service crash preserves the last committed tree and requeues unfinished
work; it can repeat unfinished measurement, including an interrupted first
baseline. Closing the UI does not cause that interruption.

History also records actual filesystem used/available capacity as hourly
observations, independently of directory permission coverage. Its chart uses time
bins for display; the stored hourly series remains intact. This separates physical
filesystem growth from directory allocation estimates.

History keeps changed directory aggregates, coalescing the first and latest
observation per directory per hour for 60 days by default. Change the retention
window with `mactrim service retention --days 180`. Older records are removed;
SQLite can reuse their database pages. Unchanged trees are not copied
into hourly snapshots. Collapsed folders have aggregate History; their individual
files are not tracked. Nested rows overlap and must not be summed. An incomplete,
newly observed or disappeared scope has **unknown growth**, rather than a guessed
zero. History starts with the Rust baseline and cannot reconstruct earlier disk
usage from the event log.

```sh
./dist/mactrim history /Users --days 30 --offset 0 --limit 200
./dist/mactrim list /Users --offset 0 --limit 200
./dist/mactrim refresh
```

The UI reports the actual allocated footprint of service metadata. It varies with
the number of retained directories and the number of changed aggregates; there is
no fixed per-Mac estimate. Cleanup plans have separate compressed inventories,
and quarantine retains the user's selected data until Restore or approved Purge.

## Optional service at login

For launchd supervision and automatic startup at login, run explicitly:

```sh
./dist/mactrim service install /
```

This stages an ad-hoc signed `MacTrim Service.app` inside the state directory and
installs the per-user LaunchAgent `io.github.ebarti.mactrim.storage`. Updates stage
and sign a replacement before atomically exchanging the installed helper. The
service uses low-priority I/O, restarts after an unexpected failure, and respects
a successful explicit Stop. It exposes storage queries and tracking controls; it
has no deletion API.

```sh
./dist/mactrim service pause       # retain pending work, stop measurement
./dist/mactrim refresh             # resume and process changes
./dist/mactrim service status      # also succeeds when stopped; same as mactrim status
./dist/mactrim service stop        # wait for shutdown; succeeds if already stopped
./dist/mactrim service start /     # start and replay offline changes
./dist/mactrim service restart     # stop, wait, start; reuse the configured scan root
./dist/mactrim service plist /     # inspect the generated XML without installing
./dist/mactrim service uninstall   # remove login registration; keep all state/data
```

Service controls, `status` and `refresh` print readable text by default, including
when output is redirected. Status shows the service PID, root, current activity,
scan progress and whether an index has been saved. For scripts, request the
complete JSON response explicitly with `mactrim service status --json` or
`mactrim --json service status`. `storage --json` continues to return JSON;
`service plist` intentionally prints the LaunchAgent XML.

Stop waits until the service releases its state writer lock, so `service stop &&
service start /` can run without a manual delay. Restart preserves committed
measurements and pending work; an interrupted first baseline can need measuring
again. Missing or stale owned sockets report a stopped service, while access,
unsafe-socket and protocol failures remain visible. Offline status and repeated
Stop do not create or clear an index. Restart accepts an optional root; a root
that conflicts with the saved or running service is rejected before stopping it.

**Use it as your regular user, without sudo.** Full Disk Access is a macOS privacy
permission, separate from Unix privileges. Grant access to the launching terminal
when running from Terminal; an independently launched background helper may need
its own Full Disk Access approval. Its stable app path is printed by installation.
MacTrim does not modify privacy settings or restart your applications.

`doctor` reports real directory-enumeration access for common protected scopes,
the volume/event identity and current service status. It does not claim one
permission probe proves access to the whole Mac. Full Disk Access does not bypass
SIP, Unix ownership/ACLs, unavailable mounts, or entries changing during a scan.

## Reviewed cleanup and recovery

Cleanup discovers repository dependencies and build artifacts, registered merged
worktrees, common package caches, and possible leftovers of missing applications.
No candidate is selected by default. Merely missing an app or having an old folder
name is not deletion authority.

Only recognized artifacts with fresh Git/manifest evidence can be validated for
quarantine. Worktree, generic cache and app-leftover reports remain manual review
items. Recently modified descendants, sensitive files, hardlinks, ownership or
volume changes, unsupported objects, dirty source/index state and uncertain
process activity block mutation. Activity inspection is for the current UID;
other users' activity is not established. If `lsof` cannot identify a live process
or descriptor's paths, the blocker is shown and mutation is refused.

```sh
./dist/mactrim cleanup scan --root /absolute/repository
./dist/mactrim cleanup validate /absolute/repository/node_modules --older-than-days 30
```

Validation writes a short-lived signed plan. The UI requires the exact displayed
`QUARANTINE <plan-id>` before moving anything. The CLI accepts the same exact text
with `cleanup quarantine <plan-id> --approve 'QUARANTINE <plan-id>'`.

Quarantine uses an exclusive same-volume rename and writes recovery intent before
the move. **It frees zero bytes.** Each item has a signed, compressed metadata
inventory. Restore refuses to overwrite an existing path. Purge requires separate
exact typed `PURGE <journal-id>` approval, fresh activity checks and unchanged
captured identities. Added or changed quarantine contents block deletion.

```sh
./dist/mactrim cleanup journals
./dist/mactrim cleanup recover
./dist/mactrim cleanup restore <journal-id>
./dist/mactrim cleanup purge <journal-id> --approve 'PURGE <journal-id>'
./dist/mactrim cleanup activity
```

An interrupted move or restore is reconciled from its saved identities and actual
locations. Interrupted purges remain explicit recovery records; residual contents
are retained for review. Recovery does not automatically delete files.

## Verification

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
./scripts/build-binary
./scripts/verify-binary
```

The executable tests exercise native FSEvents on disposable directories, stopped
service/offline changes, deep aggregates, compressed deltas and restart recovery,
global paging, signed helper staging and a real pseudo-terminal. The terminal
checks selection after asynchronous reordering, all four tabs, true-color output
and keeping the service alive after closing the client. Cleanup mutation tests
use controlled process-visibility fixtures; they do not claim a live machine's
process inventory is always complete. No benchmark or whole-Mac scan is part of
the automated checks.

See [the recovery design](docs/rust-service.md), the installed SDK's `FSEvents.h`,
and Apple's current API references for
[delivery-drop flags](https://developer.apple.com/documentation/coreservices/kfseventstreameventflaguserdropped)
and [per-device history identity](https://developer.apple.com/documentation/coreservices/1444453-fseventscopyuuidfordevice).
