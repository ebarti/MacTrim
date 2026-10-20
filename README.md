# MacTrim

A native Rust terminal app for exploring disk usage, comparing completed scans,
and reviewing cleanup actions. MacTrim runs only while its terminal command is
open. It does not run a daemon, install a login service, subscribe to filesystem
notifications, or read an event journal.

## Build and run

```sh
./scripts/build-binary
./dist/mactrim storage /
```

`./mactrim-launch` builds a missing binary and then runs it. With no arguments,
MacTrim opens Storage at `/`. The signed executable includes Rust and SQLite;
Python, Cargo and an interpreter are not needed to run the packaged app.
`build-info` reports the compiled source revision and executable checksum.

Opening Storage starts **one full scan** of its chosen root. **r** starts another
full scan after the current one finishes. Every pass inspects metadata throughout
the accessible scope, including dependency folders and directories deeper than
eight levels. Previous measurements are used for browsing and comparison, never
to skip files in a new pass. An edit outside MacTrim does not trigger any work.

```sh
mactrim storage /               # interactive app, new full scan
mactrim scan /                 # full scan, save, print result, exit
mactrim refresh /              # another full scan, save, exit
mactrim status                 # latest saved result, no scanning
mactrim snapshots              # all saved scan IDs
mactrim history /              # compare the latest two scans of this root
mactrim history / --from 2 --to 5
mactrim list /Users --scan 5
mactrim doctor /
```

Command responses are readable text by default. Add **--json** for structured
output. `storage / --json` runs a complete scan and returns its saved result;
it does not detach or return a background job. `build-info` and cleanup's detailed
plan/journal commands retain their structured output.

The default state is `~/Library/Application Support/MacTrimRust`. Supply
`--state /absolute/private/path` for a disposable trial. One terminal scan can
write a state directory at a time; other commands may read its completed scans.
No service start, install, restart, pause or event-refresh commands are available.

## Terminal controls

- **q** exits. During a scan, it asks **Y/N** before stopping work and exiting.
  Completed scans remain saved. An unfinished pass is discarded.
- **r** starts a new full pass. Pressing it while a scan runs keeps that pass.
  **R** also offers a confirmation before requesting a full pass.
- **Ctrl+X** asks **Y/N** before cancelling the active pass. Cancellation stays
  idle until another explicit scan request. **Esc alone never cancels.**
- **Enter / Right** opens a directory, **Left** goes up, and **g** returns to the
  chosen root. Navigation never cancels, replaces or starts a scan.
- **m** switches logical/allocated size. **[ / ]** changes presentation pages.
  Selection follows the same path when incoming rows reorder.
- **Tab / F1–F4** switches Storage, Cleanup, History/Growth and Quarantine.
- In **History**, **s** chooses two saved scan IDs. Empty input selects the latest
  pair. Both endpoint IDs and times appear in the comparison title.

While a new scan runs, an earlier saved tree remains available and is labeled
as the previous scan. On a first scan, observed bytes are lower bounds until the
corresponding directories finish. Immediate file rows are read on navigation;
the saved measurements and comparisons retain directory aggregates, not a record
for every ordinary file. File-row metadata is not historical file inventory.

## Saved scans and comparisons

Completed scans **auto-save**, including completed traversals with partial
coverage. Each gets an independent ID, start/finish times, coverage, physical
root identity, filesystem capacity and a compressed parent/name directory tree.
Two scans in the same second remain separate. There is no fixed byte,
directory-count or browsing-depth limit, and no automatic deletion of old scans.
The app shows the actual allocated footprint of its saved data. It grows with
the number and size of scans retained.

History compares any two saved scans of the same root. It shows before/after
allocated sizes and signed growth. Nested directory totals overlap and must not
be summed. A newly added or removed directory has a known zero endpoint only
when its parent was measured. Unreadable scopes, missing detail in an imported
legacy tree, and a replaced root have **unknown growth**. A completed traversal
can be `PARTIAL` or `DENIED`; its saved state does not claim access to those areas.

Physical filesystem used/available capacity is recorded with each completed
scan and shown separately from directory allocation estimates. A scan measures
a mutable filesystem over an interval, not an atomic point in time. Concurrent
writers can produce partial observations. There is no event reconciliation or
automatic retry loop; another scan requires an explicit request.

A private compressed tree is flushed and checksummed before a synchronous SQLite
transaction publishes it in `scans.sqlite3`. Cancellation, termination or a failed
candidate cannot replace earlier completed scans. A force-killed pass may leave
an unreferenced temporary file, but it cannot publish a half-written scan.

The previous Rust service was stopped and its login registration removed during
this migration. Its last saved directory index is imported once as a labeled
legacy scan. Original service database, history, generations and cleanup data are
preserved. Unreadable legacy data stays intact with an import warning. Old hourly
history remains in its original database; it is not relabeled as full scans.

## Measurement and access

Sizes include accessible descendants at every depth. Logical size is `st_size`;
allocated size is `st_blocks × 512`. Regular hardlinks count once across each
full scan; sorted traversal stabilizes attribution. Symlinks are not followed.
Special mounts, unrelated volumes, the duplicate APFS Data alias and MacTrim's
own state are excluded. `SKIPPED` identifies these boundaries. Errors retain the
first affected path and operating-system error.

The first totals require descendant metadata inspection, as `du` does; there is
no constant-time recursive directory-size query. Storage scans do not read file
contents. APFS clones, sparse files, compression, snapshots and shared-volume
accounting can make directory estimates differ from physical capacity. This
difference does not identify removable data.

Run as your normal user. Full Disk Access applies to the launching terminal.
`doctor` probes enumeration of common protected folders. It does not claim a
single probe establishes access to the whole Mac, and Full Disk Access does not
override Unix permissions, SIP or unavailable mounts.

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

Checks cover distinct saved scans, offline edits, full deep traversal, hardlinks,
symlinks, interrupted saves, root replacement, paging, byte paths, legacy import,
readable CLI output and a real pseudo-terminal. Terminal checks exercise refresh,
selection, all four tabs, saved comparisons and exiting without detached work.
Native executable checks reject the old service entry point and check that no
FSEvents symbols or CoreServices framework are linked. Cleanup tests retain exact
approvals, recovery and fresh process-visibility blockers. No benchmark or whole-Mac
scan is part of automated verification.

See [the full-scan persistence contract](docs/full-scan-snapshots.md).
