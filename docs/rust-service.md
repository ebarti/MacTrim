# Rust storage service

The replacement uses Rust for the CLI, Storage service, terminal client, History
and cleanup workflow. WalkDir supplies metadata traversal, Ratatui supplies
terminal widgets and SQLite supplies durable pending work. It does not invoke
Python. Legacy personal state is left intact; code compatibility is not a
constraint on this replacement.

## Recovery contract

FSEvents supplies changed-region hints, not a byte ledger. A directory timestamp
does not track in-place edits to descendant files. Recursive measurement must
establish a baseline, and later events invalidate cached subtrees. Replacement
measurements replace totals; they never add a guessed event byte delta.

First principles: a saved event cursor is safe only if every event through it
is represented by either committed measurements or durable pending work. The
receiver and measurement worker have separate lifetimes. A client disconnect
does not cancel measurement, and a daemon restart replays from its durable
cursor. A partial observation is preserved and remains explicitly partial.

The observed limitations and their owning layers are:

1. Events can be coalesced or dropped because the OS delivery buffers are finite.
2. A delivery gap cannot identify each missing edit, because event IDs are not
   consecutive and events do not contain size deltas.
3. A receiver alone cannot establish totals: the measurement/persistence boundary
   must retain invalidations until replacement measurements commit.
4. Long measurements, interrupted processes and busy writers expose this boundary;
   a short successful scan does not prove restart or overflow recovery.
5. Users expect Refresh and reopening the UI to preserve completed work, so the
   index must outlive UI sessions and its cursor must never outrun pending work.

The fix belongs in the service's ingestion and commit protocol. Rust reduces
receiver overhead and removes the Python interpreter/GIL from this path; it
does not strengthen Apple's delivery guarantees. Reported gaps cause replay
from the last durable cursor. A repeated gap, invalid history UUID, wrapped IDs
or a moved watched root causes a durable invalidation of the whole scope. The
old observation remains browsable during recovery.

Directory details remain collapsed for dependency folders and after eight
browsing levels. Their *sizes* include accessible descendants at every depth.
Hardlink/namespace accounting can require a full reconciliation; filesystem
allocation estimates are distinct from physical APFS volume usage.

The service persists a compressed directory tree and a small transactional
database of coalesced pending regions and cursors. It does not copy the OS event
log, retain file contents, or persist one record per ordinary file. No byte or
directory-count ceiling truncates the index. A generation file is fsynced before
the database atomically points to it and acknowledges covered pending work.
After a crash, an unreferenced generation is harmless; the last committed tree
and pending work remain authoritative.

The service runs as the current user. Full Disk Access and Unix permissions
still determine which directories macOS permits it to measure. It has no cleanup
or deletion API. LaunchAgent installation is an explicit command, separate from
building or running a test instance.
