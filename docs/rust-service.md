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

First principles: an applied event cursor is safe only if every event through it
is represented by committed measurements and subsequent edits remain in durable
pending work. A received cursor records delivery progress; after a gap it needs
a separate durable uncertainty marker and cannot imply verified measurements. The
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
from the last durable cursor. A repeated gap, invalid history UUID or wrapped IDs
records historical uncertainty separately from pending scopes. The active scan
continues, saves its measurements, and then becomes idle; when there is no active
scan, measurement stays idle. New notifications are still durably collected.
Refresh is required to resume. The service does not acknowledge an old journal
cursor in a replacement journal, or mark uncertain History growth as complete.
Volume UUIDs distinguish a replaced filesystem from a replaced event journal;
only the former invalidates the active filesystem measurement.

Directory details remain collapsed for dependency folders and after eight
browsing levels. Their *sizes* include accessible descendants at every depth.
Hardlink/namespace accounting can require a full reconciliation; filesystem
allocation estimates are distinct from physical APFS volume usage.

The service keeps the directory tree in persistent ordered maps from `im`.
An ordinary update remeasures an antichain of invalidated retained subtrees,
shares all unaffected map branches and recomputes the affected ancestors. It
does not clone every directory or visit every unchanged directory to refresh a
small region. Previously or newly shared hardlink identities can require global
accounting. An incremental worker reports that requirement and retains its
pending scopes instead of silently walking the whole root. A Full rescan requires
an explicit request. A periodic audit can be reported as due without starting it.

The native receiver requests file-level events. File changes invalidate their
containing directories; indexed SQLite ancestor and descendant queries coalesce
pending scopes without rewriting the full queue for each batch. There is no
queue-size threshold that promotes precise paths into a root walk. A durable
finish-then-idle marker survives restart and is cleared only by explicit Refresh.
The measurement worker and checkpoint writer share a configurable cooperative
CPU duty budget (10% of one core by default); event intake does not sleep behind
that budget. Cancellation remains responsive during paced work and checkpoint
construction, and unfinished checkpoint files are cleaned up by their temporary
file owner.

On disk, the service persists a compressed directory checkpoint plus compressed
changed-node deltas in SQLite, alongside coalesced pending regions and cursors.
Delta bytes compact into a new checkpoint once they reach the measured size of
the checkpoint. This retains the complete tree and avoids a full rewrite for
each small edit. History queries and immediate-file listings run outside the
event ingestion loop; their presentation pages never truncate saved data.
It does not copy the OS event
log, retain file contents, or persist one record per ordinary file. No byte or
directory-count ceiling truncates the index. A generation file is fsynced before
the database atomically points to it and acknowledges covered pending work;
delta payloads and their acknowledgements commit in the same synchronous SQLite
transaction. SQLite uses WAL so browsing History can overlap event ingestion.
After a crash, an unreferenced generation is harmless; the last committed tree
and pending work remain authoritative.

The socket and receiver become available while a worker loads the saved tree.
Filesystem capacity is sampled independently of directory coverage and saved as
hourly observations, so a denied directory does not prevent volume-usage history.
History retention is configurable through the service; chart sampling and page
sizes affect presentation rather than the retained directory inventory.

The service runs as the current user. Full Disk Access and Unix permissions
still determine which directories macOS permits it to measure. It has no cleanup
or deletion API. LaunchAgent installation is an explicit command, separate from
building or running a test instance.
