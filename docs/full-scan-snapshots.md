# Full scans and saved comparisons

Every measurement traverses its complete chosen root. Earlier trees supply
comparison values and browsing while a scan runs; they never skip metadata in a
new scan. Directory details are retained at every depth, including dependency
folders. Traversal sorts names so unchanged hardlinks have consistent allocation
attribution between full scans. Regular hardlinks count once, symlinks are not
followed, and special mounts and the duplicate APFS Data alias remain excluded.

Each completed traversal is saved as a separate compressed parent/name tree.
The catalog in `scans.sqlite3` gives it a numeric scan ID, start and finish times,
root identity, coverage, directory and visit counts, directory allocation
estimates, and physical filesystem used/available capacity. Two scans completed
in the same second still have different IDs; they are never coalesced hourly.
Snapshot trees have no directory-count, browsing-depth or fixed-byte cutoff.

A private generation file is flushed and checksummed before a synchronous
transaction publishes its catalog record. Interrupted traversal or persistence
does not replace earlier completed scans. An inaccessible scope can produce a
completed traversal with partial coverage, which is saved with the actual error.
Measurements span a mutable filesystem over an interval; they do not claim an
atomic filesystem snapshot.

Comparisons load two saved trees of the same root. They show both measurements
and directory changes, with nested aggregates explicitly overlapping. Added or
removed directories have a known zero endpoint only when the corresponding
parent scope was measured. Inaccessible, previously collapsed or replaced-root
coverage has unknown growth. Physical capacity is compared separately from
directory allocated-byte estimates.

The last saved Rust-service index is imported once as a labeled legacy scan.
Its previous coverage and collapsed detail remain visible. Original generation
and service database files are preserved; unreadable legacy data is retained
with an import warning and does not block new independent scans. Cleanup plans,
quarantine and restore data use their existing private state and approval rules.
