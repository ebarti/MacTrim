# Terminal-only replacement

The background storage service and event receiver have been removed. MacTrim now
owns a full-scan worker inside the terminal process. Opening Storage starts one
pass, an explicit Refresh starts another, and quitting stops all work. Browsing
never replaces an active pass. There is no event replay or unattended scan loop.

See [the scan and persistence contract](full-scan-snapshots.md) and the
[current commands and controls](../README.md). Existing service state is preserved;
its last saved tree is imported once, and old hourly history remains in the
original database. Cleanup plans, quarantine and restore approvals are unchanged.
