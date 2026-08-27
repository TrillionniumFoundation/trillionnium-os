# Historical evidence migration plan v1

This directory defines a non-destructive migration plan for the tracked May
2026 smoke outputs in `docs/mobile-smoke` and the frozen
`docs/archive/historical-v1` corpus. No evidence file is removed, rewritten,
or declared release-authoritative by this checkpoint.

`index-v1.json` records every currently tracked source path, byte length,
media type, and SHA-256 digest. It also records a digest for each complete
source set and the proposed content-addressed object key. Regenerate or verify
it with:

```sh
python3 tools/materialize_evidence_migration_index.py
python3 tools/materialize_evidence_migration_index.py --check
```

The eventual archive must be a deterministic POSIX tar ordered by bytewise
path with normalized ownership, mode, and time, compressed with the fixed zstd
profile recorded in the index. Materialization must add the archive SHA-256 to
a signed release manifest; the placeholder in this source index is not an
archive receipt.

Source deletion is a separate, explicitly approved change. It remains blocked
until two archive replicas independently verify, a clean-room restore matches
every indexed path and digest, selected golden fixtures remain in Git, and the
release owner approves the exact deletion set. The intended steady state is to
keep schemas, generators, this index, signed artifact pointers, and a small
reviewed golden fixture set in the source tree while storing bulk run output in
release artifact storage.
