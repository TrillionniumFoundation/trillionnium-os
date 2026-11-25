# AX canonical byte reuse

This successor changes one production file, ObservationCaptureEvidence.java.
The private validate method already serialized the complete validated receipt to
enforce the UTF-8 byte limit. It now returns those same bytes to its four callers,
which previously serialized the same frozen value immediately again.

The freeze order, every validation branch, MAX_RECEIPT_BYTES, persisted-byte
Arrays.equals, actual hash check, raw-byte clone, private file durability, readback,
observation clocks and publication event fences remain unchanged. Each full
write/readback construction now performs two complete receipt serializations
instead of four. Tree-array comparisons and all other checks still execute.

## Source-bound regression

Run:

    python3 -B tests/native-ax-canonical-reuse/run_host.py --source SOURCE --output OUT --java-home JDK --json-jar JAR

Use an output directory outside SOURCE that does not already exist. The runner
requires the reviewed current capture SHA and restores the complete predecessor
through a six-hunk inverse plus its full original SHA. Unrecognized source bytes
are rejected. The current production file is compiled directly.

The 23 distinct cases run against four whole-class variants: unmodified predecessor,
unmodified current source, and an independent copy of each with one counter at the
actual canonicalBytes entry. The counter counts only the three full receipt schemas.
It does not replace validation, serialization or the persisted-byte constructor.
All outcomes and refusal messages must match, and all five valid canonical receipts
must be byte-identical in all variants. Cases cover ordinary AX, empty-input history,
Ctrip form history, Chinese/JSON escapes/integral limits, exact and exceeded 2 MiB
UTF-8 limits, corrupt persisted bytes, wrong hashes, mutation before sealing,
missing identity, wrong kind, invalid UTF-16 and ownership of copied maps/bytes.

Receipt preparation reuses the unchanged existing Xiaomi test fixture and Ctrip
host factory. Only those existing explicit host values are used; no new phone
recording, account data or private task archive is embedded. Extra edge cases are
declared synthetic. The assertion count is 45 per variant, with 23 distinct cases;
the four executions are not 92 independent cases.

The private proof-copy helper also lets the existing Xiaomi parser runner retain
its original complete capture pin while compiling the current production source.
Its parser cases and fixture bytes are unchanged.

## Qualification boundary

The existing AX producer and AX consumer gates are still required. The new runner
is a separate required gate for any build claiming this optimization's equivalence.
No phone, model, Android runtime, fsync timing or mobile speedup is exercised here.
Host process timings are command diagnostics only.

The f349 Xiaomi record's ax_receipt_persist phase included file and directory
fsync, readback, receipt freezing/validation/serialization, hashing and path checks.
It did not split IO and CPU timings. Eliminating the verified redundant encodes
does not prove that the full observed 2–3 seconds came from encoding, that later
content events are safe, or that the failed phone task will now succeed.
