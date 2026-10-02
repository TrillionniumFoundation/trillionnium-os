# Owner-Open Event Store

Current module: `MOD-EVENT-STORE`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate records bounded append-only observations, integrity metadata and replay state. It records facts and never authorizes an effect or treats missing data as proof that an effect did not start.

`DurableEventStore` is the compatibility reader/writer for the v1 single-file
JSONL layout. New deployments can use `SegmentedEventStore` (also exported as
`EventStoreV2`) with the same `EventRecord` schema. V2 writes numbered
`segment-<sequence>.jsonl` WAL files, maintains keyed and per-scope replay
indexes, publishes an atomically replaced `index.v2.json` sidecar, and keeps
filesystem sync outside the metadata lock. `SegmentedEventStoreConfig` bounds
segment size, record count, total bytes and group-commit records/bytes/time.
`flush` is the explicit durability boundary; `checkpoint` additionally writes
a validated `snapshot.v2.json` high-water copy and the index. Strict recovery
remains the default, while `RepairTrailingPartial` may discard only a torn
final suffix.

All caller-supplied limits are checked before path discovery or recovery. The
schema ceilings are 1 GiB per lineage, 64 MiB per encoded record, 1,048,576
records, 4 KiB identifiers/kinds, 240 open segments, 256 MiB per pending
group and a 24-hour group interval. Deployments can lower these values but
cannot use an unbounded `usize`/`u64` to turn recovery or buffering into an
allocation or file-descriptor exhaustion path; `SegmentedEventStoreConfig::try_new`
is available when a validated constructor result is needed.

The runtime also enforces a 32 MiB conservative resident reservation and a
64 MiB logical working envelope for one store operation, independent of encoded
WAL bytes. V2 retains authenticated record headers and bounded location/key/
scope indexes; payloads are read from pinned segments on demand and their full
record digests are checked against the recovered headers. Startup still scans
and authenticates the complete WAL chain. V1 retains its payload read model
under the same resident gate. Reservations include owned string/array capacity,
repeated index strings and container growth slots. Dense JSON is checked before
DOM decoding; encoding and sidecars have independent finite allocation bounds.
These checks can refuse a record below its schema byte/count limit. The effective
encoded record/read bound is at most 16 MiB, and sidecars at most 16 MiB.

`get` reads one record. `visit_records` visits one authenticated payload at a
time and is used by job-journal recovery; callbacks must not reenter the store.
`replay` and `all_records` preserve their Vec APIs but return `CapacityExhausted`
before allocating a response above the cumulative working budget. `checkpoint`
may also refuse its snapshot working budget while the WAL, index and one-record
reads remain usable. Every exact duplicate identity remains retained at capacity;
unknown identity is never evicted. Older WAL/sidecar sets exceeding the new
resource bounds fail closed and must be preserved for reviewed migration.

Descriptors now share one linked-module256-slot RAII budget across v1/v2
instances. Each handle reserves16 control/recovery slots before touching paths;
each pinned segment reserves one before create/open. Arc clones retain the
original lease, and all files close before their slots are returned. At capacity
new handles/segments fail without evicting a live reader or losing identities.
A full240-segment handle uses the pool; joint migration/export may also refuse
capacity while both source/destination leases are required. Preserve both
lineages and their writer fence; reducing descriptor admission never licenses
source deletion or blind effect replay. On-demand payload reads use Unix
positioned I/O on the existing pinned File, preserving its offset and opening
no temporary descriptor. The append gate still serializes public read operations
with WAL publication; thread callers do not remove that consistency fence.

This is a source descriptor gate for files owned by this module; unrelated
module/OS descriptors still need their owners' budgets and installed measurement.
RAM remains32/64 MiB per-store logical resident/working limits. Multiple stores'
resident/transient memory, retained caller-owned Vec responses and allocator
costs still require shared memory admission; this FD fix does not close them.

`SegmentedEventStore::migrate_legacy` imports a validated v1 file without
changing event IDs, sequence numbers, payloads or hash-chain digests, and is
idempotent when the destination already contains the same sequence.

Its durability and scalability work is tracked by `GAP-JOURNAL-CONVERGENCE-001` and `GAP-CONC-EVENT-STORE-001`. Historical source-status prose has been removed; current state is generated under `docs/generated/`.

## Detailed contracts and local verification

- [MOD-EVENT-STORE](../../docs/modules/MOD-EVENT-STORE.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-event-store --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
