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

All v1/v2 instances in this linked module share a 32 MiB resident pool and a
separate 32 MiB temporary pool, for a combined 64 MiB admission envelope.
Each handle owns its fixed reserve and retained record/index leases; segment
metadata and pathname capacity have separate charges. Arc clones share these
leases until the final owner drops. An append reserves growth before WAL bytes
or a rotated segment are written; recovery charges each retained record/header
and releases every partial reservation on refusal. Capacity never evicts an
accepted or uncertain identity. V2 retains authenticated headers and location/key/
scope indexes; payloads are read from pinned segments on demand and their full
record digests are checked against the recovered headers. Startup still scans
and authenticates the complete WAL chain. V1 retains its payload read model
under the same shared resident gate. Reservations include owned capacities,
repeated index strings and container growth slots. Heavy codecs/response builds
serialize on a separate working lane whose lease survives callbacks, I/O and
unwind; accounting atomics are never locked across those operations. An owned
append argument waiting for that lane first reserves its actual input capacity
in the resident pool, or receives `CapacityExhausted`. Caller-built unadmitted
input memory belongs to the caller's ingress budget.

Encoding counts bytes before allocating; input capacity and overlapping encoder
buffers are preflighted together. New records also pass the recovery decode
gate before WAL mutation. Dense JSON, encoded buffers and parser/container
growth are counted before DOM decoding. Read-line growth/shrink fits the same
temporary peak. The effective encoded record/read ceiling is 16 MiB minus
32 KiB and two read-ahead bytes; sidecars retain a 16 MiB encoded ceiling with a
stricter combined decode gate. These gates can refuse below schema limits.

`get` reads one record. `visit_records` visits one authenticated payload at a
time and is used by complete job-journal recovery. `visit_scope_records` uses
the existing v2 scope index and reads only its selected sequence suffix. It
still validates live inode/length fences and each payload against the startup
header; startup always authenticates the complete WAL chain. The v1 visitor
borrows its authenticated read model. Callbacks must remain bounded and must
not enter allocating EventStore APIs or blocking JOB/EventStore working locks;
direct EventStore reentry receives `CapacityExhausted`. Arbitrary callback
allocation and cross-module lock ordering remain the embedding caller's duty.
`replay` and `all_records` preserve their Vec APIs but return `CapacityExhausted`
before allocating a response above the cumulative working budget. `checkpoint`
may also refuse its snapshot working budget while the WAL, index and one-record
reads remain usable. Duplicate lookup also counts the supplied owned argument
alongside the decoded record; temporary refusal leaves the store healthy.
Every exact duplicate identity remains retained at capacity;
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

Index publication serializes borrowed headers in store order, without cloning
the full key map. Checkpoint separately reserves retained payloads and encoder
growth, and drops snapshot bytes before index encoding. Capacity refusal
preserves the authoritative WAL; older over-budget sidecars/lineages fail closed.

These are source budgets for this linked module's admitted storage/codecs.
Ordinary returned `EventRecord`/`Value`/Vec ownership transfers to the caller;
the public API cannot attach a lease to a later arbitrary clone or retention.
Other modules, caller-owned responses/inputs/callback allocations, allocator
overhead and process/child RSS require their own accounting and installed
measurement. A combined 64 MiB source envelope does not prove 64 MiB process RSS.
The conservative shared working lane also requires throughput/latency evidence.

`SegmentedEventStore::migrate_legacy` imports a validated v1 file without
changing event IDs, sequence numbers, payloads or hash-chain digests, and is
idempotent when the destination already contains the same sequence. Migration
freshly scans and compares one source record to its authenticated v1 view, then
borrows that original view while reconciling one destination record at a time.
Rollback/export transfers one decoded payload into the v1 writer and freshly
rescans that destination before reporting success. Neither keeps
a second full payload lineage. Both writer fences and shared leases remain
required; joint capacity can still refuse without deleting either lineage.

Its durability and scalability work is tracked by `GAP-JOURNAL-CONVERGENCE-001` and `GAP-CONC-EVENT-STORE-001`. Historical source-status prose has been removed; current state is generated under `docs/generated/`.

## Detailed contracts and local verification

- [MOD-EVENT-STORE](../../docs/modules/MOD-EVENT-STORE.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-event-store --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
