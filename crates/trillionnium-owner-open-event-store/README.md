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
records, 4 KiB identifiers/kinds, 1,024 open segments, 256 MiB per pending
group and a 24-hour group interval. Deployments can lower these values but
cannot use an unbounded `usize`/`u64` to turn recovery or buffering into an
allocation or file-descriptor exhaustion path; `SegmentedEventStoreConfig::try_new`
is available when a validated constructor result is needed.

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
