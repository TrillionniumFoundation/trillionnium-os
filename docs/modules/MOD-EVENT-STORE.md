# MOD-EVENT-STORE — event durability and replay

This document is the detailed source-development, integration and qualification contract for `MOD-EVENT-STORE`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-EVENT-STORE`
- Module version: `1.0.0`
- Name: **event durability and replay**
- Plane: `state`
- Primary owner: `team-state-recovery`
- Backup owner: `team-job-runtime`
- Maturity: `SOURCE_SEGMENTED_INDEXED_PENDING_EVIDENCE`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `crates/trillionnium-owner-open-event-store`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- append-only observations.

Operationally, the required flow is:

Append validates a bounded event, selects a stable partition, writes the segment record and hash-chain metadata, advances indexes only at the declared durability boundary, and returns a cursor that can be used for indexed replay.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

## 3. Non-goals and authority boundary

Explicit non-goals:

- effect authorization.

The store records observations; it does not authorize effects, infer completion, silently repair an ambiguous fsync, or turn a missing record into proof that a process never started.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-PROTOCOL`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_event_store.api.v1`
- Catalog input labels: `event_append_v2`
- Catalog output labels: `event_query_v2`
- Catalog error labels: `event_store_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `crates/trillionnium-owner-open-event-store/src/lib.rs` — `SegmentedEventStore`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

`EventInput`, `EventRecord`, `SegmentedEventStoreConfig` and `RecoveryPolicy` define the append/replay boundary. `append_durable` forces acceptance/terminal authority through the durability barrier; ordinary grouped observations must not be mistaken for a durable acceptance.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_event_store.state.v1`
- State authority: **authoritative**
- Partition key: `store_partition`
- State owned: `turn event log; event indexes; record hash chain`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `store_partition`
- Maximum declared concurrency: `64`
- Admission resource: `resource_contract.queue_items`
- Lease source: `local_bounded_budget`
- Lock scope: `module-local per-key metadata guard`
- Backpressure: `reject_at_capacity`
- Timeout ceiling: `30000` milliseconds
- Lease expiry: `stop_new_admission_and_fence_authoritative_writes`
- Duplicate/conflict rule: `idempotent_duplicate_or_explicit_conflict`

Per-key operations are linearized while unrelated keys may progress concurrently. Process spawn, external I/O, fsync and provider waits are slow paths and must not execute under a global registry lock. At capacity, admission is rejected before starting a process or publishing an accepted effect.

The concrete EventStore source additionally serializes codecs/response builds
across stores on its shared temporary working lane. Metadata-only operations
retain their per-store locks. This conservative memory gate does not establish
the declared concurrency/latency SLO: callbacks and filesystem barriers still
require bounded embedding behavior and target measurements.

## 8. Effect, cancellation and uncertainty semantics

Automatic redispatch: **forbidden**.

Cancellation is targeted by exact request, call, job, turn, connection or module identity as appropriate. Cancellation requests and terminal completion races are serialized through the authoritative lifecycle transition. Cleanup frees resources but does not authorize a replacement effect.

An accepted operation lacking authoritative terminal evidence is `unknown` or reconciliation-required. A timeout, disconnect, restart, missing journal entry or process-leader exit is not proof that an external effect did not occur.

## 9. Resource budget and SLO status

Resource budget authority: `docs/machine/resource-budget-provenance.v1.json`.

| Contract item | Current source ceiling |
|---|---:|
| CPU weight | 100 |
| Memory | 67108864 bytes |
| File descriptors | 256 |
| Processes | 16 |
| Threads | 64 |
| I/O rate | 10485760 bytes/s |
| Queue items | 4096 |
| Queue bytes | 67108864 |
| Store bytes | 536870912 |
| Operation timeout | 30000 ms |
| Recovery target | 60000 ms |
| Provisional P99 target | 1000 ms |
| Provisional throughput target | 100/s |
| Provisional availability target | 99.0% |
| SLO recovery target | 60000 ms |
| SLO measurement window | 60 s |

Measurement status: **unmeasured until qualified evidence**.

These values are finite source-admission ceilings and provisional objectives, not benchmark results. They remain observe-only until workload profiles `WL-01` through `WL-12`, environment identity, samples, percentiles and resource observations are retained in a qualifying L2 package.

The segmented store retains at most 240 segment descriptors, leaving 16 of the
256-descriptor source ceiling for its root/lease, recovery and sidecar work.
Previously the hard segment ceiling was 1024. Rotation rejects an additional
segment before creating it; exact duplicates and retained replay remain usable.
Recovery rejects an over-ceiling directory before opening its segment set. This
is a compatibility restriction: an older store with more than 240 segments is
retained and fails closed; no automatic WAL deletion, effect replay or silent
compaction is permitted. Recovery requires an explicitly reviewed migration
that preserves every identity and hash-chain record.

V1/v2 handles now share a linked-module256-descriptor RAII pool:16 control/
recovery slots are acquired before touching the path and one slot before each
segment create/open. A capacity failure returns every partial-open reservation;
cloned Arc owners retain the same lease, and closed files return slots only
when the last owning handle drops. New handles/segments fail rather than evicting
an active reader. Concurrent source/destination migration/export can refuse
joint capacity; retain both WALs and the original writer fence. No temporary
budget bypass, deletion or redispatch is allowed to force that migration.
On-demand payload reads use the crate's existing Unix platform boundary and
`FileExt::read_exact_at` on the pinned File, without cloning a descriptor or
changing its offset. The existing segment mutex, before/after identity checks,
and public-read append gate remain in place. Concurrent callers are serialized
at that gate so they cannot observe a partially published WAL append.

RAM now uses two linked-module pools shared by every v1/v2 instance:32 MiB
resident plus32 MiB temporary, for a64 MiB combined source admission envelope.
State owns its noncloneable resident lease; pinned segments charge metadata,
pathnames and short read/sync path copies. Initial admission occurs before path
creation, append acquires growth before WAL/rotation, and partial recovery
returns every acquired lease. Arc clones preserve the same reservation until
the final owning handle drops. Accepted/uncertain IDs are never evicted.

Memory-intensive codecs/response builds serialize on a separate working lane;
the 32 MiB lease lasts across I/O/callbacks and unwinds on error/panic. The pool
accounting atomics never span those slow operations. An owned append argument
waiting for the lane first reserves its actual String/Value capacities in the
resident pool; capacity refusal prevents unbounded queued buffers. Caller-built
unadmitted arguments still require the caller's ingress budget. Callback code
must be bounded and must not call allocating EventStore APIs or blocking
JOB/EventStore working locks. Direct EventStore reentry fails capacity before
waiting; arbitrary cross-module callbacks do not gain a deadlock-free guarantee.

V2 retains only authenticated record headers and location/key/scope indexes.
Payloads are read from pinned
segments on demand, strictly decoded and digest-checked against those headers.
WAL recovery authenticates the whole chain while retaining only headers. V1
keeps its full read model within the same shared32 MiB gate. Reservations charge owned
capacities, repeated index strings and container growth; dense JSON has a
quote/escape-aware lexical allocation check before DOM decoding. The separate
shared32 MiB temporary pool bounds response construction and snapshot work;
`replay`/`all_records` may return `CapacityExhausted` before allocation.
`visit_records` reads one record at a time and supports journal recovery without
a whole-lineage payload clone. `visit_scope_records(scope, inclusive_turn_seq, callback)`
uses existing v2 scope-index ordinals and reads only that suffix, without cloning
all headers; v1 filters borrowed validated records. Both fence live identities
and lengths. Startup still authenticates the complete WAL chain; scoped reads
authenticate selected payloads against those startup headers and cannot grant
missing-prefix/restart coverage. Same-length drift in another scope is detected
by a read of that scope or full recovery; selected inspection does not reread it.

Encoding counts bytes without a DOM/Vec before allocation and preflights owned
input plus overlapping encoder buffers. New WAL records must also pass the
same combined encoded-buffer/JSON decode gate used at recovery. Duplicate v2
lookup counts the owned input beside the decoded payload; temporary refusal
never poisons or evicts its existing identity. Bounded read-line growth/shrink
reserves old/new buffers plus64 KiB fixed codec scratch. The record/read ceiling
is16 MiB minus32 KiB and two read-ahead bytes. Sidecars retain a16 MiB encoded
ceiling and a stricter combined decoder gate. Index encoding borrows headers
in store-sequence order instead of cloning the entire key table. Checkpoint
preflights its payload Vec and encoder growth and drops snapshot bytes before
index encoding. Snapshot/read-budget refusal happens before snapshot
publication and leaves the authoritative WAL unchanged. Schema byte/count limits do not override these
resident/working gates.

Migration fresh-scans each source record against the retained authenticated v1
view while preserving its writer fence, and borrows that view to reconcile one
destination payload at a time. Export moves one decoded payload to the v1
writer and freshly rescans the destination before reporting the export; neither
retains another full payload lineage. Both writer/resident/FD
leases remain required and joint capacity can refuse while preserving both WALs.

No uncertain key or accepted record is evicted. Over-budget historical WAL or
sidecars fail closed and are retained for reviewed migration; a new empty
journal must not substitute for that lineage. These source reservations do not
prove process RSS. Ordinary returned EventRecord/Value/Vec APIs transfer
ownership to the caller; an internal lease cannot follow an arbitrary later
clone/retention. Caller-owned responses/inputs/callback allocations, other
modules, allocator overhead and host/child RSS require their owners' budgets
and installed evidence. The conservative shared working lane also needs target
throughput/latency measurements before any concurrency/P99 objective is claimed.

## 10. Persistence, recovery and reconciliation

Startup validates segment headers, record checksums, hash-chain continuity and indexes. A repairable torn tail is truncated under an explicit recovery record; interior corruption is quarantined or causes fail-closed startup.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.

## 11. Security and trust boundaries

The store records observations; it does not authorize effects, infer completion, silently repair an ambiguous fsync, or turn a missing record into proof that a process never started.

Peer identity, process identity, executable or artifact digest, epoch, namespace and target identity are retained where relevant. Secrets and command content are redacted by default. Emergency inhibit is independent of provider health and prevents new admission without fabricating terminal outcomes.

## 12. Failure matrix and degraded behavior

| Failure | Required classification | Required behavior |
|---|---|---|
| Invalid or unsupported input | rejected-before-accept | no state mutation and no external start |
| Capacity exhausted | rejected-at-admission | no spawn, forward or durable accepted record |
| Timeout or disconnect before terminal proof | unknown/reconciliation-required | stop blind progress; preserve exact identity |
| Process or dependency exit | explicit failure or unknown | converge descendants and fence the epoch |
| Storage I/O or fsync ambiguity | degraded/fail-closed | stop authoritative writes; retain ambiguity |
| Corrupt state | quarantined or fail-closed | no automatic replay |
| Stale writer or lease | fenced | reject the write and emit an audit observation |
| Duplicate identity with changed content | conflict | never deliver the old terminal as the new result |

The degraded state is `fail_closed`. Recovery is `reconcile_before_resume`, and uncertain effects remain `no_automatic_redispatch`.

## 13. Compatibility, migration and rollback

Rolling compatibility is supported under the explicit compatibility and fencing contract. Read/write compatibility currently accepts `v1` and writes `v1` unless the module-specific migration below states otherwise.

v1 JSONL state migrates to v2 segmented state through fenced-prefix reconciliation; dual read and dual write are disabled.

Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

## 14. Observability

Expose append and flush latency, group size, segment size, index lag, replay range, recovery scan time, ENOSPC, checksum and quarantine counts.

Every metric and log record is bounded and versioned. Required common dimensions are module ID, instance or service epoch, ordering-key digest, operation class and outcome. High-cardinality raw identifiers are hashed or retained only in access-controlled evidence. Readiness means the module can safely admit work; liveness alone is insufficient.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

### Reproduction entrypoint

- Verification source: `crates/trillionnium-owner-open-event-store/tests/segmented.rs`

Run from the repository root in an isolated host source-test environment:

```sh
cargo test --locked -p trillionnium-owner-open-event-store --all-targets
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

## 16. Deployment and runbook

On storage faults, stop authoritative writes, preserve the affected media or image, capture the last verified cursor and fsync outcome, run read-only verification, and never replay an external effect merely because its terminal event is absent.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-JOURNAL-CONVERGENCE-001`, `GAP-CONC-EVENT-STORE-001`, `GAP-PERF-L2-BASELINE-001`, `GAP-PERF-SYSTEM-BASELINE-001`, `GAP-FAULT-MATRIX-001`.

### GAP-JOURNAL-CONVERGENCE-001 — exit L5

Storage failure and corruption converge without false no-start claims.

Exit evidence must demonstrate:
- ENOSPC and fsync ambiguity are classified.
- corruption quarantines or fails closed.
- recovery never performs blind effect replay.

### GAP-CONC-EVENT-STORE-001 — exit L2

Indexed segmented durability replaces a single-file single-lock hotspot.

Exit evidence must demonstrate:
- partitioned or serialized single-writer segments.
- bounded group commit.
- indexed replay.
- bounded recovery time.
- schema migration.

### GAP-PERF-L2-BASELINE-001 — exit L2

Installed WL-01 through WL-10 retain raw A1/A2/A3 and C1/C2/C3 batches,
complete applicable stage/resource counters and qualified stability/comparison.
WL-11 remains an L4 hold and WL-12 remains an L5 hold.

### GAP-PERF-SYSTEM-BASELINE-001 — exit L5

Mixed-workload throughput, latency, resource and recovery baselines are repeatable.

Exit evidence must demonstrate:
- WL-01 through WL-10 have installed L2 evidence, WL-11 has physical L4 evidence and WL-12 has destructive L5 evidence.
- The exact subject and continuous L1 through L5 evidence lineage bind every phase.
- P50, P95, P99 and maximum are recorded.
- CPU, RSS, FD, thread, process and I/O are recorded.
- system-objective delta gates changes.

### GAP-FAULT-MATRIX-001 — exit L5

Destructive crash, storage, disconnect, USB, reboot and power-loss cuts are executed.

Exit evidence must demonstrate:
- pre-cut durable state is bound.
- fault method is independently controlled.
- post-restart reconciliation is retained.
- redispatch count is zero.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
