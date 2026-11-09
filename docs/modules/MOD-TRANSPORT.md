# MOD-TRANSPORT — bounded transport carrier

This document is the detailed source-development, integration and qualification contract for `MOD-TRANSPORT`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-TRANSPORT`
- Module version: `1.0.0`
- Name: **bounded transport carrier**
- Plane: `execution`
- Primary owner: `team-transport`
- Backup owner: `team-execution-core`
- Maturity: `SOURCE_BOUNDED_SEGMENTED_PENDING_EVIDENCE`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `apps/trillionnium-owner-open-host/src/bin/r5_transport_host`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- frame forwarding.

Operationally, the required flow is:

The transport validates a bounded frame, reserves connection-local capacity, preserves broker identity and ordering metadata, and forwards bytes. Stream credit regulates data frames; zero data credit must not starve control frames needed for cancellation, terminal reporting or recovery.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

## 3. Non-goals and authority boundary

Explicit non-goals:

- semantic cancellation.

The carrier is byte-oriented and mechanism-only. It cannot interpret commands, invent semantic cancellation, select a device, transform a terminal outcome or bypass peer authentication.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-PROTOCOL`, `MOD-STREAM`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_transport.api.v1`
- Catalog input labels: `transport_frame_v1`
- Catalog output labels: `transport_delivery_v1`
- Catalog error labels: `transport_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `apps/trillionnium-owner-open-host/src/bin/r5_transport_host.rs` — `main`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

The selected `trillionnium-owner-open-r5-host` binary composes transport flow control, the core child and a delivery journal. Data cursors and control-frame sequences are different domains. Inspect the `src/bin/r5_transport_host/` implementation before changing replay or broker correlation.

### Scoped cursor recovery extension

The direct Host envelope remains `trillionnium.agent.turn.v1`. Its bounded
payload extension is separately identified by `scoped_cursor_v1`; the abstract
module API/state/error envelope schemas do not acquire new required fields.
`hello.ack.payload.resync_protocols` advertises this extension, with
`legacy_numeric_resume_after_gap=false` and `max_resync_cursor_scopes=64`.
The client opts into it by sending `resync_protocol="scoped_cursor_v1"` on the
recovering `stream.resume`; an unknown extension is rejected explicitly.

`stream.resync_required.payload.required_resumes` is a bounded array. Each
member contains `cursor_domain`, `cursor_scope`, `first_missing_cursor`,
`last_missing_cursor` and the exclusive `required_resume_cursor`. The scope
contains all five `session_id`, `profile_id`, `task_id`, `turn_id` and
`turn_stream_id` values, plus `job_id` for `job_runtime_event` or
`job_journal_record`. `transport_event` has no job identity. Different jobs,
including jobs from an older turn still emitting during the active turn, retain
separate ranges. Interleaving A/B/A never merges unrelated ordinals. Legacy
single-range fields remain diagnostic; only `required_resumes` authorizes the
new recovery path.

A consumer inspects `transport_event` through `turn.inspect` with the accepted
turn request digest, and job domains through `job.inspect` with that job's
complete scope. Runtime requests use `inclusive_cursor`; journal requests use
`durable_inclusive_cursor`. The returned `next_cursor` or `durable_next_cursor`
is exclusive. Pages must start at the previous exclusive cursor and contain
every ordinal up to the next cursor, without a missing prefix. Transport event
IDs must agree with their durable turn ordinals. Runtime inspection with
`resync_required=true`, a non-null `gap`, or an older unavailable prefix does not
cover that runtime range. `durable_fallback_available` offers observations in a
different domain and does not prove that a missing runtime ordinal was recovered.
An unavailable journal or exhausted cursor remains unresolved.

The transport records coverage only from actual read-only inspector responses
with the exact scope and domain. A `stream.resume` then supplies
`resumed_cursors`, one member per required range, containing `cursor_domain`,
`cursor_scope` and `resumed_through_cursor`. Every claim must reach its required
exclusive cursor and be no further than contiguous server-issued coverage.
Missing, duplicate, stale, cross-job or cross-domain acknowledgements fail before
mutating control history or clearing the gap. New output can extend the range
while inspection is in progress; a rejected resume publishes the current gap
again, including `next_control_seq`, so a consumer can inspect the new suffix. The explicit acknowledgement is
the client's claim that it consumed the pages; server issuance alone does not
prove client consumption. Neither step dispatches or retries an effect.

The range table is capped at 64 entries. Any missing scope/cursor, ordinal
exhaustion or table overflow sets `cursor_scopes_complete=false`; partial known
ranges cannot authorize whole-gap recovery. The peer must preserve uncertainty
and perform explicit reconciliation. Terminal gaps retain this description but
a retired turn has no active flow window to resume. The Android codec's
`OwnerOpenFrame.RecoveryPlan` validates each page before constructing resume;
it permits at most 4096 pages, 256 observations per request and signed 64-bit
cursors. Unsupported larger ordinals fail explicitly. Client callers consume
returned observations before acknowledging them; these source mechanisms do
not supply installed-target qualification.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_transport.state.v1`
- State authority: **authoritative**
- Partition key: `connection_id`
- State owned: `transport delivery journal`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `connection_id`
- Maximum declared concurrency: `64`
- Admission resource: `resource_contract.queue_items`
- Lease source: `local_bounded_budget`
- Lock scope: `module-local per-key metadata guard`
- Backpressure: `reject_at_capacity`
- Timeout ceiling: `30000` milliseconds
- Lease expiry: `stop_new_admission_and_fence_authoritative_writes`
- Duplicate/conflict rule: `idempotent_duplicate_or_explicit_conflict`

Per-key operations are linearized while unrelated keys may progress concurrently. Process spawn, external I/O, fsync and provider waits are slow paths and must not execute under a global registry lock. At capacity, admission is rejected before starting a process or publishing an accepted effect.

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

## 10. Persistence, recovery and reconciliation

On reconnect, the new connection epoch fences the prior writer. Resume uses retained cursors and exact missing ranges; ambiguity produces a gap or unknown result rather than a fabricated continuous stream.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.

## 11. Security and trust boundaries

The carrier is byte-oriented and mechanism-only. It cannot interpret commands, invent semantic cancellation, select a device, transform a terminal outcome or bypass peer authentication.

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

For `scoped_cursor_v1`, the durable state version is unchanged: coverage and
credit are connection/turn-local, and existing journals retain bounded opaque
payloads. Upgrade the Host and recovery-aware client together. Older clients can
still pause, add credit and resume a gap-free window, but receive an explicit
conflict if they attempt bare numeric recovery after a gap. A new client must
check the advertised protocol before building a recovery plan; against an older
Host it leaves the gap unresolved. There is no automatic downgrade to unscoped
recovery. Rollback fences the connection and reinspects durable observations;
it does not carry volatile recovery coverage into the older binary. This is an
explicitly versioned wire behavior change, not a migration/release approval or
an assertion that rolling installed recovery has been tested.


Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

## 14. Observability

Expose frame counts and bytes by class, credit exhaustion, control-frame latency, cursor gaps, reconnect epochs and bounded queue depth. Redact payload bytes.

Every metric and log record is bounded and versioned. Required common dimensions are module ID, instance or service epoch, ordering-key digest, operation class and outcome. High-cardinality raw identifiers are hashed or retained only in access-controlled evidence. Readiness means the module can safely admit work; liveness alone is insufficient.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

### Reproduction entrypoint

- Verification source: `apps/trillionnium-owner-open-host/tests/r5_stream_flow_control.rs`

Run from the repository root in an isolated host source-test environment:

```sh
cargo test --locked -p trillionnium-owner-open-host --test r5_stream_flow_control
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

## 16. Deployment and runbook

For a stalled stream, inspect credit, control-channel liveness and the last durable cursor. Preserve both endpoints' epochs and do not reset cursors until reconciliation proves the missing interval.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-STREAM-RECOVERY-001`, `GAP-BROKER-CORRELATION-001`, `GAP-PRODUCT-ENTRYPOINT-001`, `GAP-CONC-BROKER-MUX-001`, `GAP-FAULT-MATRIX-001`.

### GAP-STREAM-RECOVERY-001 — exit L2

Bounded output, exact cursor gaps and target reconnect behavior are proven.

Exit evidence must demonstrate:
- zero stream credit does not block control.
- missing cursor ranges are exact.
- resume never redispatches an effect.

### GAP-BROKER-CORRELATION-001 — exit L2

Accepted, forwarded and terminal records bind to exact request ownership.

Exit evidence must demonstrate:
- same-kind late responses cannot cross-deliver.
- startup failure reaps upstream.
- installed broker evidence passes.

### GAP-PRODUCT-ENTRYPOINT-001 — exit L3

One install manifest selects the product entrypoint and internal children.

Exit evidence must demonstrate:
- source entrypoint is unambiguous.
- target-files contain the exact selected binaries.
- foundation stubs are absent from product inventory.

### GAP-CONC-BROKER-MUX-001 — exit L2

Bounded multi-inflight multiplexing preserves exact ownership and fairness.

Exit evidence must demonstrate:
- per-ordering-key serialization.
- cross-key parallelism.
- weighted fairness.
- exact late-result isolation.
- no automatic redispatch.

### GAP-FAULT-MATRIX-001 — exit L5

Destructive crash, storage, disconnect, USB, reboot and power-loss cuts are executed.

Exit evidence must demonstrate:
- pre-cut durable state is bound.
- fault method is independently controlled.
- post-restart reconciliation is retained.
- redispatch count is zero.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
