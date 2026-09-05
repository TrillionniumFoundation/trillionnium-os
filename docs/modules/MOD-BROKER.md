# MOD-BROKER — connection broker and ingress

This document is the detailed source-development, integration and qualification contract for `MOD-BROKER`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-BROKER`
- Module version: `1.0.0`
- Name: **connection broker and ingress**
- Plane: `execution`
- Primary owner: `team-broker`
- Backup owner: `team-transport`
- Maturity: `SOURCE_MUX_PENDING_EVIDENCE`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `tools/owner-open`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- peer admission.

Operationally, the required flow is:

A peer is authenticated and admitted, the broker assigns immutable request ownership and sequence metadata, capacity is reserved, and bytes are forwarded without semantic rewriting. Terminal delivery is accepted only when identity, digest, ordering lineage and broker-assigned sequence match the live request owner.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

## 3. Non-goals and authority boundary

Explicit non-goals:

- intent interpretation.

The broker is a mechanical ingress boundary. It may authenticate a peer, enforce framing and finite budgets, and reject a request. It may not infer intent, alter a command, inject an ADB target, downgrade a target, synthesize success, or retry an uncertain effect.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-PROTOCOL`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_broker.api.v1`
- Catalog input labels: `broker_request_v2`
- Catalog output labels: `broker_response_v2`
- Catalog error labels: `broker_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `tools/owner-open/owner_open_broker_mux.py` — `WeightedFairMux`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

`enqueue`, `acquire`, `match` and `complete` operate on an immutable request owner and the complete ordering key. The live and retired request maps separate a late terminal from a new request; a timeout does not free an uncertain ordering key for blind redispatch.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_broker.state.v1`
- State authority: **authoritative**
- Partition key: `client_id`
- State owned: `broker request audit`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `client_id`
- Maximum declared concurrency: `64`
- Admission resource: `resource_contract.queue_items`
- Lease source: `local_bounded_budget`
- Lock scope: `module-local per-key metadata guard`
- Backpressure: `reject_at_capacity`
- Timeout ceiling: `30000` milliseconds
- Lease expiry: `stop_new_admission_and_fence_authoritative_writes`
- Duplicate/conflict rule: `idempotent_duplicate_or_explicit_conflict`

Per-key operations are linearized while unrelated keys may progress concurrently. Process spawn, external I/O, fsync and provider waits are slow paths and must not execute under a global registry lock. At capacity, admission is rejected before starting a process or publishing an accepted effect.

### Connection lifetime admission and exact worker ownership

`--max-clients` bounds accepted socket lifetimes, not only authenticated client
IDs. `ClientWorkers.start_reader` reserves a slot under its metadata lock before
creating a reader thread. A full or closed pool shuts down the new socket
without creating a worker, authenticating a client, admitting a request, or
forwarding an effect. The kernel listen backlog is separate from these slots.

Each slot owns exactly one reader and at most one writer. A disconnected client
ID becoming reusable does not free the connection slot: both threads must have
actually terminated. Reaping occurs on admission and bounded snapshots/joins;
completed clients never accumulate in the static `worker_threads` history.
An interrupted thread start whose native identity is not yet observable retains
its slot as unconfirmed rather than proving that no worker exists.

The concrete worker bound is `2 * max_clients + max_inflight_requests + 3`,
excluding the main thread and interpreter-internal threads. The three static
workers are upstream stderr, upstream reader and timeout monitor. Defaults
(`max_clients=16`, `max_inflight_requests=16`) therefore allow at most 51 broker
workers. This formula is a source bound, not a measured RSS/CPU/FD result or a
claim that every permitted non-default configuration fits a particular device.

The hello receive deadline is five monotonic seconds from slot reservation,
including reader scheduling delay. Byte trickling and interrupted readiness
waits cannot extend it. After successful authentication, this hello deadline is
removed; per-request timeouts and the existing line-byte bound still apply.
`SocketLineReader` buffers at most the requested line bound, preserves bytes
following the hello newline, and uses per-call nonblocking reads without
changing the writer's socket mode. It retains a duplicate socket descriptor and
one selector descriptor, both closed with the reader: closing the original
socket cannot silently unregister the selected FD before shutdown wakes it.

Shutdown fences admission, shuts down every registered socket (including
unauthenticated peers), and joins client workers with one total one-second
budget. An unconfirmed worker produces a nonzero broker shutdown result; it is
never reported as a clean exit. Closing a connection does not cancel or replay
an already accepted effect; existing durable convergence retains that authority.

- Implementation source: `tools/owner-open/owner_open_broker_connections.py` — `ClientWorkers`
- Implementation source: `tools/owner-open/owner_open_broker_connections.py` — `SocketLineReader`

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

After disconnect or restart, the broker reconstructs accepted request ownership from the journal, fences stale writers and classifies requests without authoritative terminal evidence as unknown/reconciliation-required. It never reuses a late terminal for a different request.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.

## 11. Security and trust boundaries

The broker is a mechanical ingress boundary. It may authenticate a peer, enforce framing and finite budgets, and reject a request. It may not infer intent, alter a command, inject an ADB target, downgrade a target, synthesize success, or retry an uncertain effect.

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

Rolling compatibility is not supported across a live mixed-version boundary. Read/write compatibility currently accepts `v1` and writes `v1` unless the module-specific migration below states otherwise.

The active v1 broker state has no declared cross-version migration; a rollout fences old writers, drains accepted requests and resumes from the retained journal.

Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

## 14. Observability

Retain bounded accepted, forwarded, terminal, timeout, disconnect, duplicate and conflict records keyed by broker sequence and request digest. Payload logging is disabled by default.

Every metric and log record is bounded and versioned. Required common dimensions are module ID, instance or service epoch, ordering-key digest, operation class and outcome. High-cardinality raw identifiers are hashed or retained only in access-controlled evidence. Readiness means the module can safely admit work; liveness alone is insufficient.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

### Reproduction entrypoint

- Verification source: `tools/tests/test_owner_open_broker_mux.py`
- Verification source: `tools/tests/test_owner_open_broker_connections.py`

Run from the repository root in an isolated host source-test environment:

```sh
python3 -m unittest tools.tests.test_owner_open_broker_mux tools.tests.test_owner_open_broker_connections -v
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

## 16. Deployment and runbook

On correlation alarms, stop new admission for the affected client key, preserve the journal and raw bounded transport observations, fence the connection epoch, and reconcile each accepted request before reopening.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-BROKER-CORRELATION-001`, `GAP-CONC-BROKER-MUX-001`, `GAP-PERF-SYSTEM-BASELINE-001`, `GAP-FAULT-MATRIX-001`.

### GAP-BROKER-CORRELATION-001 — exit L2

Accepted, forwarded and terminal records bind to exact request ownership.

Exit evidence must demonstrate:
- same-kind late responses cannot cross-deliver.
- startup failure reaps upstream.
- installed broker evidence passes.

### GAP-CONC-BROKER-MUX-001 — exit L2

Bounded multi-inflight multiplexing preserves exact ownership and fairness.

Exit evidence must demonstrate:
- per-ordering-key serialization.
- cross-key parallelism.
- weighted fairness.
- exact late-result isolation.
- no automatic redispatch.

### GAP-PERF-SYSTEM-BASELINE-001 — exit L2

The Broker participates in the system baseline; source fairness and correlation
tests do not establish installed throughput or latency. Run WL-01 through WL-12
on the qualified installation and retain P50/P95/P99/max latency, CPU, RSS, file
descriptors, threads, processes and I/O with the exact source and workload IDs.
Record per-key queue delay, cross-key progress and cancellation/control latency
under output backpressure. Compare system objective deltas before changing
inflight capacity, weights or queue limits. This gap remains pending L2 evidence.

### GAP-FAULT-MATRIX-001 — exit L5

Destructive crash, storage, disconnect, USB, reboot and power-loss cuts are executed.

Exit evidence must demonstrate:
- pre-cut durable state is bound.
- fault method is independently controlled.
- post-restart reconciliation is retained.
- redispatch count is zero.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
