# MOD-ADB — ordinary ADB transport

This document is the detailed source-development, integration and qualification contract for `MOD-ADB`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-ADB`
- Module version: `1.0.0`
- Name: **ordinary ADB transport**
- Plane: `platform`
- Primary owner: `team-adb`
- Backup owner: `team-runtime`
- Maturity: `L1_SOURCE_L4_PENDING`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `packaging/owner-open-adb`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- byte-transparent ADB path.

Operationally, the required flow is:

The provider supplies an explicit ordinary ADB operation and target identity. The relay preserves bytes and target selection, executes through the declared client/server path, and returns raw bounded stdout, stderr, exit and transport observations.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

## 3. Non-goals and authority boundary

Explicit non-goals:

- serial injection.

The relay never injects a serial, roots a device, changes transport class, hides unauthorized/offline states or retries a visible mutation after an ambiguous disconnect.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-TOOL-RUNTIME`, `MOD-ROOTLINUX`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_adb.api.v1`
- Catalog input labels: `adb_request_v1`
- Catalog output labels: `adb_observation_v1`
- Catalog error labels: `adb_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `tools/owner-open/adb_smart_socket_relay_release.py` — `ReleaseRelay`
- Implementation source: `tools/owner-open/adb_smart_socket_relay_selected.py` — `EventWriter`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

`ReleaseRelay` selects the product entry identity; the shared `Relay`, `EventWriter`, `Limits` and `ConnectionState` implement its finite transport and lifecycle. The historical `owner_open_adb_relay_v2.py` is not this product entry. `packaging/owner-open-adb/verify_arm64_adb.py` validates artifact identity. Relay tests do not establish a physical target; unauthorized/offline states must remain raw observations and never trigger implicit serial selection.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_adb.state.v1`
- State authority: **authoritative**
- Partition key: `target_id`
- State owned: `ADB relay epoch; transport observations`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `target_id`
- Maximum declared concurrency: `16`
- Admission resource: `resource_contract.queue_items`
- Lease source: `module_instance_lease`
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

USB loss, server restart or device reboot advances the relay epoch. Accepted operations without terminal evidence remain unknown until the device and visible state are independently reconciled.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.


### Selected relay lifecycle and journal failure

The deployed entry is `tools/owner-open/adb_smart_socket_relay_release.py`.
`ReleaseRelay` changes only `selected_entry`; its shared implementation in
`adb_smart_socket_relay_selected.py` owns admission, task cleanup, publication
and shutdown. Maintaining a second copied accept/start implementation is not
required. Historical relay variants remain non-authoritative for this contract.

`EventWriter` completes every positive short write before flushing and syncing
one JSONL record. Zero, negative, non-integer or oversized write progress fails.
The committed byte and sequence counters advance only after the whole record,
flush and file fsync succeed. A write, flush, fsync or capacity failure fences
that writer permanently; it retains any partial/visible bytes, does not truncate
or append another record, and never manufactures a terminal for the lost event.
No log is created when optional logging is disabled, and its zero counters are
not evidence of durability. File fsync tests do not establish directory-entry
persistence, actual power-loss recovery or independently authorized custody.

A failed lifecycle event inhibits the whole relay instance, closes its listener,
prevents further upstream connections/forwarding, and makes normal `serve`
completion return nonzero. Connection cleanup and capacity release remain
possible without another successful journal append. The lifecycle journal is
not the Host's durable-before-effect acceptance log: an ADB connection record,
byte counter or clean socket close does not prove a remote operation succeeded,
was cancelled, or did not execute. Recovery never repeats an uncertain effect.

The listener is bound but not serving while the descriptor and ready observation
are prepared. Any startup failure closes it, including descriptor publication
failure in the release entry. Descriptor publication and ready observation are
separate operations: a retained descriptor alone is not proof of readiness,
continued liveness or a successful qualification run. Preserve partial output
for diagnosis instead of rerunning a semantic operation to obtain a receipt.

The transfer pair owns both pump tasks through normal completion, an error and
cancellation. One-direction EOF preserves the opposite half of the stream; an
error cancels and collects its sibling before the pair returns. Transfer and
watchdog owners are also collected before a connection releases its slot.
A close that exceeds the configured grace aborts its local transport instead
of retaining a backpressured socket. Aborting may discard undelivered buffered
bytes; it is not an acknowledgement or remote-effect cancellation.

Shutdown first stops admission and cancels connection owners, then waits for
listener closure. Waiting for the server before closing active clients would
make these operations wait on each other on current Python. A bounded initial
cancellation wait, a bounded second cancellation wait when needed, and a bounded
server-close wait each use `shutdown_grace`; an unconfirmed phase returns failure
and never reports a zero-task success. These are cooperative asyncio budgets,
not hard real-time bounds on synchronous filesystem I/O or OS scheduling.

The selected relay tests use real local TCP peers and temporary files, plus
explicit short-write, flush/fsync, task-error and descriptor-failure injection.
They cover clean half-close, error ownership, shutdown with live clients, failed
journal admission and cancellation. Release and qualification entrypoint suites
remain required to detect entry-identity or byte/argv changes. No fixture is a
physical-device, destructive-power-loss or installed-target observation.

## 11. Security and trust boundaries

The relay never injects a serial, roots a device, changes transport class, hides unauthorized/offline states or retries a visible mutation after an ambiguous disconnect.

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

Relay upgrades fence the previous transport epoch and require explicit target re-observation. No target or serial is inherited through an ambiguous reconnect.

Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

## 14. Observability

Retain devices output, selected target, relay and server epochs, byte counts, exit status, unauthorized/offline transitions, disconnect timing and visible-effect evidence references.

Every metric and log record is bounded and versioned. Required common dimensions are module ID, instance or service epoch, ordering-key digest, operation class and outcome. High-cardinality raw identifiers are hashed or retained only in access-controlled evidence. Readiness means the module can safely admit work; liveness alone is insufficient.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

### Reproduction entrypoint

- Verification source: `tools/tests/test_adb_smart_socket_relay_selected.py`
- Verification source: `tools/tests/test_release_qualification_paths_v2.py`

Run from the repository root in an isolated host source-test environment:

```sh
python3 -m unittest tools.tests.test_adb_smart_socket_relay_selected tools.tests.test_release_qualification_paths_v2 -v
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

## 16. Deployment and runbook

On target ambiguity, stop ADB mutation, capture `devices` and transport observations, require an explicit authorized target and reconcile the prior operation before any retry.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-PHYSICAL-ADB-001`, `GAP-FAULT-MATRIX-001`.

### GAP-PHYSICAL-ADB-001 — exit L4

Ordinary ADB and visible effects are proven on an authorized physical device.

Exit evidence must demonstrate:
- device enumeration and explicit target operation are retained.
- raw unauthorized, offline and failure output is retained.
- visible mutation and continued turn are observed.

### GAP-FAULT-MATRIX-001 — exit L5

Destructive crash, storage, disconnect, USB, reboot and power-loss cuts are executed.

Exit evidence must demonstrate:
- pre-cut durable state is bound.
- fault method is independently controlled.
- post-restart reconciliation is retained.
- redispatch count is zero.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
