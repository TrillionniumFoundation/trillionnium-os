# MOD-TELEMETRY — telemetry and objective projection

This document is the detailed source-development, integration and qualification contract for `MOD-TELEMETRY`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-TELEMETRY`
- Module version: `1.0.0`
- Name: **telemetry and objective projection**
- Plane: `state`
- Primary owner: `team-telemetry`
- Backup owner: `team-performance`
- Maturity: `PLANNED_READ_MODEL_COST_CURVE_SOURCE_COMPLETE_PENDING_CI`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Metric authority: `docs/machine/metric-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `planned/crates/trillionnium-telemetry`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- SLI collection.

Operationally, the required flow is:

Modules emit bounded typed samples; telemetry validates identity, units, clock and epoch, aggregates finite windows and produces objective projections with source and coverage metadata.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

## 3. Non-goals and authority boundary

Explicit non-goals:

- command-content logging by default.

Telemetry excludes command content, prompts, credentials and user data by default. Metrics are observations, not authority, and cannot trigger semantic action directly.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-PROTOCOL`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_telemetry.api.v1`
- Catalog input labels: `telemetry_sample_v1`
- Catalog output labels: `objective_projection_v1`
- Catalog error labels: `telemetry_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `planned/crates/trillionnium-telemetry/src/lib.rs` — `MetricSample`
- Catalog-bound ingestion: `planned/crates/trillionnium-telemetry/src/catalog.rs` — `MetricCatalog`, `CatalogIngestor`, `MetricProjection`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

`MetricSample` contains finite measurements, `MetricWindow` retains bounded samples, and `ModuleReadModelStore`/`CostCurveStore` form derived views. `MetricCatalog` binds every metric to its unit, value type, source module, collection point, aggregation, retention, cardinality ceiling, privacy class, required and forbidden dimensions, sampling, missing-data meaning, clock and evidence level. `CatalogIngestor` rejects stale epochs, unit/source drift, unknown or sensitive dimensions, cardinality overflow and conflicting sequence reuse; it retains sequence loss, clock regression and window eviction as explicit coverage gaps. `project_objective` is a calculation, not evidence of a measured target. Hashing an identifier does not reduce its metric-label cardinality.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_telemetry.state.v1`
- State authority: **authoritative**
- Partition key: `module_instance_id`
- State owned: `metric windows; objective projections`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `module_instance_id`
- Maximum declared concurrency: `16`
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

After restart, only durable complete windows are loaded. Clock jumps, missing samples, eviction or mixed epochs create explicit coverage gaps rather than interpolated certainty. A projection may carry `durable_complete=true` only when it is coverage-complete and the owning store supplies a source-bound journal digest plus successful file and parent-directory fsync receipt. Source construction of that receipt is not installed-target evidence.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.

### Catalog admission, temporal receipts and retention

`CatalogIngestor` resolves every dimension through the immutable dimension
catalog. In v1 there are no optional dimensions: a metric's
`required_dimensions` is its complete allowed set. Even a registered global
key is rejected when that metric does not declare it. A restricted dimension
requires a restricted metric and a redacted event. Distinct values per dimension
are bounded across all metrics, instances and epochs in one ingestor lifetime;
series churn does not reset that budget. Instance and stream identity maps are
also bounded by `max_series`. Resetting an ingestor is not a proof of continuity.

The v1 `MetricEvent.value` wire is `f64`. `U64_COUNT` therefore admits only
integer-valued, finite values in `[0, 2^53-1]`, not the full u64 range. Values at
`2^53`, the rounded `u64::MAX as f64` boundary (`2^64`), fractions and nonfinite
values are rejected. Producers must not round larger counters into this wire;
full-width counters require a separately versioned typed integer representation.
Projection sum/mean remain floating-point descriptive statistics, not exact
integer accounting or evidence of a measured target.

A series identity now binds module instance, control epoch and dimensions, so
unrelated monotonic clock domains never evict each other's observations. Its
sample capacity is the minimum of the caller limit and the metric's catalog
`retention.max_samples`. Accepted observations advance an event-time watermark;
retention is the interval `(watermark - window_seconds, watermark]`. Expiration
is applied at ingestion, not by a wall-clock timer. An idle series/projection is
an as-of-last-observation snapshot and makes no currentness or background-GC
claim. Expiration increments the drop count and records `TIME_WINDOW_EVICTION`;
capacity eviction records `WINDOW_EVICTION`. A forward step greater than the
window records `CLOCK_JUMP`, including a genuine long sampling absence rather
than pretending it proves a faulty clock. All these gaps prevent a
`durable_complete` claim. Gap history is retained, not silently cleared when a
new window begins.

Admission preflights dimensions, identity/series capacity, exact duplicate and
conflict handling, every required gap slot, retention and counter overflow under
one metadata lock. It then commits once without fallible operations; it does
not clone the whole store. Every returned `Err` leaves **all** maps, windows,
last-event/rejection records, counters and gaps unchanged. Allocation failure or
panic is not claimed as a recoverable rejection.

A late sequence or regressed/equal clock on an admitted stream is a separate
explicit diagnostic transaction: `Ok` with `accepted=false`,
`idempotent_duplicate=false`, `coverage_complete=false`, and a retained
`LATE_OBSERVATION` or `CLOCK_REGRESSION` gap. It does not consume the valid stream
sequence or enter a sample window. An exact repeat of the last such diagnostic
returns `idempotent_duplicate=true` without growing state. If the diagnostic
cannot be retained, admission returns `Err` and changes nothing. A conflicting
same-sequence sample remains an error. Callers must inspect receipt acceptance;
`Ok` alone never acknowledges a sample, effect, persistence or target success.

These stricter v1 source admission rules, series-digest inputs and new gap enum
values require consumer compatibility review before deployment. They do not
migrate persisted state or inherit old review/CI credit. Regressions snapshot
every internal state family after capacity/overflow rejection, exercise
concurrent duplicate admission, and test all catalog metrics against their
actual sample/time limits. No fixture supplies L2 measurements or active control.

## 11. Security and trust boundaries

Telemetry excludes command content, prompts, credentials and user data by default. Metrics are observations, not authority, and cannot trigger semantic action directly.

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

Metric windows are versioned read models. An upgrade starts a new projection version and preserves old windows until comparison and rollback criteria are met.

Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

## 14. Observability

The module is the observation surface: sample acceptance, redaction, cardinality, window completeness, clock skew, projection coverage and storage pressure are themselves measured.

Every metric and log record is bounded and versioned. `docs/machine/metric-catalog.v1.json` is the closed machine authority and `docs/generated/METRIC_STATUS.md` is its generated view. Required common dimensions are module ID, instance or service epoch, operation class and outcome; privacy-restricted series additionally require a pseudonymous ordering-key digest. Command text, prompts, credentials, secrets, raw user input, model messages, tool arguments, semantic intent and retry instructions are forbidden dimensions. Readiness means the module can safely admit observations; liveness alone is insufficient.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

### Reproduction entrypoint

- Verification source: `planned/crates/trillionnium-telemetry/src/lib.rs`

Run from the repository root in an isolated host source-test environment:

```sh
cargo test --locked --manifest-path planned/Cargo.toml -p trillionnium-telemetry --all-targets
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

## 16. Deployment and runbook

On cardinality or privacy alarms, reject new high-cardinality dimensions, preserve schema and source identity, freeze dependent active-control promotion and review redaction before resuming.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-PERF-SYSTEM-BASELINE-001`, `GAP-CONTROL-PLANE-SHADOW-001`.

### GAP-PERF-SYSTEM-BASELINE-001 — exit L2

Mixed-workload throughput, latency, resource and recovery baselines are repeatable.

Exit evidence must demonstrate:
- WL-01 through WL-12 run.
- P50, P95, P99 and maximum are recorded.
- CPU, RSS, FD, thread, process and I/O are recorded.
- system-objective delta gates changes.

### GAP-CONTROL-PLANE-SHADOW-001 — exit L2

The mechanical global controller operates in observe and shadow before active control.

Exit evidence must demonstrate:
- leases include epoch, expiry and fencing.
- shadow decisions are reproducible.
- controller outage preserves bounded local operation.
- no semantic authority enters the controller.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
