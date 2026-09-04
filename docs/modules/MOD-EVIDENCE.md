# MOD-EVIDENCE — qualification and release evidence

This document is the detailed source-development, integration and qualification contract for `MOD-EVIDENCE`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-EVIDENCE`
- Module version: `1.0.0`
- Name: **qualification and release evidence**
- Plane: `evidence`
- Primary owner: `team-evidence`
- Backup owner: `team-security-release`
- Maturity: `L1_SOURCE`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `docs/machine/evidence-index.v1.json`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- L0-L6 evidence schemas.

Operationally, the required flow is:

A verifier binds a package to the exact repository, base, head, tree, ordered merge, run, artifact and role subject; downloads and hashes retained artifacts; validates detached signatures and trust roots when required; and proposes only evidence-supported transitions.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

## 3. Non-goals and authority boundary

Explicit non-goals:

- synthetic target evidence.

A self-hash is integrity metadata, not external authorization. Repository writers cannot mint independent review, installed-target facts, destructive-fault results, signing custody or release authority.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-PROTOCOL`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_evidence.api.v1`
- Catalog input labels: `evidence_package_v1`
- Catalog output labels: `evidence_index_v1`
- Catalog error labels: `evidence_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `tools/verify-g1-evidence.py` — `main`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

The CLI delegates to strict package verification; `verify-g1-evidence-live.py` binds current external objects. The checked-in evidence index is navigation, not a durable runtime journal or signer. A source fixture is never a substitute for an independent operator, reviewer, detached attestation or release decision.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_evidence.state.v1`
- State authority: **authoritative**
- Partition key: `evidence_id`
- State owned: `evidence index; promotion records`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `evidence_id`
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

Evidence is immutable. Revocation, expiry, subject movement or ambiguous external observation invalidates promotion and leaves the gap open. Reconciliation adds a new signed record rather than altering history.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.

### Immutable intake implementation

`tools/evidence/g1_evidence_core.py::_verify_evidence_snapshot` owns the single
package/gap snapshot. `tools/evidence/g1_evidence.py::verify_evidence_directory`
uses that same snapshot for retention and continuous-lineage checks, without
reopening package files after signature verification. The original report API
and v2 evidence/attestation schemas are unchanged.

`load_trusted_attestation` retains digest-bound raw bytes. Signature verification
uses sealed Linux memfds for key/signature input and sends the retained receipt
to OpenSSL over stdin, from a neutral working directory and finite environment.
Original paths are provenance only, not verification inputs. Missing memfd,
sealing, procfs or the system OpenSSL fails closed. Input size ceilings and
single-link/no-symlink rules are defined in
`docs/QUALIFICATION_AND_EVIDENCE.md`, section 2.3; they do not assert target RSS.

## 11. Security and trust boundaries

A self-hash is integrity metadata, not external authorization. Repository writers cannot mint independent review, installed-target facts, destructive-fault results, signing custody or release authority.

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

Evidence schemas are append-only and versioned. A new verifier may accept older packages only through an explicit compatibility matrix; signed subjects are never rewritten.

Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

## 14. Observability

Record verifier version, exact subject, API object identities, artifact digests and retention, signer and trust-root identity, authorization role, expiry, revocation and every rejected claim.

Every metric and log record is bounded and versioned. Required common dimensions are module ID, instance or service epoch, ordering-key digest, operation class and outcome. High-cardinality raw identifiers are hashed or retained only in access-controlled evidence. Readiness means the module can safely admit work; liveness alone is insufficient.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

### Reproduction entrypoint

- Verification source: `tools/tests/test_g1_evidence.py`

Run from the repository root in an isolated host source-test environment:

```sh
python3 -m unittest tools.tests.test_g1_evidence -v
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

## 16. Deployment and runbook

On evidence mismatch, stop promotion, preserve packages and detached material, re-fetch authoritative objects, verify currentness and revocation, and require a new independently administered attestation for a changed subject.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-DOC-SINGLE-TRUTH-001`, `GAP-GOVERNANCE-001`, `GAP-FAULT-MATRIX-001`, `GAP-RELEASE-001`.

### GAP-DOC-SINGLE-TRUTH-001 — exit L1

One machine truth generates every current-state and traceability view.

Exit evidence must demonstrate:
- legacy global documents are absent from the working tree.
- generated views match machine truth.
- exact-head CI and an eligible independent review pass.

### GAP-GOVERNANCE-001 — exit L1

Protected integration binds exact-head checks and a non-author approval.

Exit evidence must demonstrate:
- required checks pass on the exact integration head.
- approval is bound to that same head.
- there is no direct unreviewed integration.

### GAP-FAULT-MATRIX-001 — exit L5

Destructive crash, storage, disconnect, USB, reboot and power-loss cuts are executed.

Exit evidence must demonstrate:
- pre-cut durable state is bound.
- fault method is independently controlled.
- post-restart reconciliation is retained.
- redispatch count is zero.

### GAP-RELEASE-001 — exit L6

Signing, transparency, AVB, rollback, OTA, key custody and human authorization are bound.

Exit evidence must demonstrate:
- cryptographic verification passes.
- independent release authorization exists.
- all other gaps are closed.
- public release is explicitly enabled.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
