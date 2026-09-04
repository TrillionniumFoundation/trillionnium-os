# MOD-ROOTLINUX — Root Linux integration

This document is the detailed source-development, integration and qualification contract for `MOD-ROOTLINUX`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-ROOTLINUX`
- Module version: `1.0.0`
- Name: **Root Linux integration**
- Plane: `platform`
- Primary owner: `team-rootlinux`
- Backup owner: `team-android`
- Maturity: `SOURCE_PROFILE_L2_PENDING`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `packaging/root-linux`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- runtime image.

Operationally, the required flow is:

The integration assembles the selected owner-open payload, records immutable hashes and service identities, establishes UID/GID, namespace, cgroup, mount and store placement, then starts the host and authenticated provider under a bounded service epoch.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

## 3. Non-goals and authority boundary

Explicit non-goals:

- semantic policy.

Root capability is minimized and mechanically scoped. Packaging cannot add semantic policy, substitute unpinned provider bytes, broaden namespaces or silently select a legacy authority path.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-EXECUTION-CORE`, `MOD-PROVIDER`, `MOD-GLOBAL-CONTROL`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_rootlinux.api.v1`
- Catalog input labels: `rootlinux_service_request_v1`
- Catalog output labels: `rootlinux_service_state_v1`
- Catalog error labels: `rootlinux_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `tools/owner-open/stage_owner_open_rootfs_payload.py` — `stage`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

The staging helper validates source identity, destination paths, ELF metadata and content digests before assembling a payload. `packaging/root-linux/` contains admission policy inputs, not an already installed system. A successful source staging test does not establish live UID, namespace, cgroup or provider identity.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_rootlinux.state.v1`
- State authority: **authoritative**
- Partition key: `service_epoch`
- State owned: `install manifest projection; service runtime state`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `service_epoch`
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

Service restart validates the live install manifest and state ownership before admitting work. Emergency inhibit remains available independently of provider health.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.

### Supervisor group-retirement barrier

The deployed helper is `tools/owner-open/owner_open_rootlinux_supervisor.py`.
`Supervisor.observe_exit` uses Linux `waitid(WNOWAIT)` and never calls
`Popen.poll()` while a process group is owned. The unreaped session leader pins
its numeric PID/PGID until group signalling has finished; an external reaper or
ignored SIGCHLD is unsupported and fails closed. Status reads do not reap it.

`Supervisor.cleanup_groups` sends TERM, then always sends KILL to the original
group before reaping the leader. Two bounded same-namespace procfs observations
must find the leader exited and no live original-group members. Zombies cannot
execute; the installed init/subreaper is responsible for reaping adopted zombies.
Noncritical exit, critical restart and final shutdown all use this barrier.
An unavailable/truncated procfs view, exhausted scan budget, signal error or
cleanup deadline stops replacement and reports cleanup as unconfirmed. Limits
are 65,536 directory entries, 8,192 bytes per stat read and one second per scan;
these are finite observation ceilings, not measured device performance.

The status exposes `cleanup_scope=original_process_group_only`, a per-child
`group_cleanup` observation and `escaped_descendants_absence_proven=false`.
A process group is not a containment boundary for `setsid`/`setpgid` escape.
Installed L2 evidence must additionally establish the service cgroup/namespace
boundary, cgroup-wide cleanup, supervisor-death behaviour and a complete procfs
view. Local fork tests do not close those installed-target requirements.

Any emergency marker, including a dangling symlink or unreadable marker state,
inhibits startup/restart. Inhibit, status and event-log leaves must be distinct
and cannot contain each other. Stop/inhibit is checked between initial child
starts and again before a replacement; already accepted effects are not retried.

Reproduce the local lifecycle boundary from the repository root:

```sh
python3 -m unittest tools.tests.test_owner_open_rootlinux_supervisor -v
```

The fixture creates real local descendants with a pipe readiness handshake,
including TERM-resistant children; no timing-only assumption establishes their
existence. Test-only subreaping collects fixture orphans. Both exact-head and
synthetic-merge source lanes explicitly run this suite. No fixture is evidence
of a physical device, target installation or external-effect rollback.

## 11. Security and trust boundaries

Root capability is minimized and mechanically scoped. Packaging cannot add semantic policy, substitute unpinned provider bytes, broaden namespaces or silently select a legacy authority path.

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

Image and service upgrades are manifest-bound. A new service epoch starts only after payload, ownership, mount and state-schema checks pass; rollback restores the last compatible immutable image and fences newer writers.

Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

## 14. Observability

Retain payload hashes, signer identity when available, UID/GID, namespaces, mounts, cgroup limits, service epoch, restart count, readiness and inhibit state.

Every metric and log record is bounded and versioned. Required common dimensions are module ID, instance or service epoch, ordering-key digest, operation class and outcome. High-cardinality raw identifiers are hashed or retained only in access-controlled evidence. Readiness means the module can safely admit work; liveness alone is insufficient.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

### Reproduction entrypoint

- Verification source: `tools/tests/test_verify_owner_open_rootfs_payload_selection.py`

Run from the repository root in an isolated host source-test environment:

```sh
python3 -m unittest tools.tests.test_verify_owner_open_rootfs_payload_selection -v
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

## 16. Deployment and runbook

On manifest drift, stop admission, preserve the live filesystem and service metadata, compare exact payload hashes, restore a known compatible image or remain inhibited. Do not bless the live drift in place.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-PRODUCT-ENTRYPOINT-001`, `GAP-INSTALLED-CODEX-001`, `GAP-ROOTLINUX-PLACEMENT-001`, `GAP-ANDROID-GRAPH-001`, `GAP-RELEASE-001`.

### GAP-PRODUCT-ENTRYPOINT-001 — exit L3

One install manifest selects the product entrypoint and internal children.

Exit evidence must demonstrate:
- source entrypoint is unambiguous.
- target-files contain the exact selected binaries.
- foundation stubs are absent from product inventory.

### GAP-INSTALLED-CODEX-001 — exit L2

Exact installed Codex bytes, identity and same-turn tool callbacks are qualified.

Exit evidence must demonstrate:
- installed hash and signer are bound.
- provider session is authenticated.
- same-turn shell and job trace is retained.
- no hidden retry occurs.

### GAP-ROOTLINUX-PLACEMENT-001 — exit L2

Installed UID, GID, namespaces, cgroups, mounts, stores and restart policy are bound.

Exit evidence must demonstrate:
- install manifest matches the live target.
- resource limits are observed.
- restart and emergency inhibit work.

### GAP-ANDROID-GRAPH-001 — exit L3

A clean Android graph contains selected owner-open components and no legacy semantic nodes.

Exit evidence must demonstrate:
- clean source and target-files are retained.
- Soong, init, SELinux and package inventory agree.
- installed manifest identities match.

### GAP-RELEASE-001 — exit L6

Signing, transparency, AVB, rollback, OTA, key custody and human authorization are bound.

Exit evidence must demonstrate:
- cryptographic verification passes.
- independent release authorization exists.
- all other gaps are closed.
- public release is explicitly enabled.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
