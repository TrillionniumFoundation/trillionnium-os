# MOD-PROVIDER — provider process and session

This document is the detailed source-development, integration and qualification contract for `MOD-PROVIDER`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-PROVIDER`
- Module version: `1.0.0`
- Name: **provider process and session**
- Plane: `semantic-adapter`
- Primary owner: `team-provider`
- Backup owner: `team-turn-engine`
- Maturity: `L1_SOURCE`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `crates/trillionnium-owner-open-provider-jsonl`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- provider process lifecycle.

Operationally, the required flow is:

The adapter launches the pinned provider bytes, establishes an authenticated session epoch, exchanges bounded versioned JSONL events, and carries same-turn tool callbacks without inventing intent. Provider output is validated before it reaches execution.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

## 3. Non-goals and authority boundary

Explicit non-goals:

- OS semantic policy.

The provider is the sole semantic principal, but the adapter itself is mechanical. The adapter cannot create new semantic instructions, conceal a retry, replace the selected operation or treat unauthenticated bytes as provider authority.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-PROTOCOL`, `MOD-TURN-ENGINE`, `MOD-TOOL-RUNTIME`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_provider.api.v1`
- Catalog input labels: `provider_request_v1`
- Catalog output labels: `provider_event_v1`
- Catalog error labels: `provider_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `crates/trillionnium-owner-open-provider-jsonl/src/lib.rs` — `JsonlProviderConfig`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

`JsonlProviderConfig` supplies the executable, environment and bounded protocol configuration. `JsonlProvider` owns the child session. The protocol adapter validates scope and produces exact tool outcomes; restarting the process is not permission to replay a callback.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_provider.state.v1`
- State authority: **authoritative**
- Partition key: `turn_id`
- State owned: `provider session epoch`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `turn_id`
- Maximum declared concurrency: `32`
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

A provider exit terminates the session epoch. Pending callbacks are classified from durable acceptance and terminal evidence; a new process receives no implicit replay of uncertain effects.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.

### Python JSONL launch adapter: process retirement and callback fencing

`tools/owner-open/jsonl_provider_runtime.py` is the Python launch/bootstrap
adapter used by `execute_codex_exec_plan.py`, not the Rust Provider runtime.
It requires Linux `waitid(WNOWAIT)`, default SIGCHLD handling and exclusive
reaping of its direct child. The returned `process_id` is diagnostic only.
The child is created in a new session with closed inherited descriptors;
stdio initialization, selector registration and the pump share one cleanup guard.

The adapter never calls `Popen.poll()` while it owns the process-group anchor.
Normal leader exit, cancellation, timeout, malformed output and initialization
failure all enter retirement: send TERM, then KILL before reaping the leader,
and require two bounded observations with no live original-group members.
Observation errors are retained even when reaping succeeds. No signal is sent
after reaping or after loss of the waitable anchor. An exhausted cleanup deadline
returns an unconfirmed result, never an assurance that the process is absent.

`ProviderTerminal` adds `cleanup_confirmed`, `leader_reaped` and `process_id`.
Its `success` requires exit zero, no error, confirmed original-group retirement
and leader reaping. The execution terminal's additive `process_cleanup` object
exports these observations with `scope=original_process_group_only`,
`pid_is_recovery_authority=false`, `escaped_descendants_absence_proven=false`
and `automatic_redispatch=false`. Strict consumers of the v1 terminal schema
must validate compatibility with this additive field before deployment.

A pre-cancelled request does not spawn. Once cancellation, timeout or a forced
terminal is observed, no new sink/handler callback or handler response is
admitted, including later records in the same read batch. Checkpoints surround
callbacks; an already-entered synchronous callback cannot be preempted and must
itself return within the caller's budget. Natural-exit pipe draining can still
emit previously buffered observations; it cannot send responses to closed stdin.
Queued outbound byte counts are not delivery acknowledgements or effect receipts.

Byte/count limits must be positive integers no greater than 2**31 (booleans and
fractions are rejected). Read chunks cannot exceed 1 MiB and JSON lines 16 MiB.
Initial stdin also consumes the total outbound budget. JSON nesting is checked
before decoding and limited to 64; duplicate keys, non-finite constants and
floating-point overflow are errors. Existing unknown object fields remain intact.
Timeout is 0.001..3600 seconds, poll interval 0.001..1 second, TERM grace 0..30,
KILL/reap and pipe-drain budgets 0.01..30 seconds. Defaults are 300, 0.02, 0.25,
1 and 1 seconds respectively. One extra KILL-budget interval is available solely
for final leader reaping after all signals. Procfs scans use at most 65,536 entries,
8,192 bytes per stat and one second within the current observation deadline.
Diagnostics retain at most 4,096 characters. These are source limits, not latency
or power-loss guarantees; OS calls and synchronous callbacks are not preemptible.

Pipe EOF is not assumed to follow leader exit. A finite drain deadline closes
local pipes even when a setsid-escaped descendant still holds a writer; missing
EOF returns an error. This helper cannot terminate such escaped descendants,
provide cgroup containment, defend against another reaper, survive its own abrupt
death or prove installed-target identity. A complete same-namespace procfs view
and independently enforced installed service containment remain L2 obligations.
No failure permits implicit replay, retry, PID-based adoption or target promotion.

Run `python3 -m unittest tools.tests.test_jsonl_provider_runtime
 tools.tests.test_execute_codex_exec_plan -v` on one line from the repository root.
The exact-head source workflow explicitly runs both modules; the synthetic-merge
workflow includes them in its complete `tools/tests/test*.py` discovery. Tests use
only local fixture processes and test-only subreaping of their own orphan PIDs;
they do not qualify installed Codex, Android, physical effects or destructive faults.

### Private input snapshots and execution receipts

The Python `execute_codex_exec_plan.py` entrypoint reads plan and prompt bytes
through no-follow directory traversal and one non-inheritable, nonblocking file
descriptor. Inputs must be private, owner-controlled, single-link regular files.
It checks descriptor metadata before/after the bounded read and verifies the
named leaf still identifies that snapshot. Symlink components, special files,
hardlinks, observed replacement, same-size metadata changes and growth beyond
the byte budget fail closed. This is a checked local snapshot, not immutable
filesystem custody or an executable attestation. The existing executable probe
still does not atomically bind interpreter/transitive dependency bytes at exec.

Plan JSON uses the runtime's strict UTF-8/object/duplicate/finite-number decoder
and pre-decoder depth bound of 64. The plan remains limited to 4 MiB, prompt to
256 KiB; empty prompt is allowed, empty plan is not. Input read requests are at
most 64 KiB and total captured input at most its limit plus one sentinel byte.
Claims must contain actual booleans with the exact expected keys and values:
integer zero/one cannot impersonate false/true. A self-computed plan hash proves
byte consistency only, not independent authorization or installed Codex identity.

Before calling the provider, the CLI rejects overlapping plan/prompt/output
leaves and requires **new** event and terminal output names. It prepares both
output parents and reserves private temporary files before execution. Existing
output evidence is preserved rather than overwritten. Every pathname is limited
to 4,096 filesystem-encoded bytes and 64 components, with no parent traversal.
Output parents must already be private and owner-controlled or be newly created
with mode 0700; permissive existing parents are rejected, never silently chmodded.
No output path component may be a symlink. These are source admission checks,
not a guarantee of future free space, uninterruptible I/O or successful evidence
publication after an effect has occurred.

Each output keeps its parent descriptor through execution and publication.
A randomly named temporary is exclusively created as mode 0600 **before any
sensitive byte is written**. Its descriptor is close-on-exec. Partial writes are
completed; zero/invalid progress fails. JSON encoding rejects non-finite numbers,
and each serialized receipt has a 64 MiB output ceiling. Publication is one
attempt: serialize, fsync the temporary, recheck parent/target/temporary identity,
replace relative to the pinned parent, then fsync that parent. A collision never
deletes another attempt's file. Handled errors remove only a still-owned temporary;
a replacement temporary is neither published nor unlinked. An abrupt process
crash may leave private temporaries for independently controlled cleanup.

The `atomic_write_json` library helper still allows replacing an existing private
regular target, provided its version is unchanged since preparation; the CLI
uses the stricter new-target mode. This is not a distributed lock or an atomic
compare-and-swap against malicious same-UID/root writers. Operators must provide
a stable private namespace, unique invocation destinations and one writer.
Namespace checks cannot exclude a last-instant privileged path substitution.

Event and terminal files are **two separate commits**, not one transaction and
not the Host's durable-before-effect journal. If the second publication fails,
the event file may already exist. If parent fsync fails after replace, new bytes
may be visible with uncertain durability. Neither case proves rollback or that
no effect occurred. CLI errors distinguish pre-execution, uncertain execution
and post-execution receipt publication, always with automatic retry disabled.
Preserve partial output and reconcile independently; do not rerun a semantic
operation solely to obtain missing receipt files. Production pair-consistency,
crash/power-loss durability and independent custody remain L2/L5 obligations.

A pre-cancelled request or spawn failure no longer sets `validated_plan_executed`
to true; a diagnostic process ID establishes only local process creation, not
provider/model contact. An unsuccessful terminal prints FAIL, never PASS.
The existing execution-entrypoint suite covers the file/CLI boundary with local
fixtures and fault injection; both existing exact-head and synthetic-merge
source lanes already include it. No fixture closes the module's L2 gaps.

## 11. Security and trust boundaries

The provider is the sole semantic principal, but the adapter itself is mechanical. The adapter cannot create new semantic instructions, conceal a retry, replace the selected operation or treat unauthenticated bytes as provider authority.

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

Provider sessions are not migrated live. A new authenticated session epoch starts after the old process is stopped and outstanding accepted effects are reconciled.

Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

## 14. Observability

Retain process identity, executable digest, session epoch, protocol versions, frame counts, callback latency, cancellation and exit classification. Prompt and credential content is excluded unless an independently authorized evidence procedure requires a bounded sample.

Every metric and log record is bounded and versioned. Required common dimensions are module ID, instance or service epoch, ordering-key digest, operation class and outcome. High-cardinality raw identifiers are hashed or retained only in access-controlled evidence. Readiness means the module can safely admit work; liveness alone is insufficient.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

### Reproduction entrypoint

- Verification source: `crates/trillionnium-owner-open-provider-jsonl/tests/duplex.rs`

Run from the repository root in an isolated host source-test environment:

```sh
cargo test --locked -p trillionnium-owner-open-provider-jsonl --all-targets
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

## 16. Deployment and runbook

On provider failure, freeze new turns, retain stderr and bounded protocol framing, verify executable identity, close the session epoch and reconcile accepted callbacks before relaunch.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-PROCESS-LIFECYCLE-001`, `GAP-CONC-TURN-CANCEL-001`, `GAP-INSTALLED-CODEX-001`.

### GAP-PROCESS-LIFECYCLE-001 — exit L2

Installed-target parent death, reader-before-writer and descendant cleanup are proven.

Exit evidence must demonstrate:
- installed process identity is bound.
- leader exit is not treated as descendant absence.
- cleanup uncertainty remains explicit.

### GAP-CONC-TURN-CANCEL-001 — exit L2

Event-driven cancellation and bounded event storage replace per-tool polling.

Exit evidence must demonstrate:
- no polling thread per tool.
- cancellation remains targeted.
- large turns remain bounded.
- terminal remains exactly once.

### GAP-INSTALLED-CODEX-001 — exit L2

Exact installed Codex bytes, identity and same-turn tool callbacks are qualified.

Exit evidence must demonstrate:
- installed hash and signer are bound.
- provider session is authenticated.
- same-turn shell and job trace is retained.
- no hidden retry occurs.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
