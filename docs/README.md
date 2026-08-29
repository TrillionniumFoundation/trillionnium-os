# Trillionnium OS documentation

Current documentation revision: **owner-open R5 `2026-08-29-r6`**  
Public release: **false**

## Current authority

Read the active chain in this order:

1. [`TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
   — R3 product-semantic baseline; Codex/provider is the only semantic principal.
2. [`TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`](TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md)
   — the active implementation, blocker ordering and evidence-promotion plan.
3. [`OWNER_OPEN_R5_START_HERE.md`](OWNER_OPEN_R5_START_HERE.md)
   — concise current entrypoint and reading order.
4. [`status/owner-open-r5-gap-closure.json`](status/owner-open-r5-gap-closure.json)
   — machine-readable zero-gap register, issue mapping and closure rules.
5. [`status/owner-open-r5-status.json`](status/owner-open-r5-status.json)
   — capability/claim policy and known exact implementation baseline.
6. [`status/owner-open-r5-traceability.tsv`](status/owner-open-r5-traceability.tsv)
   — requirement/source/test/evidence mapping.
7. [`contracts/owner-open-forbidden-default-graph-v2.json`](contracts/owner-open-forbidden-default-graph-v2.json)
   — exact Cargo and Android negative graph contract.

The R4 plan and documents under `plan/`, `archive/` and earlier batch
checkpoints are provenance. They may explain how the current implementation was
reached, but they cannot override the active r6 plan or gap register.

## Normative architecture, protocol and operations documents

### Authority and topology

- [`architecture/2026-08-29-owner-open-runtime-authority-and-process-topology.md`](architecture/2026-08-29-owner-open-runtime-authority-and-process-topology.md)
  — semantic authority versus broker/transport/core/provider/runtime process boundaries.
- [`security/owner-open-threat-model.md`](security/owner-open-threat-model.md)
  — trust, attacker and non-goal boundary.

### Unified effect and recovery semantics

- [`protocols/owner-open-effect-state-machine-v1.md`](protocols/owner-open-effect-state-machine-v1.md)
  — accepted/effect/started/terminal stages, crash cuts, durability and no-redispatch rules.
- [`protocols/owner-open-event-store-v1.md`](protocols/owner-open-event-store-v1.md)
  — durable turn observation records.
- [`protocols/owner-open-inspect-v1.md`](protocols/owner-open-inspect-v1.md)
  — read-only turn/call inspection and cursor semantics.
- [`protocols/owner-open-stream-flow-v1.md`](protocols/owner-open-stream-flow-v1.md)
  — bounded stream credit, pause/resume and explicit resynchronization.
- [`protocols/owner-open-jobs-v1.md`](protocols/owner-open-jobs-v1.md)
  — long-running pipe/PTY jobs and operation identity.
- [`protocols/owner-open-multi-connection-broker-v1.md`](protocols/owner-open-multi-connection-broker-v1.md)
  — local broker admission, request ownership and disconnect semantics.

### Provider and client protocols

- [`protocols/owner-open-direct-agent-host-v1.md`](protocols/owner-open-direct-agent-host-v1.md)
- [`protocols/owner-open-provider-jsonl-v1.md`](protocols/owner-open-provider-jsonl-v1.md)
- [`protocols/owner-open-codex-mcp-jobs-v1.md`](protocols/owner-open-codex-mcp-jobs-v1.md)
- [`protocols/owner-open-installed-codex-mcp-qualification-v1.md`](protocols/owner-open-installed-codex-mcp-qualification-v1.md)

### Deployment and qualification

- [`operations/owner-open-deployment-lifecycle-and-emergency-stop.md`](operations/owner-open-deployment-lifecycle-and-emergency-stop.md)
  — final install manifest, startup/shutdown/restart, service placement and emergency stop.
- [`qualification/owner-open-evidence-promotion-and-fault-matrix.md`](qualification/owner-open-evidence-promotion-and-fault-matrix.md)
  — L0–L6 evidence object, authenticity, fault matrix and zero-gap promotion rules.

## Current exact implementation baseline

The known exact implementation baseline is:

```text
repository: TrillionniumFoundation/trillionnium-os
branch: codex/owner-open-r5-tool-loop-20260827
commit: 479e5fb78385d3706b42f83b334025fa2b6ccd50
status: HOST_TESTED
evidence: L1
claim ceiling: EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX
```

Permanent workflows on that exact commit completed successfully, including the
R5 tool-loop Rust 1.93/graph/Python closure and foundation gates.

That evidence proves the reviewed source/host baseline only. It does not prove:

- installed or authenticated target Root Linux Codex;
- final Root Linux UID/GID/namespace/cgroup placement;
- clean Android image or target-files;
- physical shell/job/ordinary-ADB effects;
- crash, ENOSPC, USB-loss, reboot or power-loss qualification;
- signed public release.

The r6 documentation and future code changes are separate candidates and must
produce their own exact-head evidence.

## Selected source closure

The current owner-open default Cargo closure contains:

- [`../crates/trillionnium-owner-open-types/`](../crates/trillionnium-owner-open-types/)
  — strict extensible frame and tool codecs.
- [`../crates/trillionnium-owner-open-runtime/`](../crates/trillionnium-owner-open-runtime/)
  — direct shell and ordinary ADB process substrate.
- [`../crates/trillionnium-owner-open-call-registry/`](../crates/trillionnium-owner-open-call-registry/)
  — scoped call identity, cancellation and uncertainty state.
- [`../crates/trillionnium-owner-open-event-store/`](../crates/trillionnium-owner-open-event-store/)
  — append-only durable turn observations.
- [`../crates/trillionnium-owner-open-job-registry/`](../crates/trillionnium-owner-open-job-registry/)
  — exact job/operation identity and lifecycle history.
- [`../crates/trillionnium-owner-open-job-runtime/`](../crates/trillionnium-owner-open-job-runtime/)
  — pipe/PTY process groups, controls and recovery.
- [`../crates/trillionnium-owner-open-provider-jsonl/`](../crates/trillionnium-owner-open-provider-jsonl/)
  — external provider duplex and cancellation.
- [`../crates/trillionnium-owner-open-stream-window/`](../crates/trillionnium-owner-open-stream-window/)
  — finite byte-window state machine.
- [`../crates/trillionnium-owner-open-tool-bridge/`](../crates/trillionnium-owner-open-tool-bridge/)
  — call registry to direct runtime handoff.
- [`../crates/trillionnium-owner-open-turn-loop/`](../crates/trillionnium-owner-open-turn-loop/)
  — same-turn provider callback and cancellation.
- [`../apps/trillionnium-owner-open-host/`](../apps/trillionnium-owner-open-host/)
  — foundation binary plus selected v5 transport and v7 core targets.
- [`../tools/owner-open/`](../tools/owner-open/)
  — broker, MCP, trace and qualification mechanisms.

The r6 plan reopens repository gaps where documentation or source behavior does
not yet meet the intended contract. Source presence is not closure.

## Current gap chain

Repository-manageable blockers:

```text
#20 exact-head evidence/governance
#14 pre-spawn job admission and total rollback
#15 process lifecycle, initial-stdin and descendant cleanup
#16 job-output flow control and cursor gaps
#17 journal-degraded convergence
#18 exact broker correlation/audit/startup cleanup
#19 one product entrypoint and install manifest
```

External evidence lanes:

```text
#10/#13 installed Codex L2
#4/#13 Root Linux placement L2
#2/#13 Android image L3
#5/#8/#13 physical ordinary ADB L4
#6/#13 destructive fault matrix L5
#13 signed release L6
```

The machine source of truth for these identifiers and exit levels is
`status/owner-open-r5-gap-closure.json`.

## Documentation contribution rules

Every active document must state:

```text
status
revision or plan binding
source/evidence boundary
normative versus historical role
open gaps where the implementation is weaker than the target contract
```

A documentation change must update the plan/status/gap register atomically when
it changes a claim, identity, state transition or acceptance gate.

Do not use an aspirational workflow or document title as evidence. Workflow
names must state the actual level, for example `L1 source closure`, `L3 Android
target-files`, `L4 physical normal path` or `L5 destructive fault matrix`.

## Zero-gap rule

The project is not zero-gap while any entry in
`status/owner-open-r5-gap-closure.json` is `OPEN`,
`SOURCE_CLOSED_PENDING_EVIDENCE` or `EXTERNAL_HOLD`.

Fixtures and status edits cannot close installed, image, physical, fault or
release lanes. Public release remains false until the L6 release gap is closed
with cryptographic and human authorization evidence.

## R5 exact-source closure evidence

- [Exact-source L1 closure evidence](status/owner-open-r5-source-closure-evidence-2026-08-29.md)
- [R5 machine gap register](status/owner-open-r5-gap-closure.json)
- [R5 current status](status/owner-open-r5-status.json)
