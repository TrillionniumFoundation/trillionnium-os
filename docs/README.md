# Trillionnium OS documentation

## Current authority

- [`TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
  — R3 semantic baseline.
- [`TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`](TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md)
  — active implementation and closeout plan.
- [`plan/owner-open-r5-batch-d-inspection-flow-control.md`](plan/owner-open-r5-batch-d-inspection-flow-control.md)
  — current source checkpoint.
- [`OWNER_OPEN_R5_START_HERE.md`](OWNER_OPEN_R5_START_HERE.md)
  — concise development entry.
- [`status/owner-open-r5-status.json`](status/owner-open-r5-status.json)
  — authoritative machine claim ceiling.
- [`status/owner-open-r5-traceability.tsv`](status/owner-open-r5-traceability.tsv)
  — requirement/source/test/evidence mapping.
- [`contracts/owner-open-forbidden-default-graph-v2.json`](contracts/owner-open-forbidden-default-graph-v2.json)
  — exact Cargo, internal-dependency, Host-binary and Android negative graph.

R4 documents remain historical foundation material. R5 determines the next
batch and what counts as complete; R3 remains normative for product semantics.

## Current R5 source closure

- [`../crates/trillionnium-owner-open-types/`](../crates/trillionnium-owner-open-types/)
  — strict extensible frame and tool codecs.
- [`../crates/trillionnium-owner-open-runtime/`](../crates/trillionnium-owner-open-runtime/)
  — direct shell and ordinary ADB process substrate.
- [`../crates/trillionnium-owner-open-call-registry/`](../crates/trillionnium-owner-open-call-registry/)
  — scoped call identity, cancellation and uncertainty state.
- [`../crates/trillionnium-owner-open-event-store/`](../crates/trillionnium-owner-open-event-store/)
  — append-only durable observations and strict reopen.
- [`../crates/trillionnium-owner-open-provider-jsonl/`](../crates/trillionnium-owner-open-provider-jsonl/)
  — external provider duplex, tool results and provider cancellation.
- [`../crates/trillionnium-owner-open-stream-window/`](../crates/trillionnium-owner-open-stream-window/)
  — isolated finite byte-credit and pause/resume state machine.
- [`../crates/trillionnium-owner-open-tool-bridge/`](../crates/trillionnium-owner-open-tool-bridge/)
  — at-most-one direct process handoff and failure closure.
- [`../crates/trillionnium-owner-open-turn-loop/`](../crates/trillionnium-owner-open-turn-loop/)
  — same-turn streaming callback and turn cancellation.
- [`../apps/trillionnium-owner-open-host/`](../apps/trillionnium-owner-open-host/)
  — selected Host v4: active controls, per-event persistence, completed replay,
  conservative recovery and read-only `turn.inspect`/`call.inspect`.

## Current protocols

- [`protocols/owner-open-direct-agent-host-v1.md`](protocols/owner-open-direct-agent-host-v1.md)
- [`protocols/owner-open-provider-jsonl-v1.md`](protocols/owner-open-provider-jsonl-v1.md)
- [`protocols/owner-open-event-store-v1.md`](protocols/owner-open-event-store-v1.md)
- [`protocols/owner-open-inspection-v1.md`](protocols/owner-open-inspection-v1.md)
- [`protocols/owner-open-stream-flow-control-v1.md`](protocols/owner-open-stream-flow-control-v1.md)
- [`security/owner-open-threat-model.md`](security/owner-open-threat-model.md)
- [`architecture/2026-08-27-owner-open-raw-adb-transparent-host-relay.md`](architecture/2026-08-27-owner-open-raw-adb-transparent-host-relay.md)

## Evidence boundary

The latest checkpoint is
[`evidence/2026-08-28-owner-open-inspection-flow-control-source.md`](evidence/2026-08-28-owner-open-inspection-flow-control-source.md).
It records L0 source preparation only. No current Rust runner has executed
formatting, compilation, tests or clippy for the selected Host v4 and stream
window. Android, device, fault and release promotions remain pending.

Historical audits, receipts and the Android dirty overlay remain useful for
provenance and migration. They do not prove the current owner-open product.
