# Trillionnium OS documentation

## Current authority

- [`TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
  — R3 semantic baseline: one Codex semantic control plane and direct
  owner-open shell/ADB.
- [`TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`](TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md)
  — **active implementation sequencing and closeout plan**.
- [`OWNER_OPEN_R5_START_HERE.md`](OWNER_OPEN_R5_START_HERE.md)
  — concise development entry point.
- [`status/owner-open-r5-status.json`](status/owner-open-r5-status.json)
  — authoritative machine progress and negative claims.
- [`status/owner-open-r5-traceability.tsv`](status/owner-open-r5-traceability.tsv)
  — requirement-to-source/test/evidence mapping.
- [`contracts/owner-open-forbidden-default-graph-v2.json`](contracts/owner-open-forbidden-default-graph-v2.json)
  — exact R5 Cargo, internal-dependency and Host-binary graph plus the Android
  forbidden graph.

R4 documents are retained as the prior foundation and evidence history. They no
longer determine the next implementation batch or completion status.

## Current R5 implementation

- [`../crates/trillionnium-owner-open-types/`](../crates/trillionnium-owner-open-types/)
  — strict extensible transport and tool codecs.
- [`../crates/trillionnium-owner-open-runtime/`](../crates/trillionnium-owner-open-runtime/)
  — direct process substrate for shell and ordinary ADB argv.
- [`../crates/trillionnium-owner-open-call-registry/`](../crates/trillionnium-owner-open-call-registry/)
  — concurrent scoped call identity and uncertainty state.
- [`../crates/trillionnium-owner-open-event-store/`](../crates/trillionnium-owner-open-event-store/)
  — append-only durable observations, scoped cursors and strict reopen.
- [`../crates/trillionnium-owner-open-tool-bridge/`](../crates/trillionnium-owner-open-tool-bridge/)
  — at-most-one spawn handoff and failure closure.
- [`../crates/trillionnium-owner-open-turn-loop/`](../crates/trillionnium-owner-open-turn-loop/)
  — same-turn streaming callback and turn-level cancellation token.
- [`../crates/trillionnium-owner-open-provider-jsonl/`](../crates/trillionnium-owner-open-provider-jsonl/)
  — bounded provider process, tool-result duplex and provider cancellation.
- [`../apps/trillionnium-owner-open-host/`](../apps/trillionnium-owner-open-host/)
  — selected R5 Host with a bounded input/control reader, independent turn
  worker, streaming persistence, detached delivery, completed replay,
  incomplete reconciliation, active `turn.cancel` and targeted `tool.cancel`.
- [`implementation/owner-open-same-turn-loop-v1.md`](implementation/owner-open-same-turn-loop-v1.md)
  — W1 behavior and evidence boundary.
- [`implementation/owner-open-provider-jsonl-v1.md`](implementation/owner-open-provider-jsonl-v1.md)
  — W2 provider boundary and cancellation semantics.
- [`protocols/owner-open-event-store-v1.md`](protocols/owner-open-event-store-v1.md)
  — W5 record, replay and uncertainty semantics.

## Protocol, security and architecture

- [`protocols/owner-open-direct-agent-host-v1.md`](protocols/owner-open-direct-agent-host-v1.md)
- [`protocols/owner-open-provider-jsonl-v1.md`](protocols/owner-open-provider-jsonl-v1.md)
- [`implementation/owner-open-codex-provider-v1.md`](implementation/owner-open-codex-provider-v1.md)
- [`implementation/owner-open-process-substrate-v1.md`](implementation/owner-open-process-substrate-v1.md)
- [`implementation/owner-open-call-registry-v1.md`](implementation/owner-open-call-registry-v1.md)
- [`implementation/owner-open-tool-bridge-v1.md`](implementation/owner-open-tool-bridge-v1.md)
- [`security/owner-open-threat-model.md`](security/owner-open-threat-model.md)
- [`architecture/2026-08-27-owner-open-raw-adb-transparent-host-relay.md`](architecture/2026-08-27-owner-open-raw-adb-transparent-host-relay.md)

## Evidence boundary

The latest checked-in R5 checkpoint is
[`evidence/2026-08-28-owner-open-turn-loop-source.md`](evidence/2026-08-28-owner-open-turn-loop-source.md).
The branch now contains additional streaming, durable recovery and active-control
source plus authored tests, but no executing Rust runner has validated the
current head. Rust, Host, Android, device, fault and release promotions remain
pending.

Historical audits, receipts and Android dirty-overlay files remain useful for
provenance and migration, but they do not prove the current owner-open product.
