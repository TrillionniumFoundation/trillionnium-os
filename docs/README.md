# Trillionnium OS documentation

## Current authority

- [`TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
  — R3 semantic baseline.
- [`TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`](TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md)
  — active implementation and closeout plan.
- [`plan/owner-open-r5-batch-d-jobs.md`](plan/owner-open-r5-batch-d-jobs.md)
  — durable job source checkpoint.
- [`plan/owner-open-r5-batch-d-codex-mcp-job-binding.md`](plan/owner-open-r5-batch-d-codex-mcp-job-binding.md)
  — Codex MCP source checkpoint.
- [`plan/owner-open-r5-batch-d-connection-and-installed-codex.md`](plan/owner-open-r5-batch-d-connection-and-installed-codex.md)
  — current connection-ownership and installed-Codex checkpoint.
- [`OWNER_OPEN_R5_START_HERE.md`](OWNER_OPEN_R5_START_HERE.md)
  — concise development entry.
- [`status/owner-open-r5-status.json`](status/owner-open-r5-status.json)
  — authoritative machine claim ceiling.
- [`status/owner-open-r5-traceability.tsv`](status/owner-open-r5-traceability.tsv)
  — requirement/source/test/evidence mapping.
- [`contracts/owner-open-forbidden-default-graph-v2.json`](contracts/owner-open-forbidden-default-graph-v2.json)
  — exact Cargo, dependency, Host-binary and Android negative graph.

R4 documents remain historical foundation material. R5 determines current
sequencing and evidence; R3 remains normative for product semantics.

## Current R5 source closure

- [`../crates/trillionnium-owner-open-types/`](../crates/trillionnium-owner-open-types/)
  — strict extensible frame and tool codecs.
- [`../crates/trillionnium-owner-open-runtime/`](../crates/trillionnium-owner-open-runtime/)
  — direct shell and ordinary ADB process substrate.
- [`../crates/trillionnium-owner-open-call-registry/`](../crates/trillionnium-owner-open-call-registry/)
  — scoped call identity, cancellation and uncertainty state.
- [`../crates/trillionnium-owner-open-event-store/`](../crates/trillionnium-owner-open-event-store/)
  — append-only durable turn observations and strict reopen.
- [`../crates/trillionnium-owner-open-job-registry/`](../crates/trillionnium-owner-open-job-registry/)
  — exact job/operation identity, lifecycle and bounded observation state.
- [`../crates/trillionnium-owner-open-job-runtime/`](../crates/trillionnium-owner-open-job-runtime/)
  — direct pipe/PTY process groups, job controls and durable recovery.
- [`../crates/trillionnium-owner-open-provider-jsonl/`](../crates/trillionnium-owner-open-provider-jsonl/)
  — external provider duplex, tool results and provider cancellation.
- [`../crates/trillionnium-owner-open-stream-window/`](../crates/trillionnium-owner-open-stream-window/)
  — finite byte-window and pause/resume state machine.
- [`../crates/trillionnium-owner-open-tool-bridge/`](../crates/trillionnium-owner-open-tool-bridge/)
  — at-most-one direct process handoff and failure closure.
- [`../crates/trillionnium-owner-open-turn-loop/`](../crates/trillionnium-owner-open-turn-loop/)
  — same-turn streaming callback and turn cancellation.
- [`../apps/trillionnium-owner-open-host/`](../apps/trillionnium-owner-open-host/)
  — selected v5 transport carrier plus job-aware v7 execution core.
- [`../tools/owner-open/codex_owner_open_mcp.py`](../tools/owner-open/codex_owner_open_mcp.py)
  — local Codex STDIO MCP job server.
- [`../tools/owner-open/owner_open_connection_broker.py`](../tools/owner-open/owner_open_connection_broker.py)
  — multi-client, single-upstream mechanical broker foundation.
- [`../tools/owner-open/trace_mcp_stdio.py`](../tools/owner-open/trace_mcp_stdio.py)
  — exact-byte MCP trace and deterministic teardown.
- [`../tools/owner-open/qualify_codex_mcp_jobs.py`](../tools/owner-open/qualify_codex_mcp_jobs.py)
  — installed-Codex registration and exact job-sequence qualification.

## Current protocols

- [`protocols/owner-open-direct-agent-host-v1.md`](protocols/owner-open-direct-agent-host-v1.md)
- [`protocols/owner-open-provider-jsonl-v1.md`](protocols/owner-open-provider-jsonl-v1.md)
- [`protocols/owner-open-event-store-v1.md`](protocols/owner-open-event-store-v1.md)
- [`protocols/owner-open-inspect-v1.md`](protocols/owner-open-inspect-v1.md)
- [`protocols/owner-open-stream-flow-v1.md`](protocols/owner-open-stream-flow-v1.md)
- [`protocols/owner-open-jobs-v1.md`](protocols/owner-open-jobs-v1.md)
- [`protocols/owner-open-codex-mcp-jobs-v1.md`](protocols/owner-open-codex-mcp-jobs-v1.md)
- [`protocols/owner-open-multi-connection-broker-v1.md`](protocols/owner-open-multi-connection-broker-v1.md)
- [`protocols/owner-open-installed-codex-mcp-qualification-v1.md`](protocols/owner-open-installed-codex-mcp-qualification-v1.md)
- [`security/owner-open-threat-model.md`](security/owner-open-threat-model.md)
- [`architecture/2026-08-27-owner-open-raw-adb-transparent-host-relay.md`](architecture/2026-08-27-owner-open-raw-adb-transparent-host-relay.md)

## Evidence boundary

Current source records bind durable jobs and the initial MCP adapter fixtures.
The broker/trace/qualification slice remains at L0 until its exact-checkout
Python tests and the selected Rust closure execute on one commit. Installed
Codex, Android, physical device, fault and release promotions remain pending.

Historical audits, receipts and the Android dirty overlay remain useful for
provenance and migration. They do not prove the current owner-open product.
