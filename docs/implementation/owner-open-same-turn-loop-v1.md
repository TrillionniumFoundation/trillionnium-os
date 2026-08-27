# Owner-open same-turn loop v1

Status: **R5 source implementation; execution validation pending**  
Plan: `docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`  
Source: `crates/trillionnium-owner-open-turn-loop`

## Boundary

The provider owns semantics. The loop gives it one callback surface that can:

- emit provider/model observations;
- invoke a `BoundToolCall` through the reviewed call registry and direct process
  bridge;
- inspect raw runtime events and the terminal observation;
- continue the same semantic turn; and
- return exactly one provider terminal.

The loop does not parse user intent, classify risk, require approval, rewrite a
command, inject an ADB target, choose a provider or retry an uncertain effect.

## Correlation

Every tool call must carry a `CallKey` whose `TurnScope` exactly matches:

```text
session_id
profile_id
task_id
turn_id
turn_stream_id
```

A mismatched scope is rejected before bridge dispatch. The call registry then
binds the scoped call ID to request digest, binding fingerprint, tool and target
metadata.

## Same-turn ordering

The collecting source implementation emits monotonically ordered events:

```text
turn.accepted
provider/model event*
tool accepted/started/output/terminal*
provider/model event*
turn.terminal
```

The initial implementation collects events in memory. Host streaming,
backpressure, durable event IDs, resume and cross-connection control are later
W1/W5 gates and must not be inferred from this source slice.

## Duplicate behavior

- exact scoped call and request: return `ToolOutcome::Existing`; do not spawn;
- same scoped call ID with different binding: return a bridge/registry conflict;
- inhibited call: return `ToolOutcome::Inhibited`; do not spawn;
- newly granted call: execute through the mechanism-only process runtime.

The in-memory registry terminal does not contain raw output bytes, so an
`Existing` outcome is not yet a complete durable replay response. W5 must add a
bound event store before reconnect/restart replay is claimed.

## Failure behavior

- non-zero shell/ADB exit is a tool observation; provider may continue;
- bridge failure is returned to provider code;
- provider-returned error becomes one `provider_failed` terminal;
- provider panic becomes one `provider_panicked` terminal;
- provider terminal text is mechanically bounded and NUL-free.

## Current tests authored

- deliberate shell exit 7 with stdout/stderr, followed by provider continuation;
- duplicate call produces one process-side file mutation;
- ordinary ADB unknown argv remains exact and target metadata is not injected;
- provider panic produces one terminal.

Claim ceiling remains **SOURCE_IMPLEMENTED / L0** until the exact commit passes
Rust formatting, tests and clippy on a real runner.
