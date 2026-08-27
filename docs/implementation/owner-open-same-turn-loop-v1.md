# Owner-open same-turn loop v1

Status: **R5 source implementation; execution validation pending**  
Plan: `docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`  
Source: `crates/trillionnium-owner-open-turn-loop`

## Boundary

The provider owns semantics. The loop gives it one callback surface that can:

- emit provider/model observations;
- invoke a `BoundToolCall` through the reviewed call registry and direct process
  bridge;
- observe raw runtime events and the terminal result;
- continue the same semantic turn;
- receive a turn cancellation token; and
- return exactly one provider terminal.

The loop does not parse user intent, classify risk, require approval, rewrite a
command, inject an ADB target, choose a provider or retry an uncertain effect.

## Correlation

Every tool call carries a `CallKey` whose `TurnScope` exactly matches:

```text
session_id
profile_id
task_id
turn_id
turn_stream_id
```

A mismatched scope is rejected before bridge dispatch. The call registry binds
the scoped call ID to request digest, binding fingerprint, tool and target
metadata.

## Streaming ordering

`TurnRunner::run_with_sink` and
`TurnRunner::run_with_sink_and_cancellation` synchronously invoke a
`TurnEventSink` as each event is produced:

```text
turn.accepted
provider/model event*
tool accepted/started/output/terminal*
provider/model event*
turn.terminal
```

The event is retained in the returned `TurnRun` for source compatibility, but
Host observability and durable persistence no longer wait for turn completion.
A sink failure cancels an active local process through the bridge and returns a
mechanical Host error; it does not reinterpret the command.

## Cancellation

`TurnCancellation` is an `Arc<AtomicBool>` mechanism token. Before a new tool
call, a cancelled turn rejects the call. During an active tool call, a bounded
monitor requests cancellation through the exact scoped call registry; the
bridge then terminates the owned process group and records the terminal.

The selected Host supplies the token from its independent control loop:

- `turn.cancel` sets the turn token and is also translated to provider JSONL;
- `tool.cancel` requests cancellation only for the named scoped call;
- client EOF or output failure does not set either cancellation path.

## Duplicate behavior

- exact scoped call and request: return `ToolOutcome::Existing`; do not spawn;
- same scoped call ID with different binding: return a bridge/registry conflict;
- inhibited call: return `ToolOutcome::Inhibited`; do not spawn;
- newly granted call: execute through the mechanism-only process runtime.

Durable replay of raw Host frames is owned by the Host/event-store layer, not by
the in-memory call registry.

## Failure behavior

- non-zero shell/ADB exit is a tool observation; provider may continue;
- targeted cancellation is a cancelled tool observation; provider may continue;
- turn cancellation may end the provider turn as cancelled;
- bridge failure is returned to provider code;
- provider-returned error becomes one `provider_failed` terminal;
- provider panic becomes one `provider_panicked` terminal;
- provider terminal text is mechanically bounded and NUL-free.

## Tests authored

- deliberate shell exit with stdout/stderr followed by provider continuation;
- duplicate call produces one process-side file mutation;
- ordinary ADB unknown argv remains exact and target metadata is not injected;
- provider panic produces one terminal;
- provider events reach the sink before `emit` returns;
- runtime `started` reaches the sink before the process can complete;
- turn cancellation reaches an active tool process group.

Claim ceiling remains **SOURCE_IMPLEMENTED / L0** until the exact commit passes
Rust formatting, tests and clippy on an executing runner.
