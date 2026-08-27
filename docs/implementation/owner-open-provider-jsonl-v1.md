# Owner-open external provider adapter v1

Status: **R5 source implementation; Rust/real-provider validation pending**  
Source: `crates/trillionnium-owner-open-provider-jsonl`  
Selected source Host: `apps/trillionnium-owner-open-host/src/bin/r5_control_host_v2.rs`

## Implemented source path

```text
client turn.start
  -> trillionnium-owner-open-r5-host
  -> external provider process / turn.start
  -> provider.event
  -> provider tool.call
  -> strict owner-open ToolCall codec
  -> scoped call registry
  -> direct process runtime
  -> provider tool.result
  -> provider continues
  -> provider turn.complete / turn.cancelled
  -> Host turn.end
```

The provider executable, argv, cwd, environment, shell executable and ordinary
ADB executable are owner configuration. The adapter does not infer a Codex
version from source names and does not silently replace an unsupported provider
or access mode.

## Process mechanics

- one provider process group per turn;
- stdin/stdout/stderr pipes;
- recursive duplicate-member-safe JSON;
- independent inbound/outbound sequence checks;
- provider line and aggregate stdout ceilings;
- continuously drained bounded stderr;
- absolute monotonic turn timeout;
- explicit cancellation grace followed by TERM/KILL and leader reap;
- original protocol/tool/provider failure retained after cleanup.

## Tool conversion

The provider `call` object decodes through `trillionnium-owner-open-types`.
Missing session/profile/task/turn/stream correlation is filled from the active
turn; conflicting correlation is rejected.

Before registry admission the adapter:

1. removes claimed request/binding digests from the canonical preimage;
2. serializes the normalized ToolCall deterministically;
3. computes a configuration fingerprint over tool, selected executable and
   configuration generation;
4. verifies any provider-claimed digests;
5. constructs `ShellExecRequest` or `AdbExecRequest` mechanically.

Command meaning is never classified. PTY is currently reported unsupported
rather than silently downgraded. Unknown tools receive `invalid_request` and the
provider may continue.

## Cancellation

The adapter observes the active `ProviderHost` turn token.

When cancelled it writes:

```json
{
  "protocol": "trillionnium.owner-open.provider-jsonl.v1",
  "kind": "turn.cancel",
  "seq": 2,
  "turn": {
    "session_id": "...",
    "profile_id": "owner-open",
    "task_id": "...",
    "turn_id": "...",
    "turn_stream_id": "..."
  }
}
```

A provider may reply with `turn.cancelled`. If it does not reply within the
configured mechanical grace, the provider process group is closed and the Host
reports a cancelled turn. This is process lifecycle, not a semantic denial.

A targeted `tool.cancel` does not set the provider turn token. It cancels the
scoped call through the call registry; the adapter returns a `tool.result` whose
terminal has `kind=client_cancelled`, and the provider may continue the same
turn.

## Host carrier source

The selected `trillionnium-owner-open-r5-host` has:

- a bounded input/control reader;
- an independent provider turn worker;
- per-event durable append and immediate delivery attempt;
- active correlated `turn.cancel`;
- active targeted `tool.cancel`;
- client EOF/output loss detached from cancellation;
- completed replay without provider restart;
- incomplete recovery without automatic redispatch.

The current source carrier is stdio qualification infrastructure. Android
abstract socket and kernel peer admission remain W6.

## Authored tests

Provider package:

- external provider receives failed shell observation and continues;
- recursive duplicate provider member fails before spawn;
- EOF before terminal is a truthful provider failure;
- unknown tool is returned without killing the semantic turn;
- correlated `turn.cancel` is delivered and `turn.cancelled` is accepted.

Host package:

- spawned provider/shell callback with non-zero exit and continuation;
- in-flight event persistence before provider terminal;
- client output disconnect with continued terminal persistence;
- active `turn.cancel` while a shell call runs;
- targeted `tool.cancel` followed by provider continuation;
- completed replay and incomplete conservative recovery without provider
  redispatch.

These are authored tests, not executed Rust evidence until a real runner binds
results to the exact commit.
