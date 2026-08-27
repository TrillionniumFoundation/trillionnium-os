# Owner-open external provider adapter v1

Status: **R5 source implementation; Rust/real-provider validation pending**  
Source: `crates/trillionnium-owner-open-provider-jsonl`  
Executable source Host: `apps/trillionnium-owner-open-host/src/bin/r5_host.rs`

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
  -> provider turn.complete
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
- graceful wait followed by TERM/KILL and leader reap;
- original protocol/tool failure retained after cleanup.

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

## Host carrier source

`trillionnium-owner-open-r5-host` is an explicit stdio qualification binary. It
truthfully reports:

- external JSONL provider configured;
- same-turn callback source available;
- runtime ready for the configured source path;
- event storage is memory-only/best-effort;
- asynchronous control is not implemented.

It maps runtime chunks to compact base64 `tool.stdout`/`tool.stderr` frames and
preserves process terminal fields. It does not claim the Android abstract
socket, peer credentials, durable store or reconnect.

## Authored tests

Provider package:

- external provider receives failed shell observation and continues;
- recursive duplicate provider member fails before spawn;
- EOF before terminal is a truthful provider failure;
- unknown tool is returned without killing the semantic turn.

Host package:

- spawns the R5 Host binary;
- writes client hello and turn.start;
- spawns an external provider fixture;
- executes a real shell child with exit 9 and stdout/stderr;
- returns tool events to the provider;
- observes provider continuation and completed Host turn.

These are authored tests, not executed Rust evidence until a real runner binds
results to the exact commit.
