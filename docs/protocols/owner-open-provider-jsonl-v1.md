# Owner-open provider JSONL v1

Protocol: `trillionnium.owner-open.provider-jsonl.v1`  
Status: **R5 source protocol; live Codex compatibility not yet claimed**

## Transport

One child process serves one semantic turn. Host writes newline-delimited JSON
to provider stdin; provider writes newline-delimited JSON to stdout. Stderr is
bounded diagnostic output and never parsed as events.

Every frame contains:

```json
{
  "protocol": "trillionnium.owner-open.provider-jsonl.v1",
  "kind": "...",
  "seq": 0
}
```

`seq` is independently monotonic and contiguous in each direction. Duplicate
object members at any nesting depth, non-finite numbers, non-object records,
missing newline termination, out-of-order sequence and oversized records are
protocol failures.

## Host to provider

### `turn.start`

First frame, sequence zero:

```json
{
  "protocol": "trillionnium.owner-open.provider-jsonl.v1",
  "kind": "turn.start",
  "seq": 0,
  "turn": {
    "session_id": "session-...",
    "profile_id": "owner-open",
    "task_id": "task-...",
    "turn_id": "turn-...",
    "turn_stream_id": "stream-...",
    "user_input": "..."
  }
}
```

### `tool.result`

The Host replies to one provider `tool.call`. `status` is one of:

- `terminal` — one real local process call completed;
- `existing` — exact scoped duplicate attached to an existing call;
- `inhibited` — registry state proves no new spawn is permitted;
- `invalid_request` — malformed or unsupported mechanism request;
- `host_error` — local bridge/runtime failure.

A terminal result contains ordered accepted/started/output/terminal events,
base64 output bytes, exit/signal/timeout state, output counts, observation hash
and registry snapshot. Tool failure is an observation; the provider may
continue the same turn.

## Provider to Host

### `provider.event`

Known event labels:

- `provider.status`
- `model.delta`
- `model.message`

Unknown labels remain opaque provider events, subject only to frame/resource
bounds.

### `tool.call`

```json
{
  "protocol": "trillionnium.owner-open.provider-jsonl.v1",
  "kind": "tool.call",
  "seq": 1,
  "call": {
    "call_id": "call-...",
    "tool": "shell.exec",
    "command": "printf hello"
  }
}
```

The Host fills missing turn correlation from the active turn and rejects any
conflicting supplied correlation. It computes canonical request bytes and a
configuration binding. `shell.exec` accepts exactly one of `command` or `argv`;
`adb.exec` accepts exact argv excluding the program name. Target metadata is
not translated into `-s`, host/port or privilege arguments.

### Turn terminal

- `turn.complete` — provider completed normally;
- `turn.cancelled` — provider reports cancellation;
- `turn.fail` — provider reports a terminal failure.

Provider EOF or process exit before one of these frames is
`provider_interrupted`/failed turn evidence.

## Bounds and lifecycle

Initial owner defaults:

- provider line: 32 MiB;
- aggregate provider stdout: 64 MiB;
- provider stderr prefix: 1 MiB;
- provider events: 4096;
- provider turn timeout: 300 seconds;
- TERM-to-KILL cleanup grace: 250 ms.

The 32 MiB line is a finite P0 compatibility envelope for one aggregate result
containing the runtime's bounded 16 MiB output in base64. Incremental provider
result frames and live backpressure are a later protocol revision.

The provider runs in its own process group. Timeout, protocol failure or Host
teardown closes the process group and reaps the leader. Cleanup status must not
replace the earlier, more specific protocol/tool failure.

## Explicit limitations

This source protocol does not yet prove:

- compatibility with the installed Codex CLI/app-server;
- asynchronous `turn.cancel` or `tool.cancel` while provider code is running;
- PTY callbacks;
- durable event replay or reconnect;
- Android abstract socket, SELinux or device effects.
