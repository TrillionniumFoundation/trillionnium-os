# Owner-open Codex MCP jobs v1

Status: **R5 source implementation; installed-Codex and Rust Host evidence pending**  
Semantic authority: `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`  
MCP entry: `tools/owner-open/codex_owner_open_mcp.py`

## 1. Purpose

This binding gives Codex a native local MCP tool surface for the reviewed
owner-open `shell.job` wire:

```text
Codex MCP client
  -> local newline-delimited JSON-RPC STDIO
  -> codex_owner_open_mcp.py
  -> selected v5 transport Host
  -> selected job-aware v7 execution core
  -> durable pipe or PTY job runtime
```

The bridge is mechanism-only. Codex remains the only semantic principal. The
bridge does not classify commands, require approval, assign risk, rewrite
arguments, inject targets, choose compensating actions or retry uncertainty.

## 2. MCP transport

The server uses MCP protocol version `2025-06-18` over STDIO. Each input and
output message is one UTF-8 JSON-RPC object terminated by a newline.

The decoder rejects:

- empty or over-1-MiB messages;
- missing newline termination;
- invalid UTF-8 or JSON;
- recursive duplicate object members;
- malformed JSON-RPC requests;
- duplicate in-flight request IDs.

Only MCP messages are written to stdout. Startup and fatal diagnostics use
stderr.

Implemented methods:

```text
initialize
ping
tools/list
tools/call
shutdown
exit
notifications/initialized
notifications/cancelled
```

## 3. Tools

The server exposes:

```text
trillionnium_job_start
trillionnium_job_inspect
trillionnium_job_attach
trillionnium_job_detach
trillionnium_job_write
trillionnium_job_resize
trillionnium_job_close_stdin
trillionnium_job_kill
trillionnium_job_wait
```

Mapping is exact:

| MCP tool | Host frame |
| --- | --- |
| `trillionnium_job_start` | `job.start` |
| `trillionnium_job_inspect` | `job.inspect` |
| `trillionnium_job_attach` | `job.attach` |
| `trillionnium_job_detach` | `job.detach` |
| `trillionnium_job_write` | `job.write` |
| `trillionnium_job_resize` | `job.resize` |
| `trillionnium_job_close_stdin` | `job.close_stdin` |
| `trillionnium_job_kill` | `job.kill` |
| `trillionnium_job_wait` | repeated read-only `job.inspect` |

`job_wait` never starts, repeats or repairs an effect. It polls bounded
inspection until a terminal observation or timeout.

## 4. Correlation

One MCP server lifetime has one job scope:

```text
session_id
profile_id
 task_id
turn_id
turn_stream_id
```

The owner may pin all IDs on the bridge command line. Missing IDs are allocated
mechanically with cryptographically random suffixes. Every tool call adds its
`job_id` to that scope.

The bridge does not infer correlation from command text, model prose or target
state.

## 5. Effect identity

Every effectful operation requires a stable `operation_id`:

```text
start
write
resize
close_stdin
kill
```

The bridge sends each MCP invocation to the Host exactly once. It does not add
an internal retry. The Host job journal remains responsible for exact duplicate
idempotency, byte conflict and `unknown_after_restart` behavior.

A caller must inspect an uncertain outcome before choosing any new operation.
MCP error results always state `automatic_redispatch=false`.

## 6. Start semantics

`trillionnium_job_start` requires:

```text
job_id
operation_id
mode = pipe | pty
exactly one of command or argv
```

Optional fields include cwd, environment delta, initial stdin, PTY dimensions,
target correlation, claimed request digest, claimed binding fingerprint and
opaque extensions.

The bridge validates only representability and ambiguity:

- command and argv are mutually exclusive;
- strings are NUL-free;
- argv is non-empty;
- environment keys cannot contain NUL or `=`;
- PTY rows and columns are finite and non-zero;
- base64 input must decode canonically;
- claimed digests are lowercase SHA-256.

It does not maintain a command or executable allowlist.

## 7. Results and errors

Successful `tools/call` responses include both MCP text content and
`structuredContent`:

```json
{
  "schema": "org.trillionnium.owner-open.mcp-job-result.v1",
  "job_id": "...",
  "scope": {},
  "automatic_redispatch": false,
  "response": {},
  "observed_frames": [],
  "observed_frame_count": 1
}
```

Host-reported job failures remain MCP tool results with `isError=true`, the raw
Host frame when available and `automatic_redispatch=false`. Invalid MCP tool
arguments use JSON-RPC `-32602`; transport/internal boundaries use their normal
JSON-RPC error classes.

The MCP result is bounded to 1 MiB. Oversized results return a finite error and
direct the caller to narrower cursor inspection.

## 8. Cancellation

MCP `notifications/cancelled` sets the cancellation token for the corresponding
in-flight MCP request. This stops the bridge wait. It does not falsely claim
that an already accepted Host effect did not occur.

Cancelling an MCP request is not a substitute for `trillionnium_job_kill`.
Explicit process termination remains a separate operation with its own stable
`operation_id`.

## 9. Launch binding

All executable paths must be absolute, executable, non-symlink regular files
with one hard link. Job and event store paths must be absolute, non-symlink
paths whose parents already exist.

Representative registration:

```sh
codex mcp add trillionnium-owner-open-jobs -- \
  python3 /absolute/repo/tools/owner-open/codex_owner_open_mcp.py \
  --host /absolute/bin/trillionnium-owner-open-r5-host \
  --core /absolute/bin/trillionnium-owner-open-r5-core \
  --provider /absolute/provider-adapter \
  --job-store /absolute/state/jobs.jsonl \
  --event-store /absolute/state/events.jsonl
```

The provider path is retained because the selected Host also serves same-turn
provider requests. Direct job frames do not start the provider.

## 10. Evidence boundary

The source regression suite uses a fake Host to verify:

- MCP initialize and tool discovery;
- exact start/write/close/wait forwarding;
- scope and `tool=shell.job` correlation;
- recursive duplicate JSON rejection;
- ambiguous command+argv rejection;
- no hidden bridge retry;
- clean process/pipe shutdown under `ResourceWarning`-as-error.

That suite is isolated Python evidence. It does not establish:

- the current repository checkout passes all CI commands;
- the Rust v5 transport launches the Rust v7 core;
- an installed Codex process loads this MCP server;
- a live Codex turn controls a real Root Linux pipe or PTY;
- Android or physical-device integration;
- fault or release qualification.
