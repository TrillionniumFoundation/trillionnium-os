# Owner-open Codex MCP jobs v1

Status: **R5 source implementation; installed-Codex and Rust Host evidence pending**  
Semantic authority: `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`  
MCP entry: `tools/owner-open/codex_owner_open_mcp.py`

## 1. Purpose

This binding gives Codex a native local MCP surface for the reviewed
owner-open `shell.job` wire:

```text
Codex MCP client
  -> local newline-delimited JSON-RPC STDIO
  -> optional exact-byte trace proxy
  -> codex_owner_open_mcp.py
  -> selected v5 transport Host or multi-connection broker
  -> selected job-aware v7 execution core
  -> durable pipe or PTY job runtime
```

The bridge is mechanism-only. Codex remains the only semantic principal. The
bridge does not classify commands, require approval, assign risk, rewrite
arguments, inject targets, choose compensating actions or retry uncertainty.

## 2. MCP transport

The server uses MCP protocol version `2025-06-18` over STDIO. Each input and
output message is one UTF-8 JSON-RPC object terminated by a newline.

The decoder rejects empty/oversized messages, missing newline termination,
invalid UTF-8/JSON, recursive duplicate object members, malformed JSON-RPC and
duplicate in-flight request IDs. Only MCP messages are written to stdout;
startup/fatal diagnostics use stderr.

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
trillionnium_connection_info
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

| MCP tool | Host operation |
| --- | --- |
| `trillionnium_connection_info` | local bridge identity only |
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
inspection until terminal observation or timeout.

## 4. Correlation and connection identity

One MCP server lifetime has one job scope:

```text
session_id
profile_id
task_id
turn_id
turn_stream_id
```

The owner may pin those IDs. Missing IDs are generated mechanically with random
suffixes. Every tool call adds `job_id`.

The process also generates one `bridge_instance_id`. Codex obtains it through:

```text
trillionnium_connection_info {}
```

The result is local lifecycle correlation, not a semantic capability lease.

## 5. Live-control ownership

The following tools require the current `bridge_instance_id` in their input:

```text
trillionnium_job_start
trillionnium_job_attach
trillionnium_job_detach
trillionnium_job_write
trillionnium_job_resize
trillionnium_job_close_stdin
trillionnium_job_kill
```

A missing or mismatched bridge ID fails before Host dispatch. No job frame is
emitted and no local effect is attempted.

Read-only operations remain usable from a later connection:

```text
trillionnium_job_inspect
trillionnium_job_wait
```

A later bridge must use the stable job scope and, when available,
`request_sha256`. It can read durable truth but cannot claim that it owns an old
pipe, PTY master or process-group handle. Cross-Host live descriptor adoption
is explicitly unsupported in v1.

## 6. Effect identity

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
idempotency, changed-byte conflict and `unknown_after_restart` behavior.

A caller must inspect an uncertain outcome before choosing a new operation.
MCP tool-error results state `automatic_redispatch=false`.

## 7. Start and byte semantics

`trillionnium_job_start` requires `job_id`, `bridge_instance_id`,
`operation_id`, `mode=pipe|pty` and exactly one of command or argv. Optional
fields include cwd, environment delta, initial stdin, PTY dimensions, target
correlation, request digest, binding fingerprint and opaque extensions.

The bridge validates only representability and ambiguity:

- command and argv are mutually exclusive;
- strings are NUL-free;
- argv is non-empty;
- environment keys cannot contain NUL or `=`;
- PTY dimensions are finite and non-zero;
- base64 input decodes canonically;
- claimed digests are lowercase SHA-256.

It does not maintain a command or executable allowlist.

## 8. Results and annotations

Successful calls include MCP text content and `structuredContent`, carrying
scope, job ID, Host response, bounded observations and
`automatic_redispatch=false`.

Operation annotations are specific:

- connection-info, inspect and wait are read-only and closed-world;
- attach/detach mutate local bookkeeping but are not marked destructive;
- start/write/close/kill are destructive and open-world;
- PTY resize is mutating/open-world but not labeled destructive.

Host-reported job failures remain MCP tool results with `isError=true`, the raw
Host frame when available and no automatic redispatch. Invalid arguments use
JSON-RPC `-32602`. Results are bounded to 1 MiB; oversized results direct Codex
to narrower cursor inspection.

## 9. Cancellation

MCP `notifications/cancelled` sets the cancellation token for the corresponding
in-flight MCP request. This stops the bridge wait. It does not falsely claim
that an already accepted Host effect did not occur.

Cancelling an MCP request is not a substitute for `trillionnium_job_kill`.
Explicit process termination remains a separate operation with a stable
`operation_id` and bridge identity.

## 10. Launch and qualification

All configured executable paths are absolute stable regular files. Job/event
store parents already exist and are private.

Installed-Codex qualification uses:

```text
tools/owner-open/trace_mcp_stdio.py
tools/owner-open/qualify_codex_mcp_jobs.py
```

The qualification contract is documented in
`owner-open-installed-codex-mcp-qualification-v1.md` and requires an exact
connection-info plus pipe/PTY tool sequence, successful JSON-RPC responses,
Codex completed-turn JSONL and deterministic cleanup.

## 11. Evidence boundary

Source fixtures can verify strict JSON, tool discovery, exact job forwarding,
bridge ownership, no hidden retry, annotations and process cleanup. They do not
establish:

- exact-checkout Rust success;
- installed Codex loading this MCP server;
- a live Codex turn controlling Root Linux pipe/PTY jobs;
- Android or physical-device integration;
- fault or release qualification.

Until those records exist, this capability remains `SOURCE_IMPLEMENTED / L0`.
