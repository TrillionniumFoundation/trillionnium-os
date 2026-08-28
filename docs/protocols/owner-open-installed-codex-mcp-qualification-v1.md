# Installed Codex MCP job qualification v1

Status: **R5 executable qualification contract; target execution pending**

## 1. Goal

This qualification proves more than an MCP fixture. It binds one measured
installed Codex executable to the selected Trillionnium MCP bridge, v5 transport
Host, v7 execution core and durable job runtime, then proves one real Codex turn
uses the expected pipe and PTY controls.

The canonical runner is:

```text
tools/owner-open/qualify_codex_mcp_jobs.py
```

The exact-byte transport recorder is:

```text
tools/owner-open/trace_mcp_stdio.py
```

## 2. Required isolation

Qualification requires:

- an explicit `--execute` flag;
- a dedicated private `CODEX_HOME`;
- a private workspace;
- a new private evidence directory;
- absolute stable paths for Codex, Python, trace proxy, MCP bridge, Host,
  provider adapter and optional core/shell;
- private job and event stores;
- finite command and turn timeouts.

The runner refuses a pre-existing qualification MCP server name. It snapshots
`config.toml`, locks the dedicated `CODEX_HOME`, removes the temporary MCP
registration in `finally`, restores the exact original configuration bytes and
removes the qualification lock.

## 3. Measurements

Before mutation, the runner measures each supplied file through a stable open
file descriptor and records:

```text
path
SHA-256
byte count
UID/GID
mode
device/inode
```

Optional expected SHA-256 arguments turn those observations into hard binding
requirements. Group/world-writable, symlinked, multiply linked, changing or
oversized files are rejected.

## 4. Codex capability observations

The runner executes bounded observations for:

```text
codex --version
codex --help
codex mcp --help
codex exec --help
codex login status
```

It requires the installed CLI to advertise MCP add/get/list/remove and one
observed owner-open execution mode. Help observation alone is not a live-turn
claim.

## 5. Temporary MCP registration

The temporary server command is:

```text
Codex
  -> trace_mcp_stdio.py
  -> codex_owner_open_mcp.py
  -> selected Host / core / job runtime
```

After `codex mcp add`, both `mcp get --json` and `mcp list --json` are recorded.
The returned registration must bind the expected trace proxy and MCP bridge
paths before execution continues.

## 6. Exact tool sequence

The Codex instruction requires exactly eleven native MCP calls:

```text
1.  trillionnium_connection_info
2.  trillionnium_job_start          pipe-job / pipe-start
3.  trillionnium_job_write          pipe-job / pipe-write
4.  trillionnium_job_close_stdin    pipe-job / pipe-close
5.  trillionnium_job_wait           pipe-job
6.  trillionnium_job_start          pty-job / pty-start
7.  trillionnium_job_write          pty-job / pty-write
8.  trillionnium_job_resize         pty-job / pty-resize / 40x120
9.  trillionnium_job_inspect        pty-job
10. trillionnium_job_kill           pty-job / pty-kill / SIGTERM
11. trillionnium_job_wait           pty-job
```

Every live/mutating call must carry the `bridge_instance_id` returned by call 1.
No additional tool call, missing call, reordered call, changed job ID, changed
operation ID, changed dimensions or hidden retry is accepted.

## 7. Trace validation

The trace proxy preserves each newline-delimited JSON-RPC frame byte-for-byte.
Each trace record binds:

```text
connection_id
monotonic sequence
elapsed time
direction
byte count
SHA-256
base64 raw line
strict parsed object
```

Recursive duplicate members, invalid UTF-8/JSON, unterminated frames, trace
capacity exhaustion or downstream transport failure fail qualification.

For each traced `tools/call`, the validator requires a corresponding successful
JSON-RPC response with `isError != true`. It does not infer success from model
prose.

## 8. Codex JSONL validation

`codex exec --json` output is stored unchanged. Qualification requires:

- at least one parsed JSONL event;
- no turn/item failure event;
- a completed-turn event; and
- the exact final marker:

```text
TRILLIONNIUM_OWNER_OPEN_MCP_JOBS_QUALIFIED
```

## 9. Deterministic teardown

Both ordinary command execution and the MCP trace proxy use a new process
session. Timeout or upstream EOF triggers finite SIGTERM grace, SIGKILL
escalation if needed, and deterministic process-group reap.

A downstream MCP server that ignores EOF must not leave the qualification
runner blocked indefinitely. Teardown failure is a failed qualification, not a
pass with a warning.

## 10. Evidence package

The private evidence directory contains at least:

```text
mcp-get.json
mcp-list.json
codex-events.jsonl
codex-stderr.bin
mcp-trace.jsonl
mcp-stderr.bin
qualification-terminal.json
```

The terminal document records measurements, command output digests, exact
trace and Codex event summaries, cleanup result, restored config digest and
`automatic_redispatch=false`.

## 11. Promotion boundary

A successful run is an L2 candidate only when its evidence is bound to one
exact repository commit and reviewed Rust Host artifacts. It does not by itself
establish:

- Android image inclusion;
- physical ADB behavior;
- reboot/power-loss conformance;
- public release qualification.
