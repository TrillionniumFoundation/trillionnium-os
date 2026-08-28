# R5 Batch D checkpoint: Codex MCP job binding

Status: **SOURCE_IMPLEMENTED / L0; installed-Codex and Rust Host execution pending**

This checkpoint follows the durable jobs selection checkpoint. It adds a native
Codex-facing STDIO MCP surface without changing the R3 semantic contract.

## Landed source slice

```text
Codex local MCP client
  -> codex_owner_open_mcp.py
  -> selected v5 transport Host
  -> selected job-aware v7 core
  -> durable shell.job runtime
```

Implemented source behavior:

1. strict newline-delimited JSON-RPC and MCP initialization;
2. bounded `tools/list` and concurrent `tools/call` handling;
3. exact tools for job start, inspect, attach, detach, write, resize,
   close-stdin, kill and bounded wait;
4. one mechanically allocated or owner-pinned scope per MCP server lifetime;
5. stable operation IDs on every effectful job control;
6. exact command/argv and UTF-8/base64 forwarding;
7. no semantic approval, risk classification or command rewriting;
8. no internal retry of uncertain Host effects;
9. `automatic_redispatch=false` on Host and bridge error results;
10. MCP cancellation separated from explicit job termination.

## Executed isolated evidence

The staged Python implementation was executed with:

```sh
python3 -m py_compile \
  tools/owner-open/codex_owner_open_mcp.py \
  tools/owner-open/owner_open_mcp_common.py \
  tools/owner-open/owner_open_mcp_host.py \
  tools/owner-open/owner_open_mcp_jobs.py \
  tools/tests/test_codex_owner_open_mcp.py

PYTHONWARNINGS=error::ResourceWarning \
python3 -m unittest tools.tests.test_codex_owner_open_mcp -v
```

Result: **3 tests run, 3 passed**. The test used a fake Host and did not use an
installed Codex or the Rust v5/v7 binaries, so it cannot promote W2 or W3 beyond
L0 source evidence.

## Next acceptance gate

1. execute the repository Python and Rust workflows on one exact commit;
2. run `probe_codex_cli.py` against the installed target Root Linux Codex;
3. register this bridge as a local STDIO MCP server using the observed Codex
   configuration interface;
4. prove one installed Codex turn invokes:
   - pipe job start/write/close/wait;
   - PTY job start/write/resize/inspect/kill;
5. capture raw MCP, Host, job journal and provider-turn events;
6. prove an exact duplicate operation does not repeat the local effect;
7. prove an uncertain operation is inspected rather than automatically retried.

## Hold

Do not describe this source slice as a live installed-Codex adapter until the
actual target executable, launch configuration, MCP handshake, tool calls and
same-turn continuation are bound in L2 evidence.
