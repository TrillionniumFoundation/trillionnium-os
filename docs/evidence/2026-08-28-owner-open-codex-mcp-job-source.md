# Owner-open Codex MCP job bridge — isolated source evidence

Date: 2026-08-28  
Evidence ceiling: **L0 exact adapter-source and isolated process-fixture evidence**

## Scope

This record covers:

- `tools/owner-open/codex_owner_open_mcp.py`
- `tools/owner-open/owner_open_mcp_common.py`
- `tools/owner-open/owner_open_mcp_host.py`
- `tools/owner-open/owner_open_mcp_jobs.py`
- `tools/tests/test_codex_owner_open_mcp.py`

It does not cover an installed Codex executable, a compiled Rust Host, Android,
Root Linux placement or a physical device.

## Environment

```text
Python 3.13.5
Linux x86_64
isolated staged source tree
Rust toolchain unavailable
private repository checkout unavailable
```

## Commands

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

## Result

```text
test_duplicate_json_and_invalid_effect_arguments_fail_mechanically ... ok
test_exact_duplicate_host_control_result_is_returned_without_server_retry ... ok
test_stdio_mcp_exposes_and_drives_job_tools ... ok
test_tool_annotations_distinguish_read_only_and_mutating_operations ... ok

Ran 4 tests in 7.960s
OK
```

## Source binding

After the final isolated run, local `git hash-object` values were compared with
the GitHub blob SHA returned for each checked-in file:

```text
b400d7545f37a4ccfdd56f4da0a3afe61e27e9b6  codex_owner_open_mcp.py
31474ac9d38a5a3376dc5962d5244161c2d35514  owner_open_mcp_common.py
e95a0c20d53d65ae675c81cbe17aa182a282ce96  owner_open_mcp_host.py
04742f50cb4165ef665955a9a45dcca141087e8f  owner_open_mcp_jobs.py
5af3139c03f801102b064a82275d4ac37ff4af2e  test_codex_owner_open_mcp.py
```

All five GitHub blob SHAs match the exact files used by the final isolated test.
This binds the adapter source and test bytes, but it is not a full repository
checkout or CI result.

## Verified behavior

- MCP `initialize` returns protocol `2025-06-18`;
- `tools/list` exposes the long-running job tools;
- start, write, close-stdin and wait map to the exact Host job frames;
- the configured session/task/turn/stream scope is forwarded;
- `tool=shell.job` and the caller's operation ID are preserved;
- no semantic approval field is inserted;
- recursive duplicate JSON members fail with parse error;
- command plus argv ambiguity fails before Host dispatch;
- two explicit duplicate start calls result in exactly two Host requests, not a
  hidden third bridge retry;
- inspect/wait are read-only and closed-world in MCP metadata;
- attach/detach mutate local bookkeeping without being labeled destructive;
- start/write/close/kill are explicitly destructive and open-world;
- PTY resize is mutating and open-world but not labeled destructive;
- child pipes and reader threads close cleanly with resource warnings promoted
  to errors.

## Not proved

- full exact-checkout graph or workflow execution;
- Rust compilation, tests or clippy;
- v5 transport to v7 core startup;
- installed Codex MCP registration or tool invocation;
- same-turn model continuation after a real job observation;
- Root Linux or Android effects;
- fault or release qualification.
