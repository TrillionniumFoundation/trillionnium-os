# Owner-open Codex MCP job bridge — isolated source evidence

Date: 2026-08-28  
Evidence ceiling: **L0 isolated adapter source and process-fixture evidence**

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

Ran 3 tests in 7.869s
OK
```

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
- child pipes and reader threads close cleanly with resource warnings promoted
  to errors.

## Not proved

- exact checkout equality beyond later source fetch comparison;
- GitHub Actions execution;
- Rust compilation, tests or clippy;
- v5 transport to v7 core startup;
- installed Codex MCP registration or tool invocation;
- same-turn model continuation after a real job observation;
- Root Linux or Android effects;
- fault or release qualification.
