# Owner-open development tools

These are explicit owner bootstrap, observation and source-qualification
utilities. They are not semantic approval gates, and their output alone is not
an integrated Codex turn or device-effect claim.

Canonical entries:

- `probe_codex_cli.py` — read-only executable/help observation;
- `build_codex_exec_prefix.py` — executable-bound, unexecuted launch prefix;
- `execute_codex_exec_plan.py` — explicit execution of a reviewed launch plan;
- `codex_owner_open_mcp.py` — local STDIO MCP server exposing the selected
  Host's long-running `shell.job` controls to Codex;
- `owner_open_mcp_common.py` — strict JSON, correlation and bounded result
  mechanics shared by the MCP bridge;
- `owner_open_mcp_host.py` — bounded exact-frame client for the selected v5
  transport Host and v7 core;
- `owner_open_mcp_jobs.py` — MCP tool schemas and exact job-wire mapping;
- `jsonl_provider_runtime.py` — provider-neutral bounded duplex JSONL process
  mechanics for W1 fixtures and bootstrap adapters;
- `prepare-adb-reverse-v1.sh` — explicit owner-host reverse bootstrap.

## Codex MCP registration

The bridge is intended to run as a local STDIO MCP server under Codex. A
representative registration is:

```sh
codex mcp add trillionnium-owner-open-jobs -- \
  python3 /absolute/repo/tools/owner-open/codex_owner_open_mcp.py \
  --host /absolute/bin/trillionnium-owner-open-r5-host \
  --core /absolute/bin/trillionnium-owner-open-r5-core \
  --provider /absolute/provider-adapter \
  --job-store /absolute/state/jobs.jsonl \
  --event-store /absolute/state/events.jsonl
```

Equivalent `config.toml`:

```toml
[mcp_servers.trillionnium-owner-open-jobs]
command = "python3"
args = [
  "/absolute/repo/tools/owner-open/codex_owner_open_mcp.py",
  "--host", "/absolute/bin/trillionnium-owner-open-r5-host",
  "--core", "/absolute/bin/trillionnium-owner-open-r5-core",
  "--provider", "/absolute/provider-adapter",
  "--job-store", "/absolute/state/jobs.jsonl",
  "--event-store", "/absolute/state/events.jsonl",
]
startup_timeout_sec = 10
```

The bridge exposes:

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

One MCP server lifetime receives one mechanically allocated scope unless the
owner pins explicit session/task/turn/stream IDs. Effectful controls require a
stable `operation_id`. The bridge never supplies semantic approval, rewrites a
command, chooses a weaker target, or retries an uncertain effect.

The unversioned `prepare-adb-reverse.sh` was an intermediate source draft. It
must not be referenced by plans, automation or evidence; use the `-v1` tool.

Every tool has a machine status/evidence boundary. A help probe, MCP fixture,
launch prefix, fake provider, reverse mapping or qualified ELF may never be
promoted to a live installed-Codex, physical-device or release claim without
the later acceptance gates.
