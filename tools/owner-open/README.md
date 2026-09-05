# Owner-open development tools

These are explicit owner bootstrap, transport, observation and
source-qualification utilities. They are not semantic approval gates, and their
output alone is not an integrated Codex turn or device-effect claim.

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
- `owner_open_mcp_jobs.py` — MCP tool schemas, connection identity and exact
  job-wire mapping;
- `owner_open_broker_common.py` — strict descriptor, token, path and executable
  mechanics for the multi-connection broker;
- `owner_open_connection_broker.py` — one-upstream filesystem Unix broker with
  bounded multi-client routing;
- `owner_open_broker_client.py` — Host-compatible broker client transport;
- `trace_mcp_stdio.py` — exact-byte bounded MCP STDIO trace and deterministic
  downstream process-group lifecycle;
- `qualify_codex_mcp_jobs.py` — temporary-registration installed-Codex MCP job
  qualification runner;
- `jsonl_provider_runtime.py` — provider-neutral bounded duplex JSONL process
  mechanics for W1 fixtures and bootstrap adapters;
- `prepare-adb-reverse-v1.sh` — explicit owner-host reverse bootstrap.

## Codex MCP registration

The bridge can run directly over the selected Host:

```sh
codex mcp add trillionnium-owner-open-jobs -- \
  python3 /absolute/repo/tools/owner-open/codex_owner_open_mcp.py \
  --host /absolute/bin/trillionnium-owner-open-r5-host \
  --core /absolute/bin/trillionnium-owner-open-r5-core \
  --provider /absolute/provider-adapter \
  --job-store /absolute/state/jobs.jsonl \
  --event-store /absolute/state/events.jsonl
```

The bridge exposes:

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

One MCP server lifetime receives one mechanically allocated
`bridge_instance_id` and one correlation scope unless the owner pins explicit
session/task/turn/stream IDs. Start, attach, detach, write, resize, close and
kill require that live bridge ID. Inspect and wait remain durable read-only
operations for later connections.

The bridge never supplies semantic approval, rewrites a command, chooses a
weaker target or retries an uncertain effect.

## Installed Codex qualification

Use a dedicated private `CODEX_HOME`, workspace and new evidence directory:

```sh
python3 tools/owner-open/qualify_codex_mcp_jobs.py \
  --execute \
  --codex /absolute/bin/codex \
  --python /absolute/bin/python3 \
  --trace-proxy /absolute/repo/tools/owner-open/trace_mcp_stdio.py \
  --mcp-bridge /absolute/repo/tools/owner-open/codex_owner_open_mcp.py \
  --host /absolute/bin/trillionnium-owner-open-r5-host \
  --core /absolute/bin/trillionnium-owner-open-r5-core \
  --provider /absolute/provider-adapter \
  --shell /absolute/bin/sh \
  --job-store /absolute/private-state/jobs.jsonl \
  --event-store /absolute/private-state/events.jsonl \
  --codex-home /absolute/private-codex-home \
  --workspace /absolute/private-workspace \
  --evidence-dir /absolute/new-private-evidence
```

The runner measures files, observes installed CLI help/login, refuses a
pre-existing qualification server name, records `mcp get/list`, executes one
exact eleven-call pipe/PTY turn through the trace proxy, validates Codex JSONL
and MCP responses, removes the server and restores the original configuration
bytes.

## Multi-connection broker boundary

The foundation broker uses a filesystem Unix socket, same-UID `SO_PEERCRED` and
a private random token. It routes direct responses to the request owner and can
broadcast bounded observations. Client disconnect never means automatic
`turn.cancel`, `job.kill` or effect redispatch.

A new bridge/Host process can inspect durable job truth but cannot claim that it
has adopted an old pipe, PTY master or process-group descriptor. Android
abstract-socket/SELinux admission and any future descriptor transfer are
separate W6 gates.

The unversioned `prepare-adb-reverse.sh` was an intermediate source draft. It
must not be referenced by plans, automation or evidence; use the `-v1` tool.

Every utility has a machine status/evidence boundary. A help probe, MCP fixture,
trace, launch prefix, fake provider, reverse mapping or qualified ELF may never
be promoted to a physical-device or release claim without the later acceptance
gates.

## Root Linux supervisor lifecycle

`owner_open_rootlinux_supervisor.py --execute --config /absolute/private/config.json`
starts the manifest-selected mechanical carriers, not semantic commands. The
configuration requires canonical absolute paths, a private state root and
separate inhibit/status/event-log leaves. Any existing emergency marker, even
a dangling symlink, inhibits spawn; unreadable inhibit state fails closed.

Linux `waitid(WNOWAIT)`, default SIGCHLD handling and exclusive reaping of the
supervisor's direct children are required. The leader is retained until TERM,
KILL and bounded original-process-group observations finish. Only then can a
critical carrier be replaced or a noncritical carrier forgotten. An unconfirmed
cleanup leaves the supervisor failed rather than authorizing a replacement.

Status records are observations of the original group, not a proof about
processes escaping via setsid/setpgid. The installed cgroup/namespace and init
must enforce and demonstrate whole-service cleanup, including supervisor death;
this remains an external L2 gate. Follow
[`MOD-ROOTLINUX`](../../docs/modules/MOD-ROOTLINUX.md) for the barrier, limits,
status fields and operator obligations. Source-only reproduction:

```sh
python3 -m unittest tools.tests.test_owner_open_rootlinux_supervisor -v
```

### State storage and single-writer admission

Before any carrier starts, the supervisor owns an exclusive advisory lock on the
private state-root directory and has pinned all state/output/inhibit parents
without following symlinks. The installer must provision stable, private,
owner-controlled directories; existing permissive parents are rejected, not
silently repaired. A second cooperating supervisor must not use the same root.
This lock is not cgroup containment or a supervisor-crash recovery proof.

Event writes complete partial writes, synchronize file and directory, and fence
this instance after I/O/integrity failure. A torn newline tail blocks startup
without automatic repair. Status writes complete a fresh temporary file, fsync,
replace within the pinned parent, and fsync the directory; a post-rename fsync
failure remains durability-unknown even if new status is readable. Handled
pre-rename failures remove the attempt's temporary file. Settled leaders are all
reaped before cleanup events are emitted, so log failure cannot abandon reaping.

The existing supervisor test command above runs the state-I/O failure matrix,
real competing-process lock test and bounded local lifecycle tests together.
Local injected errors and ordinary fsync success do not close installed L2,
physical L4 or destructive L5 gaps. Consult `MOD-ROOTLINUX` sections 10 and 13 for
exact write boundaries, compatibility changes and offline migration procedure.

### Crash-session reconciliation fence

A private `.supervisor-session.json` is synchronized before the first carrier.
Any retained marker from an earlier process blocks startup before status/event
mutation, even when the advisory directory lock is now available. PIDs and age
are diagnostic only: no implicit kill, adoption, marker deletion or effect replay
is permitted. Normal and handled emergency stops clear only their own marker,
after original-group cleanup and durable terminal observations. Failed runs,
including exhausted restart budgets, retain the fence. The independent owner
inhibit is never removed by the supervisor.

This intentionally changes restart behavior: init must remain inhibited after an
unclean session until an independent operator verifies whole-service cleanup,
preserves state and authorizes offline reconciliation. Do not delete the marker
in an init pre-start hook. The marker does not clean up escaped descendants or
qualify installed behavior; see `MOD-ROOTLINUX` for release ordering, failure
classification and migration requirements. The existing supervisor suite also
covers real SIGKILL/orphan/restart behavior using test-only subreaping.

## Broker connection-resource ownership

`owner_open_broker_connections.py` is a required broker runtime dependency, not
a test-only helper. Include it beside the existing broker Python modules when
assembling an installed payload, and bind its exact bytes in that payload's
manifest. `--max-clients` now includes silent pre-authentication sockets and
teardown. Capacity is released only after the reader and optional writer have
terminated; an over-limit socket is closed before worker creation. The hello
receive deadline is five seconds from reservation and is not renewed by input.
The detailed API, worker/descriptor accounting, interrupted-start behavior and
shutdown contract are in `docs/modules/MOD-BROKER.md`.

Run `python3 -m unittest tools.tests.test_owner_open_broker_connections -v` from
the repository root. These unit/socket/subprocess regressions are source
evidence only; installed limits, scheduling, descriptor behavior and recovery
still need the level-correct evidence for `GAP-CONC-BROKER-MUX-001`.
