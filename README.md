# Trillionnium OS

Trillionnium is an AI Agent Native Android OS. Codex is the single semantic
Agent. The owner-open substrate supplies provider lifecycle, direct shell,
ordinary raw ADB, event transport, storage, connection delivery, watchdog and
recovery mechanics; it does not add a second planner, risk engine or approval
authority.

```text
AiShell / owner client / Codex MCP
  -> optional owner-open multi-connection broker
  -> selected v5 bounded transport carrier
  -> job-aware v7 execution core
  -> one Codex/provider turn or direct shell.job lifecycle
  -> shell.exec / adb.exec / shell.job
  -> raw observation
  -> the same provider turn or an attached owner client
```

## Current authority

- [R3 semantic contract](docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
- [Active R5 implementation plan](docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md)
- [Durable jobs checkpoint](docs/plan/owner-open-r5-batch-d-jobs.md)
- [Codex MCP binding checkpoint](docs/plan/owner-open-r5-batch-d-codex-mcp-job-binding.md)
- [Connection and installed-Codex checkpoint](docs/plan/owner-open-r5-batch-d-connection-and-installed-codex.md)
- [Machine status](docs/status/owner-open-r5-status.json)
- [Traceability](docs/status/owner-open-r5-traceability.tsv)
- [Start page](docs/OWNER_OPEN_R5_START_HERE.md)

R3 governs product semantics. R5 governs implementation order, evidence
promotion and completion. This branch is an owner-open development lane, not a
public release.

## Current selected source state

Source-authored and selected or directly bound to the owner-open closure:

- strict owner-open frame/tool codecs;
- direct command-string and argv shell execution;
- ordinary configured ADB argv without serial/host/port injection;
- process groups, timeout, cancellation, output bounds and descendant cleanup;
- scoped call identity, at-most-one spawn and truthful uncertainty states;
- same-turn streaming provider/tool callback;
- external provider JSONL duplex and provider cancellation;
- v5 transport delivery with bounded window, pause/resume and durable resync;
- selected job-aware v7 execution core beneath the transport carrier;
- append-only durable turn and job observations with conservative recovery;
- read-only `turn.inspect`, `call.inspect` and `job.inspect` paths;
- direct long-running pipe/PTY jobs with attach, write, resize, close-stdin,
  process-group kill and operation-level idempotency;
- completed-job replay without child/provider redispatch;
- local STDIO MCP server exposing job start, inspect, attach, detach, write,
  resize, close-stdin, kill and bounded wait to Codex;
- connection-bound live controls through `bridge_instance_id` and read-only
  durable inspection from later connections;
- filesystem Unix multi-connection broker foundation with strict peer/token
  admission, request-owner response routing and bounded observation broadcast;
- exact-byte MCP trace proxy with finite process-group teardown;
- explicit installed-Codex MCP qualification runner with temporary registration,
  exact eleven-call validation, cleanup and config restoration;
- exact negative Cargo/Host graph contracts and candidate CI commands.

Explicitly not claimed:

- Rust 1.93 formatting, compilation, tests or clippy for the current head;
- a reviewed current `Cargo.lock`, Cargo metadata or feature tree;
- a runner-backed exact-checkout Python pass for the current head;
- a live installed Codex MCP `shell.job` qualification result;
- cross-Host live file-descriptor adoption;
- real ARM64 ADB or a deployed byte-transparent relay;
- a clean Android owner-open image or physical shell/job/ADB effect;
- crash, ENOSPC, reboot or power-loss qualification;
- public release.

A GitHub workflow result with `runner_id=0`, `steps=[]` and no logs remains an
infrastructure no-execution result, not source pass/fail evidence.

## Source gates

```sh
python3 tools/generate-owner-open-types.py --check
python3 tools/verify-owner-open-r5.py --json
python3 -m unittest tools.tests.test_verify_owner_open_r5 -v
PYTHONWARNINGS=error::ResourceWarning \
  python3 -m unittest tools.tests.test_codex_owner_open_mcp -v
PYTHONWARNINGS=error::ResourceWarning \
  python3 -m unittest tools.tests.test_codex_mcp_qualification_lifecycle -v
PYTHONWARNINGS=error::ResourceWarning \
  python3 -m unittest discover -s tools/tests -p 'test_*broker*.py' -v

cargo generate-lockfile
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Only exact output bound to one commit can raise a capability above L0 source
evidence.

## Owner-open dogfood completion boundary

Dogfood completes only when one bound evidence package proves:

1. Android starts one owner-open Host and no forbidden legacy semantic node;
2. one physical Codex turn invokes Root Linux shell and ordinary raw ADB;
3. Codex loads the local MCP server and starts, controls and observes a
   long-running pipe and PTY job in that same turn;
4. duplicate calls and job operations do not spawn or mutate twice;
5. uncertain effects are not blindly redispatched;
6. inspect/reconnect/cancel and provider/Host/broker/MCP-client failure produce
   truthful state;
7. emergency stop works without provider availability;
8. Codex can build, install, inspect and recover the dogfood userland; and
9. evidence binds exact source, Android manifest/patches, Cargo/Soong graphs,
   rootfs, provider runtime, target files and device.

Signing, AVB/rollback, OTA, multi-user isolation and public-release security are
separate L6 properties.
