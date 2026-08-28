# Trillionnium OS

Trillionnium is an AI Agent Native Android OS. Codex is the single semantic
Agent. The owner-open substrate supplies provider lifecycle, direct shell,
ordinary raw ADB, event transport, storage, watchdog and recovery mechanics; it
does not add a second planner, risk engine or approval authority.

```text
AiShell / owner client
  -> owner-open Direct Agent Host
  -> one Codex/provider turn
  -> shell.exec / adb.exec
  -> raw observation
  -> the same provider turn
```

## Current authority

- [R3 semantic contract](docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
- [Active R5 implementation plan](docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md)
- [Current Batch D checkpoint](docs/plan/owner-open-r5-batch-d-inspection-flow-control.md)
- [Machine status](docs/status/owner-open-r5-status.json)
- [Traceability](docs/status/owner-open-r5-traceability.tsv)
- [Start page](docs/OWNER_OPEN_R5_START_HERE.md)

R3 governs product semantics. R5 governs implementation order, evidence
promotion and completion. This branch is an owner-open development lane, not a
public release.

## Current source state

Source-authored now:

- strict owner-open frame/tool codecs;
- direct command-string and argv shell execution;
- ordinary configured ADB argv without serial/host/port injection;
- process groups, timeout, cancellation, output bounds and descendant cleanup;
- scoped call identity, at-most-one spawn and truthful uncertainty states;
- same-turn streaming provider/tool callback;
- external provider JSONL duplex and provider cancellation;
- selected Host v4 with active `turn.cancel` and targeted `tool.cancel`;
- per-event durable append, detached client delivery, completed replay and
  conservative incomplete recovery;
- read-only wire `turn.inspect` and `call.inspect`, with live-registry and
  durable-frame paths and no automatic redispatch;
- isolated bounded stream-window state for byte credit, pause, resume, close
  and exact control sequencing;
- exact negative Cargo/Host graph contracts and candidate CI commands.

Explicitly not claimed:

- Rust 1.93 formatting, compilation, tests or clippy for the current head;
- a reviewed current `Cargo.lock`;
- Host-integrated stream credit/pause/resume;
- a live installed Codex turn;
- real ARM64 ADB or a deployed transparent relay;
- a clean Android owner-open image or physical shell/ADB effect;
- crash, ENOSPC, reboot or power-loss qualification;
- public release.

The latest observed Actions jobs ended without assigned steps or logs. That is
an infrastructure failure, not evidence that the Rust source passed or failed.

## Source gates

```sh
python3 tools/generate-owner-open-types.py --check
python3 tools/verify-owner-open-r5.py --json
python3 -m unittest tools.tests.test_verify_owner_open_r5 -v

cargo generate-lockfile
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

Only exact output bound to the commit can raise a capability above L0 source
evidence.

## Owner-open dogfood completion boundary

Dogfood completes only when one bound evidence package proves:

1. Android starts one owner-open Host and no forbidden legacy semantic node;
2. one physical Codex turn invokes Root Linux shell and ordinary raw ADB;
3. raw observations return to that same turn and Codex continues;
4. duplicate calls do not spawn twice and uncertain effects are not blindly
   redispatched;
5. inspect/reconnect/cancel and provider/Host/client failure produce truthful
   state;
6. emergency stop works without provider availability;
7. Codex can build, install, inspect and recover the dogfood userland; and
8. evidence binds exact source, Android manifest/patches, Cargo/Soong graphs,
   rootfs, provider runtime, target files and device.

Signing, AVB/rollback, OTA, multi-user isolation and public-release security are
separate L6 properties.
