# Trillionnium OS

Trillionnium is an AI Agent Native Android OS. Codex is the single built-in
semantic Agent. The OS supplies an owner-open mechanism substrate for provider
lifecycle, direct shell, ordinary raw ADB, event transport, storage, watchdog
and recovery; it does not insert a second semantic planner, risk engine or
approval authority.

```text
AiShell / owner client
  -> owner-open Direct Agent Host
  -> one Codex/provider turn
  -> shell.exec / adb.exec
  -> raw process or transport observation
  -> the same provider turn
```

Root Linux is the Android-managed headless execution environment for Codex and
its tools. Inference remains off-device. WindowsCompat and historical local
model/desktop paths are not current product capabilities.

## Current authority

- **R3 semantic contract:**
  [`docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
- **R5 implementation and closeout plan — active:**
  [`docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`](docs/TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md)
- **R5 machine status:**
  [`docs/status/owner-open-r5-status.json`](docs/status/owner-open-r5-status.json)
- **R5 traceability:**
  [`docs/status/owner-open-r5-traceability.tsv`](docs/status/owner-open-r5-traceability.tsv)
- **R5 start page:**
  [`docs/OWNER_OPEN_R5_START_HERE.md`](docs/OWNER_OPEN_R5_START_HERE.md)

R4 remains retained as the previous execution plan and source foundation. R5
supersedes R4 for what is built next and what counts as complete; R3 continues
to govern product semantics.

## Current source state

The branch is an owner-open source development lane, not a public release.

Implemented at source level:

- strict owner-open frame and tool codecs;
- direct command-string shell and element-preserving argv runtime;
- ordinary configured ADB argv without injected serial/host/port;
- process groups, cancellation, timeout and output bounds;
- concurrent scoped call registry and registry-to-runtime failure closure;
- R5 same-turn callback loop in which a provider receives a tool observation
  and may continue before producing one turn terminal;
- bounded external provider JSONL process adapter;
- executable stdio R5 Host mapping provider/tool observations to Host frames;
- append-only event store with strict reopen and scoped event identity;
- optional Host `--event-store` path, stable turn identity, completed-turn
  replay without provider/tool respawn, and incomplete-turn reconciliation to
  `unknown_after_disconnect` without automatic redispatch;
- exact negative source-graph contracts and Python verifier tests.

Not yet claimed:

- successful Rust formatting, compilation, tests or clippy for the latest R5
  commit—the observed Actions runs had no runner steps or logs;
- reviewed Cargo lock refresh from the current source closure;
- live installed Codex provider events;
- streaming persistence while a provider/tool is still active;
- asynchronous turn/tool cancellation, flow control or resume;
- real ARM64 ADB or transparent relay;
- Android owner-open product graph, image or physical effect;
- Host-crash, ENOSPC, reboot or power-loss qualification;
- signed public release.

The checked-in Android audit overlay still contains the pre-R3
Authority/Capability Lease/P01/old shell-broker product graph. It is audit
material and an explicit W6 hold, not the owner-open product closure.

## R5 source checks

```sh
python3 -m json.tool docs/contracts/owner-open-forbidden-default-graph-v2.json >/dev/null
python3 -m json.tool docs/status/owner-open-r5-status.json >/dev/null
python3 tools/verify-owner-open-r5.py --json
python3 -m unittest tools.tests.test_verify_owner_open_r5 -v

cargo generate-lockfile
cargo fmt --all -- --check
cargo test --all-targets --package trillionnium-owner-open-types
cargo test --all-targets --package trillionnium-owner-open-runtime
cargo test --all-targets --package trillionnium-owner-open-call-registry
cargo test --all-targets --package trillionnium-owner-open-event-store
cargo test --all-targets --package trillionnium-owner-open-tool-bridge
cargo test --all-targets --package trillionnium-owner-open-turn-loop
cargo test --all-targets --package trillionnium-owner-open-provider-jsonl
cargo test --all-targets --package trillionnium-owner-open-host
cargo clippy --all-targets -- -D warnings
```

Only exact command output bound to the commit may promote the machine status.
Source presence alone remains L0.

## Owner-open dogfood completion boundary

Dogfood is complete only when one bound evidence package proves:

1. Android starts one owner-open Host and no forbidden legacy semantic node;
2. one physical Codex turn invokes Root Linux shell and ordinary raw ADB;
3. raw tool events return to that same turn and Codex continues;
4. duplicate local calls do not spawn twice and uncertain effects are not
   blindly re-dispatched;
5. client/provider/Host failure, USB loss and reboot produce inspectable truth;
6. out-of-band emergency stop works without provider availability;
7. Codex can build, install, inspect and recover the dogfood userland; and
8. evidence binds exact control-plane source, Android manifest/patches, Cargo
   graph, Soong graph, rootfs, provider runtime, target files and device.

Public signing, AVB/rollback, OTA, multi-user isolation and release security
review are separate L6 properties and do not block owner-open development.
