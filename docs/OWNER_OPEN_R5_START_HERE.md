# Owner-open R5: start here

R5 is the active implementation sequencing and closeout layer for
Trillionnium OS. Read the documents in this order:

1. `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md` — R3 semantic decisions.
2. `TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md` — current implementation
   order and acceptance gates.
3. `status/owner-open-r5-status.json` — machine-readable claim ceiling.
4. `status/owner-open-r5-traceability.tsv` — requirement/source/test/evidence
   mapping.
5. `contracts/owner-open-forbidden-default-graph-v2.json` — exact source graph.
6. `implementation/owner-open-same-turn-loop-v1.md` — W1 callback loop.
7. `implementation/owner-open-provider-jsonl-v1.md` — external provider adapter.
8. `protocols/owner-open-event-store-v1.md` — durable observation log boundary.
9. `security/owner-open-threat-model.md` — accepted risk and required mechanics.

## Current implemented source path

```text
turn.start
  -> executable R5 Host
  -> external provider JSONL process
  -> provider tool.call
  -> call registry + direct shell/ordinary adb runtime
  -> raw tool.result
  -> same provider turn continuation
  -> Host frames
  -> optional append-only event store
```

With `--event-store /absolute/path/events.jsonl`:

- a completed durable turn replays without starting the provider or tool again;
- an incomplete durable turn is reconciled to `unknown_after_disconnect` and
  is never automatically redispatched;
- event-store failure is reported as unavailable/unreplayable and does not
  become semantic denial.

This remains source-level until the exact Rust commands execute successfully.
The observed GitHub Actions runs currently report failure with no assigned
runner steps or logs, so they are not treated as source failures or passes.

## Current development command sequence

```sh
python3 tools/verify-owner-open-r5.py --json
python3 -m unittest tools.tests.test_verify_owner_open_r5 -v
cargo generate-lockfile
cargo fmt --all -- --check
cargo test --all-targets --package trillionnium-owner-open-event-store
cargo test --all-targets --package trillionnium-owner-open-turn-loop
cargo test --all-targets --package trillionnium-owner-open-provider-jsonl
cargo test --all-targets --package trillionnium-owner-open-host
cargo clippy --all-targets -- -D warnings
```

## Immediate next code gate

1. obtain a runner that actually executes Rust 1.93 commands and fix every
   compile, formatting, test and clippy defect;
2. replace complete-turn in-memory collection with event-by-event persistence;
3. keep `turn.cancel` and `tool.cancel` serviceable while provider/tools run;
4. add inclusive replay cursors and inspect/attach APIs;
5. bind the installed Codex provider;
6. implement the real ADB topology; and
7. cut the Android owner-open product graph.

## Do not claim yet

Do not describe this branch as having a live installed Codex turn, interactive
asynchronous cancellation, physical Root Linux shell, physical ADB effect,
clean Android image, Host-crash/ENOSPC/reboot/power-loss qualification or public
release. Those promotions require the evidence levels defined by R5.
