# Owner-open R5: start here

R5 is the active implementation sequencing and closeout layer for
Trillionnium OS. Read the documents in this order:

1. `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md` — R3 semantic decisions.
2. `TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md` — current implementation
   order and acceptance gates.
3. `status/owner-open-r5-status.json` — machine-readable claim ceiling.
4. `status/owner-open-r5-traceability.tsv` — requirement/source/test/evidence
   mapping.
5. `contracts/owner-open-forbidden-default-graph-v2.json` — exact source and
   Host-binary graph.
6. `implementation/owner-open-same-turn-loop-v1.md` — W1 callback loop.
7. `implementation/owner-open-provider-jsonl-v1.md` — external provider adapter.
8. `protocols/owner-open-event-store-v1.md` — durable observation log boundary.
9. `security/owner-open-threat-model.md` — accepted risk and required mechanics.

## Current implemented source path

```text
turn.start
  -> selected R5 streaming Host
  -> external provider JSONL process
  -> provider model/tool events
  -> call registry + direct shell/ordinary adb runtime
  -> runtime accepted/started/output/terminal events
  -> synchronous Host event sink
  -> per-event durable append + immediate delivery attempt
  -> same provider turn continuation
  -> one turn terminal
```

With `--event-store /absolute/path/events.jsonl`:

- provider and tool events are appended while the provider/tool is still
  active, rather than after a complete turn has been collected;
- a completed durable turn replays without starting the provider or tool again;
- an incomplete durable turn is reconciled to `unknown_after_disconnect` and
  is never automatically redispatched;
- losing the client output path detaches delivery but does not cancel an
  already accepted turn;
- event-store failure is reported as unavailable/unreplayable and does not
  become semantic denial.

The turn loop also has a cross-thread cancellation token. It reaches an active
call through the scoped call registry and process group, and the provider JSONL
adapter sends a correlated `turn.cancel`. The current stdio carrier still
blocks on the provider thread and therefore cannot read a client `turn.cancel`
frame during the active turn. That carrier limitation remains the next source
gate.

This remains source-level until the exact Rust commands execute successfully.
The observed GitHub Actions runs have reported failure with no assigned runner
steps or logs, so they are not treated as source failures or passes.

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
2. replace the blocking stdio carrier with an active-turn control loop;
3. keep correlated `turn.cancel` and targeted `tool.cancel` serviceable while
   provider/tools run;
4. add inclusive replay cursors and inspect/attach APIs;
5. add bounded window/pause/resume behavior;
6. bind the installed Codex provider;
7. implement the real ADB topology; and
8. cut the Android owner-open product graph.

## Do not claim yet

Do not describe this branch as having successful Rust validation, a live
installed Codex turn, carrier-serviceable asynchronous cancellation, physical
Root Linux shell, physical ADB effect, clean Android image,
Host-crash/ENOSPC/reboot/power-loss qualification or public release. Those
promotions require the evidence levels defined by R5.
