# Owner-open R5: start here

Read in this order:

1. `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md` — R3 product semantics.
2. `TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md` — active implementation and
   evidence gates.
3. `plan/owner-open-r5-batch-d-inspection-flow-control.md` — current source
   checkpoint.
4. `status/owner-open-r5-status.json` — machine claim ceiling.
5. `status/owner-open-r5-traceability.tsv` — requirement/source/test/evidence
   mapping.
6. `contracts/owner-open-forbidden-default-graph-v2.json` — exact source graph.
7. `protocols/owner-open-inspection-v1.md` — read-only recovery inspection.
8. `protocols/owner-open-stream-flow-control-v1.md` — bounded byte-credit state.
9. `security/owner-open-threat-model.md` — accepted dogfood risk and required
   mechanical isolation.

## Current source path

```text
turn.start
  -> selected R5 Host v4
  -> external provider JSONL
  -> direct shell / ordinary adb
  -> per-event durable append and delivery attempt
  -> active turn.cancel / tool.cancel

read-only controls:
  turn.inspect -> durable inclusive turn slice
  call.inspect -> live registry or durable call-correlated frames
```

Inspection does not start providers or tools and does not mutate the event
store. The stream-window crate is in the exact source closure but is not yet
wired into Host delivery.

## Current command gate

```sh
python3 tools/generate-owner-open-types.py --check
python3 tools/verify-owner-open-r5.py --json
python3 -m unittest tools.tests.test_verify_owner_open_r5 -v
cargo generate-lockfile
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

## Immediate next gate

1. obtain an executing Rust 1.93 runner and repair every compiler, format, test
   and clippy finding;
2. bind the stream window to actual Host output queues while keeping
   persistence independent of client credit;
3. add durable interactive jobs and attach/write/resize/close-stdin/kill;
4. run the existing Codex probe in the target Root Linux environment and bind
   the observed native provider interface;
5. implement the real ADB topology;
6. cut the Android owner-open product graph.

Do not claim Rust/Host success, Host-integrated flow control, live Codex, real
ADB, Android inclusion, physical effects, fault qualification or public release
until exact evidence exists.
