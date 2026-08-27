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
6. `implementation/owner-open-same-turn-loop-v1.md` — current W1 source slice.
7. `security/owner-open-threat-model.md` — accepted risk and required mechanics.

## Current development command sequence

```sh
python3 tools/verify-owner-open-r5.py --json
python3 -m unittest tools.tests.test_verify_owner_open_r5 -v
cargo generate-lockfile
cargo fmt --all -- --check
cargo test --package trillionnium-owner-open-turn-loop
cargo test --package trillionnium-owner-open-tool-bridge
cargo test --package trillionnium-owner-open-runtime
cargo clippy --all-targets -- -D warnings
```

After the exact commit passes, the next code change imports the same-turn loop
behind the executable Host provider boundary and adds a fake external provider
JSONL process. A live Codex adapter follows only after the fake process closes
streaming, cancellation, duplicate-call and failure-ordering tests.

## Do not claim yet

Do not describe this branch as having a live integrated Codex turn, physical
Root Linux shell, physical ADB effect, clean Android image, durable restart
replay, reboot/power-loss qualification or public release. Those promotions
require the evidence levels defined by R5.
