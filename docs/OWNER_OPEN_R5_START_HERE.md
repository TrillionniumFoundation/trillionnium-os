# Owner-open R5: start here

R3 remains the semantic contract. R5 is the active implementation and evidence
sequence.

Read in this order:

1. `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`
2. `TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`
3. `status/owner-open-r5-status.json`
4. `status/owner-open-r5-traceability.tsv`
5. `contracts/owner-open-forbidden-default-graph-v2.json`
6. `protocols/owner-open-inspect-v1.md`
7. `protocols/owner-open-stream-flow-v1.md`

## Selected source path

```text
client/AiShell
  -> v5 transport carrier
       - exact transport sequence
       - bounded high-volume byte window
       - pause/resume and resync-required
       - separate transport delivery journal
  -> v4 execution core
       - provider JSONL same-turn loop
       - direct shell / ordinary adb process runtime
       - active turn.cancel / tool.cancel
       - persist-before-delivery event store
       - turn.inspect / call.inspect
```

The carrier defaults to pass-through. Flow control activates only through
explicit `stream.window_update`, `stream.pause` or `stream.resume`, and only
when the core reports an available durable event store.

High-volume model/output frames consume credit. Cancellation, inspection,
lifecycle and terminal frames bypass the byte gate. If the finite queue cannot
retain another delivery copy, the carrier emits a durable-cursor-bound
`stream.resync_required`; it never redispatches the provider or tool effect.

## Exact verification commands

```sh
python3 tools/verify-owner-open-r5.py --json
python3 -m unittest tools.tests.test_verify_owner_open_r5 -v
cargo generate-lockfile
cargo fmt --all -- --check
cargo test --locked --all-targets --package trillionnium-owner-open-stream-window
cargo test --locked --all-targets --package trillionnium-owner-open-host
cargo clippy --locked --all-targets --package trillionnium-owner-open-stream-window -- -D warnings
cargo clippy --locked --all-targets --package trillionnium-owner-open-host -- -D warnings
```

Until those commands execute against one exact commit, the claim ceiling remains
`SOURCE_IMPLEMENTED / L0`.

## Next gate

After runner closeout:

1. durable long-running jobs and attach/write/resize/close-stdin/kill;
2. multi-connection ownership and cross-connection controls;
3. installed Codex probe and native provider binding;
4. physical ADB topology;
5. Android owner-open product split and L3-L5 qualification.
