# Owner-open R5: start here

R3 remains the semantic contract. R5 is the active implementation and evidence
sequence.

Read in this order:

1. `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`
2. `TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`
3. `plan/owner-open-r5-batch-d-jobs.md`
4. `plan/owner-open-r5-batch-d-codex-mcp-job-binding.md`
5. `status/owner-open-r5-status.json`
6. `status/owner-open-r5-traceability.tsv`
7. `contracts/owner-open-forbidden-default-graph-v2.json`
8. `protocols/owner-open-inspect-v1.md`
9. `protocols/owner-open-stream-flow-v1.md`
10. `protocols/owner-open-jobs-v1.md`
11. `protocols/owner-open-codex-mcp-jobs-v1.md`

## Selected source path

```text
client/AiShell
  -> v5 transport carrier
       - exact transport sequence
       - bounded high-volume byte window
       - pause/resume and resync-required
       - separate transport delivery journal
  -> job-aware v7 execution core
       - provider JSONL same-turn loop
       - direct shell / ordinary adb process runtime
       - durable shell.job pipe and PTY lifecycle
       - job.inspect / attach / write / resize / close-stdin / kill
       - active turn.cancel / tool.cancel
       - persist-before-delivery turn and job stores
       - turn.inspect / call.inspect

Codex-native local path
  -> STDIO MCP JSON-RPC
  -> tools/owner-open/codex_owner_open_mcp.py
  -> the same v5 transport and v7 core
```

The carrier defaults to pass-through. Flow control activates only through
explicit `stream.window_update`, `stream.pause` or `stream.resume`, and only
when the core reports an available durable event store.

High-volume model/output frames consume credit. Cancellation, inspection,
lifecycle and terminal frames bypass the byte gate. If the finite queue cannot
retain another delivery copy, the carrier emits a durable-cursor-bound
`stream.resync_required`; it never redispatches the provider, tool or job
effect.

Long-running jobs are direct mechanical primitives. Exact operation IDs are
bound before start/write/resize/close/kill effects, completed jobs replay
without a second child process, and incomplete restart state remains
inspectable or unknown rather than automatically redispatched.

The local MCP server exposes job start, inspect, attach, detach, write, resize,
close-stdin, kill and bounded wait. It allocates correlation mechanically,
preserves exact bytes and never adds an approval layer or hidden effect retry.

## Exact verification commands

```sh
python3 tools/verify-owner-open-r5.py --json
python3 -m unittest tools.tests.test_verify_owner_open_r5 -v
PYTHONWARNINGS=error::ResourceWarning \
  python3 -m unittest tools.tests.test_codex_owner_open_mcp -v
cargo generate-lockfile
cargo fmt --all -- --check
cargo test --locked --all-targets --package trillionnium-owner-open-job-registry
cargo test --locked --all-targets --package trillionnium-owner-open-job-runtime
cargo test --locked --all-targets --package trillionnium-owner-open-stream-window
cargo test --locked --all-targets --package trillionnium-owner-open-host
cargo clippy --locked --all-targets --package trillionnium-owner-open-job-registry -- -D warnings
cargo clippy --locked --all-targets --package trillionnium-owner-open-job-runtime -- -D warnings
cargo clippy --locked --all-targets --package trillionnium-owner-open-stream-window -- -D warnings
cargo clippy --locked --all-targets --package trillionnium-owner-open-host -- -D warnings
```

Until those commands execute against one exact commit, the claim ceiling remains
`SOURCE_IMPLEMENTED / L0`.

## Next gate

1. obtain a runner that executes the exact Python and Rust command closure;
2. run the installed target Root Linux Codex help probe;
3. register `codex_owner_open_mcp.py` as a local STDIO MCP server;
4. prove one installed Codex turn controls a pipe and PTY job through native
   MCP calls;
5. define cross-Host live attachment and multi-connection ownership;
6. implement the physical ADB topology;
7. cut the Android owner-open product split and collect L3-L5 evidence.
