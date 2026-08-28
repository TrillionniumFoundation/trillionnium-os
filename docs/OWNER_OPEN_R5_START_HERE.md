# Owner-open R5: start here

R3 remains the semantic contract. R5 is the active implementation and evidence
sequence.

Read in this order:

1. `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`
2. `TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`
3. `plan/owner-open-r5-batch-d-jobs.md`
4. `plan/owner-open-r5-batch-d-codex-mcp-job-binding.md`
5. `plan/owner-open-r5-batch-d-connection-and-installed-codex.md`
6. `status/owner-open-r5-status.json`
7. `status/owner-open-r5-traceability.tsv`
8. `contracts/owner-open-forbidden-default-graph-v2.json`
9. `protocols/owner-open-inspect-v1.md`
10. `protocols/owner-open-stream-flow-v1.md`
11. `protocols/owner-open-jobs-v1.md`
12. `protocols/owner-open-codex-mcp-jobs-v1.md`
13. `protocols/owner-open-multi-connection-broker-v1.md`
14. `protocols/owner-open-installed-codex-mcp-qualification-v1.md`

## Selected source path

```text
AiShell / owner clients
  -> optional filesystem Unix multi-connection broker
       - same-UID plus private-token admission
       - request-owner direct responses
       - bounded observation broadcast
       - disconnect is not cancellation
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
  -> exact-byte STDIO trace proxy
  -> Codex MCP job bridge
       - connection_info / bridge_instance_id
       - connection-bound live controls
       - durable read-only inspect/wait from later connections
  -> the same broker/transport/core/job runtime
```

High-volume model/output frames consume bounded delivery credit. Cancellation,
inspection, lifecycle and terminal frames bypass the byte gate. If a finite
queue cannot retain another delivery copy, the carrier emits a durable-cursor
resynchronization requirement; it never redispatches provider, tool or job
effects.

Long-running jobs are direct mechanical primitives. Exact operation IDs bind
start/write/resize/close/kill effects, completed jobs replay without a second
child process, and incomplete restart state remains inspectable or unknown
rather than automatically redispatched.

The local MCP server exposes connection identity plus job start, inspect,
attach, detach, write, resize, close-stdin, kill and bounded wait. A live or
mutating job call must carry the current bridge identity. A later process can
inspect durable truth but cannot claim old live file descriptors.

## Exact verification commands

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

Until those commands execute against one exact commit, the claim ceiling
remains `SOURCE_IMPLEMENTED / L0`.

## Next gate

1. execute the exact Python and Rust 1.93 closure and repair every finding;
2. bind reviewed `Cargo.lock`, metadata, feature trees and raw logs;
3. run the installed target Root Linux Codex help probe;
4. execute `qualify_codex_mcp_jobs.py --execute` and review the exact trace;
5. prove one installed Codex turn controls pipe and PTY jobs without hidden
   retry;
6. implement and qualify the physical ADB topology;
7. cut the Android owner-open product split and collect L3-L5 evidence.
