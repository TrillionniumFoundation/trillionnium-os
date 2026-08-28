# Owner-open R5: start here

R3 remains the semantic contract. R5 is the active implementation and evidence
sequence. The exact repository-internal source closure is now
`HOST_TESTED / L1`; installed Codex, Android image, physical device and release
qualification remain open and must not be inferred from source tests.

Read in this order:

1. `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`
2. `TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`
3. `evidence/2026-08-28-owner-open-r5-exact-source-closeout.md`
4. `plan/owner-open-r5-batch-d-jobs.md`
5. `plan/owner-open-r5-batch-d-codex-mcp-job-binding.md`
6. `plan/owner-open-r5-batch-d-connection-and-installed-codex.md`
7. `status/owner-open-r5-status.json`
8. `status/owner-open-r5-traceability.tsv`
9. `contracts/owner-open-forbidden-default-graph-v2.json`
10. `protocols/owner-open-inspect-v1.md`
11. `protocols/owner-open-stream-flow-v1.md`
12. `protocols/owner-open-jobs-v1.md`
13. `protocols/owner-open-codex-mcp-jobs-v1.md`
14. `protocols/owner-open-multi-connection-broker-v1.md`
15. `protocols/owner-open-installed-codex-mcp-qualification-v1.md`

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
       - job.inspect / attach / detach / write / resize / close-stdin / kill / wait
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
child process, configured journal failure is fail-closed, and incomplete restart
state remains inspectable or unknown rather than automatically redispatched.

The local MCP server exposes connection identity plus job start, inspect,
attach, detach, write, resize, close-stdin, kill and bounded wait. A live or
mutating job call must carry the current bridge identity. A later process can
inspect durable truth but cannot claim old live file descriptors.

## Exact L1 source evidence

The source candidate
`fa1d287103c46aff35cf5e95addbc18da8a92063` passed the strict v15 closeout in
GitHub Actions run `33186972324`:

```sh
python3 tools/generate-owner-open-types.py --check
python3 tools/verify-owner-open-r5.py --json
python3 -m unittest tools.tests.test_verify_owner_open_r5 -v
PYTHONWARNINGS=error::ResourceWarning \
  python3 -m unittest discover -s tools/tests -p 'test_*.py' -v
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo metadata --locked --format-version 1
cargo tree --locked -e features
```

Observed result:

- exact sorted 31-file candidate boundary;
- 680 Python tests passed, with five explicit external-material skips;
- complete Rust default all-target test closure passed;
- complete Rust default all-target Clippy closure passed with warnings denied;
- generated source and R5 graph gates passed;
- locked metadata, feature tree, patch and evidence hashes captured;
- automatic redispatch remained false.

Claim ceiling:

```text
EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX
```

## Next gate

1. run the target Root Linux installed-Codex help/version probe and bind the
   executable path, digest and exact capability bytes;
2. execute `qualify_codex_mcp_jobs.py --execute` against that installed CLI and
   review the exact MCP trace;
3. prove one installed Codex turn controls pipe and PTY jobs, survives
   disconnect/reconnect and never hides an effect retry;
4. select and execute the physical ADB topology with USB/offline/unauthorized,
   recovery and reboot evidence;
5. remove forbidden legacy nodes from the Android owner-open product graph;
6. wire init, SELinux, abstract socket, Root Linux and AiShell, then build clean
   target files;
7. collect L3–L5 evidence and keep public release false until a separate signed
   L6 profile passes.

Missing installed binaries, credentials, Android build outputs or physical
devices are evidence holds, not permission to synthesize a pass.
