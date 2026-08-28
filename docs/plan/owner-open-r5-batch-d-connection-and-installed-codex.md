# R5 Batch D checkpoint — connection ownership and installed Codex

Status: **source implementation landed; exact runner and target qualification remain open**

## Completed source slice

This checkpoint closes two source-level ambiguities left after durable jobs and
the initial Codex MCP bridge:

1. live job controls now bind to one `bridge_instance_id` rather than an
   implicit process assumption;
2. a strict multi-connection broker foundation defines peer/token admission,
   request-owner response routing, observation broadcast and disconnect truth;
3. a bounded exact-byte MCP STDIO trace proxy records the native Codex exchange;
4. an explicit qualification runner measures installed artifacts, temporarily
   registers the MCP server, executes one exact job sequence, validates Codex
   JSONL and MCP JSON-RPC, and restores configuration;
5. upstream EOF, command timeout and ignored downstream EOF receive finite
   process-group TERM/KILL/reap handling;
6. CI candidate commands include broker, MCP and qualification lifecycle tests.

## Source path

```text
Codex
  -> exact-byte trace proxy
  -> owner-open MCP job bridge
  -> optional multi-connection broker foundation
  -> selected v5 transport Host
  -> job-aware v7 execution core
  -> durable pipe / PTY job runtime
```

Codex remains the only semantic Agent. None of these layers decides whether a
command is desirable or retries an uncertain effect.

## Gate D5 — exact Python and Rust runner

Required on one exact commit:

```text
python compileall for owner-open tools/tests
R5 graph verifier and verifier tests
MCP bridge tests
qualification lifecycle tests
broker process tests
cargo fmt --all -- --check
cargo test --locked --all-targets for every owner-open package
cargo clippy --locked --all-targets -- -D warnings
cargo metadata --locked
cargo tree --locked -e features
```

All fixes and generated lock/graph evidence must be committed before promotion.

## Gate D6 — installed Codex

On the target Root Linux environment:

1. run the read-only installed Codex probe;
2. measure the exact Codex, Python, trace, MCP, Host, core, provider and shell
   files;
3. use a dedicated private `CODEX_HOME` and workspace;
4. execute `qualify_codex_mcp_jobs.py --execute`;
5. review the exact eleven native MCP calls and their responses;
6. confirm the same Codex turn completes with the final marker;
7. confirm the MCP registration is removed and `config.toml` is restored;
8. bind job/event journals and binary hashes to the same evidence package.

## Gate D7 — connection and failure truth

Required cases:

- two admitted clients submit independent read-only requests;
- each direct response returns only to its request owner;
- observation broadcast remains bounded;
- wrong UID or token is rejected before upstream dispatch;
- disconnect does not become turn cancellation or job kill;
- a new bridge can inspect durable job truth but cannot claim old live file
  descriptors;
- downstream MCP ignores EOF and is still reaped within the finite grace;
- qualification timeout removes registration and restores config;
- accepted but uncertain operations are inspected, never blindly retried.

## Critical path after this checkpoint

1. execute and repair the full Python/Rust closure;
2. produce the first installed-Codex L2 evidence package;
3. select and implement the physical ADB topology;
4. split the Android owner-open product graph;
5. integrate init, SELinux, socket admission, Root Linux placement and AiShell;
6. collect L3, L4 and L5 evidence.

No source or host-only result promotes Android, physical-device, fault or
release status by itself.
