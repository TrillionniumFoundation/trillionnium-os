# 2026-08-27 owner-open process substrate source record

Evidence level: **L1 source-authored, validation pending**  
Branch: `codex/owner-open-r4-foundation-20260827`  
Plan: `docs/TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md`  
Implementation: `crates/trillionnium-owner-open-runtime`

## Scope

This record covers the first isolated r4 W2/W3 process slice:

- first-class shell command strings;
- exact shell argv;
- cwd/environment/stdin mechanics;
- raw stdout/stderr events;
- process-group timeout and cancellation;
- output-exhaustion termination;
- exact ordinary-adb argv without wrapper injection;
- source tests for normal, failure and fault paths.

It does not cover a live Codex provider, owner-open Host integration, Root Linux
placement, an Android image, real ADB transport, durable replay or a physical
device effect.

## Source set

| Path | Purpose |
| --- | --- |
| `crates/trillionnium-owner-open-runtime/Cargo.toml` | Isolated no-default-feature runtime package |
| `crates/trillionnium-owner-open-runtime/src/lib.rs` | Process/event/lifecycle implementation |
| `crates/trillionnium-owner-open-runtime/tests/runtime.rs` | Normal, negative and fault tests |
| `crates/trillionnium-owner-open-runtime/README.md` | Boundary and non-claims |
| `docs/implementation/owner-open-process-substrate-v1.md` | Implementable semantics and next integration gates |
| `docs/status/owner-open-r4-w2-w3-source-slice.json` | Machine status and claim ceiling |
| `docs/status/owner-open-r4-w2-w3-traceability.tsv` | Requirement/source/test mapping |

## Static design review

The source is intended to establish these facts:

1. No dependency on `trillionnium-os-types`, the old direct-effect model,
   capability lease, privilege broker, risk guard, P01 custody or
   `trillionnium-shell-exec` exists.
2. Shell command content is never parsed for safety/risk semantics.
3. Shell argv has no absolute-path, standard-profile, command-string or
   executable allowlist inherited from `shell.exec.v1`.
4. ADB argv is passed directly to the configured executable and no serial,
   target, host, port or privilege argument is added.
5. Target labels are retained only on events.
6. Validation happens before `accepted`; spawn failure has no `started` event.
7. The supervisor creates a process group and signals the group for timeout,
   cancellation and output exhaustion.
8. Output events carry `Vec<u8>` and therefore do not require valid UTF-8.
9. Every source test asserts one terminal event; cancellation asserts one spawn.
10. The machine status leaves all Host/Root Linux/Android/device/release claims
    false.

## Authored test matrix

| Test | Intended proof |
| --- | --- |
| `command_string_streams_raw_stdout_stderr_and_preserves_failure` | Binary output, split streams, non-zero exit and one terminal |
| `argv_is_element_preserving_and_does_not_expand_shell_text` | Exact argument boundaries |
| `cwd_environment_delta_and_stdin_are_mechanical_inputs` | cwd, env set/remove and binary stdin |
| `timeout_terminates_the_process_group_and_emits_one_terminal_event` | Monotonic timeout and bounded cleanup |
| `cancellation_terminates_the_process_group_without_redispatch` | One spawn, cancellation and no duplicate dispatch |
| `output_exhaustion_is_mechanical_and_returns_truncated_observation` | Exact delivered cap and resource terminal |
| `adb_exec_passes_unknown_future_argv_without_target_or_serial_injection` | Unknown adb subcommand transparency |
| `spawn_failure_is_an_honest_terminal_observation` | Accepted/no-started/spawn-failed sequence |
| `malformed_adb_request_is_rejected_before_any_process_event` | Empty argv proves no spawn attempt |

## Required executable validation

The source must not be promoted beyond this record until the exact branch SHA
passes:

```sh
cargo fmt --all -- --check
cargo test --package trillionnium-owner-open-runtime
cargo tree -e features -p trillionnium-owner-open-runtime
python3 tools/verify-owner-open-foundation.py
```

The expected Cargo feature tree is limited to the runtime package plus `libc`,
`thiserror` and test-only `tempfile` dependencies. Any old Trillionnium
Authority/broker/runtime package in that tree is a failure.

## Current validation hold

The GitHub Actions job observed for the r4 branch was allocated no runner
(`runner_id=0`) and executed no steps. Consequently this record does not claim a
Rust compile, test pass or generated lock update. The workflow remains checked
in as a future reproducible gate, but absence of a runner is not treated as a
successful result.

## Review items before Host integration

- compile under Rust 1.93 and resolve all formatting/type errors;
- verify timeout/cancel tests are stable under load;
- verify process-group cleanup with a command that forks a descendant;
- add a bounded event-to-wire binary codec in the Host;
- add a per-call Host registry and duplicate-call conflict test;
- decide whether stdin writer errors are terminal or auxiliary observation in
  the final protocol mapping;
- add a cgroup/PID namespace closeout test before Android integration;
- create the ADB topology ADR before claiming W3 beyond the fake executable.

## Claim boundary

The accurate statement for this record is:

> A mechanism-only owner-open shell/ordinary-adb process substrate and its
> source tests have been authored in an isolated crate. Compilation, Host/Codex
> integration, Root Linux/Android inclusion, real ADB and device effects remain
> unproven.
