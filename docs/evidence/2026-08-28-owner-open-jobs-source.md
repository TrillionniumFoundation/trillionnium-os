# Owner-open jobs source checkpoint — 2026-08-28

Evidence level: **L0 source/contract only**  
Branch: `codex/owner-open-r5-tool-loop-20260827`

## Present in source

- mechanism-only scoped job registry;
- at-most-one spawn generation;
- restart uncertainty without automatic redispatch;
- accepted-before-effect operation journal;
- direct pipe and PTY runtime;
- write, resize, close-stdin, kill, inspect, attach and detach source paths;
- parent-death signal, process groups, PTY EOF handling and descendant cleanup;
- job-aware v7 execution core behind the selected v5 transport;
- job-specific delivery stream compatible with v5 window/pause/resume mechanics;
- authored registry, runtime and Host process tests;
- exact Cargo graph and CI package-list updates.

## Validation actually available

An isolated API-compatible workspace was used while authoring the job registry/runtime packages. Its local `cargo check`, package tests and clippy-with-warnings-denied completed successfully against a small event-store API stub. This is useful implementation feedback, but it is not an exact repository checkout and is not promotion evidence.

The exact branch still requires:

```text
python verifier
cargo generate-lockfile
cargo fmt --all -- --check
cargo test --locked --all-targets for the complete R5 closure
cargo clippy --locked --all-targets -- -D warnings
cargo metadata and feature-tree capture
```

## Explicit non-claims

This checkpoint does not claim:

- an exact-checkout Rust pass;
- reviewed lockfile output;
- live Codex `shell.job` use;
- Android image inclusion;
- physical Root Linux placement or PTY operation;
- live reattachment across Host restart;
- Host-crash, reboot, ENOSPC or power-loss conformance;
- public-release readiness.
