# R5 Batch D closeout — durable long-running jobs

Status: **source implementation landed; exact-runner and provider/device gates remain open**

## Completed source batch

The Batch D job slice now contains:

1. isolated job identity and lifecycle registry;
2. exact job-request and operation-request binding;
3. accepted-before-effect durable journal;
4. pipe and PTY process substrate;
5. write, resize, close-stdin and process-group kill;
6. bounded runtime observations and read-only inspection;
7. live attachment bookkeeping and detach;
8. conservative restart recovery with no automatic redispatch;
9. job-aware v7 execution core composed with the existing v4 turn core;
10. selected v5 transport over the v7 core, preserving persisted stream windows;
11. exact Cargo graph, CI closure, protocol, implementation and traceability updates.

## Acceptance gates still open

### Gate D1 — exact Rust runner

Required on one exact commit:

```text
cargo fmt --all -- --check
cargo test --locked --all-targets for all owner-open packages
cargo clippy --locked --all-targets -- -D warnings
cargo metadata --locked
cargo tree --locked -e features
```

All resulting code fixes, lockfile changes and evidence must be committed before status promotion.

### Gate D2 — provider job callback

The installed Codex adapter must expose `shell.job` as a native same-turn tool. It must:

- start a pipe job;
- observe output;
- write stdin;
- start and resize a PTY job;
- inspect and kill the target job;
- continue the same provider turn;
- never retry an uncertain operation ID.

### Gate D3 — durable reconnect

A new client connection must inspect a completed or uncertain job without starting a provider or child process. Live attachment after the same Host remains available; cross-Host live file-descriptor reattachment remains a separate design gate.

### Gate D4 — fault qualification

Required cases:

- client delivery disconnect;
- provider disconnect while job continues;
- Host crash before and after accepted operation;
- child leader exit with surviving descendants;
- PTY slave close;
- event-store ENOSPC and partial write;
- Root Linux restart;
- Android reboot and power loss.

## Critical path after this source batch

1. obtain exact Rust execution and fix every defect;
2. bind native Codex `shell.job` callbacks;
3. select and implement the physical ADB topology;
4. cut the Android owner-open product graph;
5. wire init, SELinux, abstract socket, Root Linux placement and AiShell controls;
6. collect L3, L4 and L5 evidence.

No job source artifact promotes Android, device, fault or release status by itself.
