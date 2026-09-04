# Trillionnium Owner-Open Host

This Cargo component is the mechanical composition root for the active owner-open control and transport hosts. It implements two catalog modules:

- [`MOD-EXECUTION-CORE`](../../docs/modules/MOD-EXECUTION-CORE.md) through `src/bin/r5_control_host_v7`;
- [`MOD-TRANSPORT`](../../docs/modules/MOD-TRANSPORT.md) through `src/bin/r5_transport_host`.

The machine authority is `docs/machine/module-catalog.v1.json`. This README is a component-local development guide and never overrides that authority.

## Authority boundary

The host routes validated requests, coordinates registries and runtimes, preserves request and terminal correlation, applies bounded transport mechanics and publishes observations. It is not a semantic principal. It must not reconstruct a plan, select another tool, rewrite a command, inject an ADB serial, hide a retry, convert ambiguity into success or automatically redispatch an uncertain effect.

The provider is the sole semantic principal. A host may reject input because identity, framing, version, capacity, lease, state or trust checks fail; rejection is not permission to substitute another action.

## Active implementation selection

The active execution implementation is `src/bin/r5_control_host_v7`. Historical source retained elsewhere in the tree is not selected merely because it compiles. The active transport implementation is `src/bin/r5_transport_host`.

Cargo feature and binary selection, the root workspace `default-members`, packaging manifests and Android product inventory must agree. A second product entrypoint or legacy authority in the default build, install or runtime graph is a qualification failure.

## Concurrency and lifecycle

Admission reserves finite capacity before slow work. Per-key lifecycle transitions are linearized by the request, turn, job or connection identity; unrelated keys may progress concurrently. Process spawn, external I/O, fsync and provider waits stay outside broad registry locks.

Cancellation is targeted. Terminal completion and timeout/cancel races pass through the authoritative lifecycle transition. Cleanup may release capacity but never authorizes a replacement effect. Late results must match the exact broker sequence, request identity, digest and lineage before delivery.

## Persistence and recovery

The host binds accepted operations to durable records owned by the relevant registry or event store. On restart it creates a new epoch, fences stale writers, reconstructs correlation state and reconciles observed external reality. Missing terminal evidence produces an unknown/reconciliation-required outcome; it is not proof that a process or device action never occurred.

## Build and verification

The required G1 source qualification uses Rust 1.93 with:

```sh
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

The exact clean checkout, lockfile and generated documentation graph are also required. These checks establish source properties only. Installed process identity, namespace/cgroup placement, Android target-files, physical-device effects and destructive-fault recovery require separate evidence.

## Change checklist

A change to a host binary must update every affected module contract, protocol or state version, migration rule, finite budget, negative test, product-entrypoint manifest and evidence expectation. The exact source must stop moving before independent review and attestation are bound.

Automatic redispatch is forbidden. `public_release` remains false until the complete L1–L6 chain is independently authorized.

## Detailed contracts and local verification

- [MOD-EXECUTION-CORE](../../docs/modules/MOD-EXECUTION-CORE.md)
- [MOD-TRANSPORT](../../docs/modules/MOD-TRANSPORT.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-host --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
