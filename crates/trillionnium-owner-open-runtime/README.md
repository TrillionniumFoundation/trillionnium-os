# Owner-Open Direct Runtime

Current module: `MOD-TOOL-RUNTIME`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate executes exact shell or ordinary ADB requests using bounded process, pipe, PTY, signal and cleanup mechanics. It does not rewrite command semantics, inject target routing or retry uncertain effects.

Mechanical schema ceilings remain separate from resource admission. Each
profile reserves stdin, reader/blocked/current chunks, queue/container metadata
and request/spec/Command copies within32 MiB; actual String/Vec/Path capacities
are checked before acceptance. A shared64 MiB /16 active-leader RAII budget is
acquired before the synchronous accepted receipt and held through cleanup.
Capacity denial publishes no process event or durable effect acceptance.

`reserve_shell_capacity` / `reserve_adb_capacity` and additive
`execute_*_with_capacity` entry points let the bridge retain that reservation
through its registry admission. The token is consumed once and actual capacity
is checked again. Existing terminal/unknown identities require no new lease.
Inherited environment values are preserved in a bounded1 MiB snapshot before
admission, with request environment deltas applied afterward; later host-env
mutation cannot widen the admitted child. Snapshot/Command staging is reserved.

These bounds cover owned substrate buffers/leaders. Caller-retained output,
external processes/descendants, thread stacks and whole-process RSS require
their own admission/installed measurements; streaming a large total output
alone does not imply resident retention of that output.

Installed process-lifecycle evidence remains tracked by `GAP-PROCESS-LIFECYCLE-001`. Current state is generated under `docs/generated/`.

## Detailed contracts and local verification

- [MOD-TOOL-RUNTIME](../../docs/modules/MOD-TOOL-RUNTIME.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-runtime --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
