# Owner-Open Direct Runtime

Current module: `MOD-TOOL-RUNTIME`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate executes exact shell or ordinary ADB requests using bounded process, pipe, PTY, signal and cleanup mechanics. It does not rewrite command semantics, inject target routing or retry uncertain effects.

Installed process-lifecycle evidence remains tracked by `GAP-PROCESS-LIFECYCLE-001`. Current state is generated under `docs/generated/`.

## Detailed contracts and local verification

- [MOD-TOOL-RUNTIME](../../docs/modules/MOD-TOOL-RUNTIME.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-runtime --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
