# Owner-Open Call Registry

Current module: `MOD-EXECUTION-CORE`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate provides bounded per-call identity, state transition, cancellation and duplicate/conflict mechanics. It is mechanism-only and does not authorize commands, select targets or retry uncertain effects.

Its current scalability gap is tracked as `GAP-CONC-REGISTRY-001`. Historical maturity and integration claims have been removed; current state is generated under `docs/generated/`.

## Detailed contracts and local verification

- [MOD-EXECUTION-CORE](../../docs/modules/MOD-EXECUTION-CORE.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-call-registry --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
