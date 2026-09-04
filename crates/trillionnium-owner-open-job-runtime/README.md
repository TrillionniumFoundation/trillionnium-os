# Owner-Open Job Runtime

Current module: `MOD-JOB-RUNTIME`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns durable long-running pipe and PTY job mechanics, controls, observations, process-group lifecycle and restart reconciliation.

Admission correctness is closed at L1; installed lifecycle, slow-path lock removal and target evidence remain tracked by `GAP-PROCESS-LIFECYCLE-001` and `GAP-CONC-JOB-START-HOTLOCK-001`. Current state is generated under `docs/generated/`.

## Detailed contracts and local verification

- [MOD-JOB-RUNTIME](../../docs/modules/MOD-JOB-RUNTIME.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-job-runtime --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
