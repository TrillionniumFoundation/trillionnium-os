# Owner-Open Job Registry

Current module: `MOD-JOB-RUNTIME`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns bounded job and operation identity, lifecycle transitions and duplicate/conflict handling. It does not schedule semantic work or automatically restart an uncertain effect.

Current status and open gaps are generated from `docs/machine/`; no historical maturity statement in this directory is authoritative.

## Detailed contracts and local verification

- [MOD-JOB-RUNTIME](../../docs/modules/MOD-JOB-RUNTIME.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-job-registry --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
