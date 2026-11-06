# Owner-Open Job Registry

Current module: `MOD-JOB-RUNTIME`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns bounded job and operation identity, lifecycle transitions and duplicate/conflict handling. It does not schedule semantic work or automatically restart an uncertain effect.

Current status and open gaps are generated from `docs/machine/`; no historical maturity statement in this directory is authoritative.

Public insertion/control methods check owned String capacities as well as
logical framing, including keys, requests, attachments, output hashes and
terminals. A new entry reserves its future bounded history/attachment/terminal
storage before Accepted. All registry constructors share the linked job
module's 48 MiB active/retained pool; job runtime also uses this same pool and a
separate 16 MiB working pool. Capacity pressure preserves uncertain keys and
exact duplicate/conflict behavior rather than evicting effect identities.
`JobMemoryLease` provides the noncloneable shared charge used by the runtime;
Arc owners share one charge and final Drop releases it. Ordinary returned
snapshots/histories can be retained or cloned by callers and require their own
response custody; these source reservations are not installed RSS evidence.

## Detailed contracts and local verification

- [MOD-JOB-RUNTIME](../../docs/modules/MOD-JOB-RUNTIME.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-job-registry --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
