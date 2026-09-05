# Owner-Open Stream Window

Current module: `MOD-STREAM`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns bounded byte credit, delivery windows and explicit cursor-gap mechanics. Zero data credit must not block control, inspection or terminal delivery.

Installed stream recovery remains tracked by `GAP-STREAM-RECOVERY-001`. Current state is generated under `docs/generated/`.

## Detailed contracts and local verification

- [MOD-STREAM](../../docs/modules/MOD-STREAM.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-stream-window --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
