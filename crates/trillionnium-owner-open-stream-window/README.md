# Owner-Open Stream Window

Current module: `MOD-STREAM`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns bounded byte credit, delivery windows and explicit cursor-gap mechanics. Zero data credit must not block control, inspection or terminal delivery.

Installed stream recovery remains tracked by `GAP-STREAM-RECOVERY-001`. Current state is generated under `docs/generated/`.
