# Owner-Open Tool Bridge

Current module: `MOD-TOOL-RUNTIME`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate binds exact call identity to direct runtime execution and returns raw observations. It is a mechanism boundary and does not approve, reinterpret or automatically redispatch work.

Current module status and evidence are generated from `docs/machine/`.

## Detailed contracts and local verification

- [MOD-TOOL-RUNTIME](../../docs/modules/MOD-TOOL-RUNTIME.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-tool-bridge --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.

Shell and ADB request timeouts use the process runtime's shared hard ceiling.
An oversized timeout is rejected before call registration or event delivery;
zero retains the runtime's default-timeout meaning. This is an internal framing
fix with no API or state migration. Source regression tests prove this admission
ordering, while installed liveness and resource use remain unqualified.
