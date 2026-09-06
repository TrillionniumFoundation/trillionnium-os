# Owner-Open Provider JSONL

Current module: `MOD-PROVIDER`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns provider process lifecycle, bounded strict JSONL framing and same-turn tool callback transport. Codex/provider remains the only semantic principal; this adapter adds no fallback, approval or retry policy.

Installed Codex and event-driven cancellation work remain tracked in the G1 gap register. Current state is generated under `docs/generated/`.

## Detailed contracts and local verification

- [MOD-PROVIDER](../../docs/modules/MOD-PROVIDER.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-provider-jsonl --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
