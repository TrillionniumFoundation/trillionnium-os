# Owner-Open Provider JSONL

Current module: `MOD-PROVIDER`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns provider process lifecycle, bounded strict JSONL framing and same-turn tool callback transport. Codex/provider remains the only semantic principal; this adapter adds no fallback, approval or retry policy.

Installed Codex and event-driven cancellation work remain tracked in the G1 gap register. Current state is generated under `docs/generated/`.
