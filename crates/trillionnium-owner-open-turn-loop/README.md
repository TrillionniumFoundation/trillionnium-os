# Owner-Open Turn Engine

Current module: `MOD-TURN-ENGINE`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns the same-turn provider event and tool callback lifecycle, targeted cancellation and exactly-one terminal mechanics. Semantic decisions remain inside Codex/provider.

Event-driven cancellation and bounded event-spool work remain tracked by `GAP-CONC-TURN-CANCEL-001`. Current state is generated under `docs/generated/`.
