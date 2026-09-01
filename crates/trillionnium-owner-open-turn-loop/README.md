# Owner-Open Turn Engine

Current module: `MOD-TURN-ENGINE`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns the same-turn provider event and tool callback lifecycle, targeted cancellation and exactly-one terminal mechanics. Semantic decisions remain inside Codex/provider.

Turn cancellation is propagated through a turn-scoped flag into the direct-tool
bridge; no per-tool cancellation monitor thread is created. Returned turn and
tool diagnostics are bounded, while provider I/O readers retain bounded
readiness polling for cleanup. Installed qualification and evidence remain
tracked by `GAP-CONC-TURN-CANCEL-001`; generated state is under
`docs/generated/`.

Diagnostic retention has two independent ceilings: at most 4,096 turn events
and 64 MiB of estimated owned payload, and at most 4,096 tool-runtime events
and 64 MiB of estimated owned payload. The byte estimate is checked arithmetic
over the concrete `String`/`Vec` capacities plus fixed value layouts (a
conservative accounting aid, not a wire-format limit). A provider event or
runtime output that cannot fit is still delivered to the event sink; it is
omitted only from the returned diagnostic tail. Eviction preserves the initial
`TurnAccepted` marker and the final `TurnTerminal` event, so retention never
changes provider or terminal semantics.
