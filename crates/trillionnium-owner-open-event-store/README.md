# Owner-Open Event Store

Current module: `MOD-EVENT-STORE`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate records bounded append-only observations, integrity metadata and replay state. It records facts and never authorizes an effect or treats missing data as proof that an effect did not start.

Its durability and scalability work is tracked by `GAP-JOURNAL-CONVERGENCE-001` and `GAP-CONC-EVENT-STORE-001`. Historical source-status prose has been removed; current state is generated under `docs/generated/`.
