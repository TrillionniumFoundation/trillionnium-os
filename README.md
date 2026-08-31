# Trillionnium OS

Trillionnium OS is developed through one active, machine-verified documentation corpus.

Start at [`docs/START_HERE.md`](docs/START_HERE.md).

Current truth is split into:

- `docs/machine/` — baseline, program, modules, requirements, gaps, global objective and evidence;
- `docs/generated/` — generated current-state, module, gap, traceability and performance views;
- the remaining top-level files under `docs/` — the only active normative development documents.

Earlier plans, status snapshots, audit narratives, batch documents and duplicated evidence prose have been removed from the working tree. They remain recoverable from Git history for research, but they are not current development authority and must not be copied back as active guidance.

Core invariants:

- Codex/provider is the sole semantic principal;
- substrate and global control are mechanical only;
- uncertain effects are never automatically redispatched;
- source, installed-target, Android-image, physical-device, destructive-fault and public-release claims remain separate evidence levels.

Validate the active corpus with:

```sh
python3 tools/docs/generate_global_docs.py --check
python3 tools/docs/verify_global_docs.py
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
```

The exact current state is generated in [`docs/generated/CURRENT_STATE.md`](docs/generated/CURRENT_STATE.md).
