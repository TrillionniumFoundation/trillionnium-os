## G1 change identity

- Program revision: `2026-08-31-g1`
- Affected modules: `MOD-...`
- Change class: `D0 / D1 / D2 / D3 / D4 / D5`
- Exact source base: `<commit>/<tree>`

## Contract

- [ ] I started from `docs/START_HERE.md` and did not reintroduce historical development authority.
- [ ] Machine truth and generated views are updated atomically.
- [ ] Module responsibilities, dependencies and state ownership remain explicit.
- [ ] API and state-schema compatibility or migration is documented.
- [ ] Ordering, concurrency and resource-budget impact is documented.
- [ ] SLI/SLO and benchmark impact is documented.
- [ ] Effect identity, durability and `automatic_redispatch=false` are preserved.
- [ ] Canary, rollback and recovery behavior is documented.

## Verification

- [ ] `python3 tools/docs/generate_global_docs.py --check`
- [ ] `python3 tools/docs/verify_global_docs.py`
- [ ] `cargo fmt --all -- --check`
- [ ] `cargo test --locked --all-targets`
- [ ] `cargo clippy --locked --all-targets -- -D warnings`

## Gaps and evidence

- Gaps changed:
- Evidence level reached:
- Evidence artifacts:
- Negative claims retained:

- [ ] This PR does not infer installed, image, physical-device, destructive-fault or release evidence from source tests.
- [ ] Any approval is bound to the current exact head and is from a non-author where required.

## Claim boundary

- [ ] Documentation/source candidate only
- [ ] L1 exact-source evidence attached
- [ ] L2 installed-target evidence attached
- [ ] L3 Android-image evidence attached
- [ ] L4 physical-device evidence attached
- [ ] L5 destructive-fault evidence attached
- [ ] L6 release authorization attached
