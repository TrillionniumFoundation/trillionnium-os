# Contributing to Trillionnium OS

Start with `docs/START_HERE.md`. Current program truth lives under `docs/machine/`; files under `docs/generated/` are generated and must not be edited by hand.

## Historical-document rule

Historical development documents must not be reintroduced. Git history is the recovery source for prior plans, audits, status snapshots and evidence narratives. Historical material may be studied, but it must not be copied back into the working tree as an active plan, protocol, status or evidence authority.

## Module contract

Every behavior-affecting change identifies its affected module IDs and updates the applicable:

- responsibilities and non-goals;
- interfaces and state schemas;
- ordering, concurrency and resource contracts;
- SLI/SLO and benchmark evidence;
- failure, recovery, migration and rollback behavior;
- requirements, gaps, claim ceiling and negative claims.

Each module has a primary and backup owner. Cross-module API or state changes require both producer and consumer review.

## Change classes

- D0 — wording or link only;
- D1 — module-internal implementation;
- D2 — cross-module API or state schema;
- D3 — concurrency, persistence, resources or lifecycle;
- D4 — semantic authority or Effect invariant;
- D5 — evidence, release or claim ceiling.

Review requirements are defined in `docs/TEAM_AND_DELIVERY_MODEL.md`.

## Branch and CI requirements

Use short-lived branches and the protected integration path. Do not push directly to `main`, bypass required checks or reuse a historical green run for a changed head.

Every behavior-affecting pull request must:

1. check out and identify its exact clean source head;
2. keep `Cargo.lock` reviewed and unchanged by CI;
3. pass formatting, locked tests and strict lint;
4. keep generated documentation byte-exact;
5. declare API/state compatibility and migration;
6. report performance and resource-budget impact;
7. provide canary and rollback conditions;
8. retain explicit negative claims.

Any behavior-changing push invalidates stale approvals.

## Effect and evidence safety

Preserve exact identity, durable-before-effect requirements, truthful uncertainty and `automatic_redispatch=false`. Source fixtures cannot close installed, Android-image, physical-device, destructive-fault or release gaps.

Do not commit credentials, private keys, target tokens, device secrets, unredacted user data or unreviewed release evidence. Security reports follow `SECURITY.md`.
