# Contributing to Trillionnium OS

Trillionnium OS uses an evidence-first stacked integration process. A green
source workflow is necessary but is not sufficient to claim that code is
installed, image-included, device-observed, fault-qualified, or released.

## Change topology

1. Branch from the exact reviewed base named in the active plan.
2. Keep each pull request narrow enough for an independent reviewer to inspect.
3. Do not bypass the declared stacked PR order.
4. Do not push directly to `main` or force-push a reviewed integration head.
5. Re-run exact-head CI after every behavior-affecting source change.

The active semantic and implementation authorities are listed in
`docs/OWNER_OPEN_R5_START_HERE.md`. Historical plans and status snapshots do not
override the active machine gap register.

## Required source checks

Before requesting review, the exact pull-request head must pass the permanent
workflows covering:

- generated contracts and exact source graph;
- Python compilation, mutation and protocol fixtures;
- locked Rust metadata, formatting, all-target tests and strict Clippy;
- owner-open product entrypoint and Android source-profile contracts;
- evidence workflow boundaries and fail-closed promotion rules.

Do not copy a successful run from an earlier commit into status documents.
Checked-in status is claim policy; exact evidence is produced by CI.

## Evidence levels

- **L0** — contract/source shape only.
- **L1** — exact-checkout host tests.
- **L2** — installed Root Linux, provider, broker and Codex observations.
- **L3** — clean Android target-files, Soong, init and SELinux evidence.
- **L4** — authorized physical shell/job/ordinary-ADB effects.
- **L5** — crash, storage, disconnect, USB, reboot and power-loss qualification.
- **L6** — signed public release with independent human authorization.

Never edit a gap to `CLOSED` without a promotable evidence bundle at or above
its declared exit level. Synthetic fixtures and source-only CI cannot close an
external lane.

## Review independence

A reviewer approving integration or external evidence must differ from the
change author, evidence producer and target operator. Stale approvals do not
apply after a behavior-affecting head change. Release authorization must be
separate from production, review and target operation.

## Security-sensitive changes

Changes to process lifecycle, credentials, ADB, persistence, Android/SELinux,
workflows, evidence capture or release paths require explicit negative tests.
Preserve raw errors and uncertain effect state. Never introduce automatic
redispatch after disconnect, timeout, journal failure or restart.

## Commit and artifact hygiene

- Sign off commits and use descriptive, scoped messages.
- Pin third-party workflow actions to full commit SHAs.
- Keep `Cargo.lock` reviewed and unchanged by locked CI.
- Do not commit credentials, device secrets, private keys, target tokens or
  unreviewed release evidence.
- Bind generated artifacts to exact source, toolchain, manifest and digest.

Security reports follow `SECURITY.md` rather than the public issue tracker.
