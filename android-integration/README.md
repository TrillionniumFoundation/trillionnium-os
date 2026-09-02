# Android integration audit overlay

This directory records the Android repo-manifest inputs and the uncommitted
Trillionnium integration files that were present in the canonical
`lineage-fogos` checkout when the audit snapshot was published.

The Android checkout is a repo-manifest workspace with 1,172 independent Git
projects; it is not flattened into this repository. The complete source
baseline is reproducible from the pinned manifest files under
`../docs/audit/android-manifest/`. The `working-tree/` subtree contains the
current Trillionnium dirty overlay (modified and untracked source files),
with generated `__pycache__` files excluded. `PROJECT_STATUS.tsv` records each
overlay path, its project HEAD, worktree status, and content SHA-256.

This overlay is evidence for external audit and is not an approval gate. It
does not claim that a live Android build, device effect, or OTA has passed by
itself. The checked-in overlay is consumed by the protected-main desktop
workflow in `.github/workflows/android-remote-package-device.yml`; the
workflow verifies its hashes, materializes it on the canonical external
checkout, builds `trillionnium_fogos-bp4a-userdebug`, and performs the bounded
APK/device smoke described in `GITHUB_DEVICE_CI.md`. A new overlay path or
project revision must update `PROJECT_STATUS.tsv` and the pinned manifest in
the same reviewed change, otherwise the desktop preflight fails closed.
The lane validates the frozen manifest and the declared overlay projects; the
remaining base projects are trusted pre-provisioned inputs rather than
re-cloned on every run.
The desktop runner's removable-disk systemd guard is recorded in
[`desktop-runner-external-disk.conf`](desktop-runner-external-disk.conf).

The supported GitHub-hosted package to local self-hosted-device workflow is
documented in [`GITHUB_DEVICE_CI.md`](GITHUB_DEVICE_CI.md).
