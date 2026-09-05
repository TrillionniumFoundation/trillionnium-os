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
does not claim that a live Android build, device effect, or OTA has passed.

The supported GitHub-hosted package to local self-hosted-device workflow is
documented in [`GITHUB_DEVICE_CI.md`](GITHUB_DEVICE_CI.md).
