# Trillionnium OS GitHub audit snapshot

This repository is the complete source snapshot prepared from the canonical
Trillionnium control-plane tree for an external full-tree audit.

- Source root: `/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-release-sources/p0-agent-native-integration-20260731/trillionnium-os`
- Baseline Git revision: `7cba499c46fb8f28cb94aea5b5e41c28420995e5`
- Snapshot date: 2026-08-27 (Asia/Shanghai)
- The current working-tree files (including the latest Rust, Python, contract,
  evidence, and plan changes) overlay the baseline source.
- Historical tracked files that were temporarily staged for deletion in the
  source worktree are retained in this audit snapshot so the external review
  does not lose evidence. The active-tree cleanup can be evaluated separately.

Generated build outputs and repository administration are deliberately absent:
all `target/`, `__pycache__/`, nested `.git/`, and host `.repo/`/build
output directories are excluded. No source file over 100 MiB is present.

The Android integration checkout is a separate repo-manifest tree, not a
single Git repository. Its manifest declaration and pinned project revisions
remain documented in `docs/evidence/2026-08-26-development-tree-inventory.md`;
the AOSP checkout and its `out/`/object stores are not flattened into this
repository. This boundary keeps the snapshot cloneable while preserving the
inputs needed to audit the control-plane integration plan.

The normative current plan is
`docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md` (revision
`2026-08-27-r3`). It keeps Codex as the only semantic control plane and
allows direct shell/argv and raw ADB operations; the remaining implementation
and device/release holds are stated explicitly in that plan.
