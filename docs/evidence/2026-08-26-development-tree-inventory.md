# Trillionnium OS development-tree inventory and cleanup receipt

Date: 2026-08-26 (Asia/Shanghai)  
Decision: **one active control-plane tree; retired routes removed from the
active graph**

This is the bounded inventory for the source reorganization requested on
2026-08-26. It is an audit receipt, not an implementation plan; the only
active plan is [`../TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](../TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md).

## Active trees

| Role | Exact path | Revision/status |
| --- | --- | --- |
| Trillionnium control plane (唯一主树) | `/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-release-sources/p0-agent-native-integration-20260731/trillionnium-os` | branch `p0-agent-native-integration-20260731`, HEAD `7cba499c46fb8f28cb94aea5b5e41c28420995e5`; dirty changes are the current uncommitted integration lane and are retained |
| Android integration tree | `/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/android/lineage-fogos` | canonical AOSP checkout; its `out/` and signed/device evidence are build products, not a second control plane |
| Android manifest inputs | `lineage-fogos/trillionnium-os/{contracts,schemas,tools}` | three manifest-managed projects; retained in place and required by current Android checks |

The external disk is mounted at `/data/toshiba-dev` from UUID
`63df6e1a-baf3-4680-8bbb-8019fb025341`. No internal-SSD Android fallback is
valid. Android source checks after the path fix found no active reference to a
retired Rust worktree or old release-root name.

## Retired Rust worktrees

The following trees were older snapshots or duplicate branches. Before removal,
all source files (including untracked files, excluding generated `target/` and
Git administrative data) were captured in the hash-verified custody archives
below. Their source-file inventory digests are included so a restore can be
checked without trusting a path name.

| Retired path | HEAD / state at freeze | source files | inventory digest | custody archive SHA-256 |
| --- | --- | ---: | --- | --- |
| `/data/toshiba-dev/TrillionniumOS/rootfs/data/trillionnium-p01-codex-worktree-20260802` | detached `ca8372517de1ac900a66a2c82a2e9f2a0c0d8c5f`; dirty source-only conformance lane | 1087 | `a5db0b45fd5f065f692fa7d4e16dad26491d8a1791018e79e175fe42b5e34a3a` | `d1ee30b931e1033343548ddb176f93a600aca8fc3688de9b05b97a7710b5c6ae` |
| `/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-release-sources/control-plane-full-hardening-20260716` | branch `p0-canonical-freeze-20260728`, `9a84ff394f01151bd966b8cea5a4f15852f0ffaf`; clean | 1046 | `106e925abd7712dc31fc827bb43b8dfe5461f55899ce09e1c5b06c31b75a7a69` | `5e83f2946f5b4d6faf1f1b6a59b464f29ded31d5748abc071cf44fc1982eb10c` |
| `/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-release-sources/p0-execution-20260728` | branch `p0-execution-20260728`, `9a84ff394f01151bd966b8cea5a4f15852f0ffaf`; dirty | 1044 | `94e2489deb6df41d82be569f3a894d5979b5a3ae78386f21c59d4567e9d407e5` | `625d9bab7aafa3c0ef328f34d6b08339683a32b6b165a41dc93d55f8cb0fa132` |
| `/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-release-sources/p01-launch-conformance-20260728` | branch `p01-launch-conformance-20260728`, `9a84ff394f01151bd966b8cea5a4f15852f0ffaf`; dirty | 1034 | `d6c645164340f8230eb7c2aeea63878707988bba5306d920a68bdf4a074d0ab1` | `532d2a6b1a3a83c7721d8d9785172574053a0ffc7e0d71bcfc174d00654c0c03` |
| `/tmp/trillionnium-preformat-tree.1bLa1X` | detached `7cba499c46fb8f28cb94aea5b5e41c28420995e5`; temporary dirty copy | 726 | `4585229b27578368064a8bc628c9815772263e35c9303ea7702fe4b2aa2ca548` | `0af697d6f9f08ae849061555b8b0bf3ae390d3003a2d79234c3d66603a48a98b` |

The corresponding archives are under
`/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-retired-artifacts/2026-08-26/`.
They are recovery custody only and are not searched as product inputs.

The five archive digests above plus the following exact legacy bundles were
verified with `zstd -t` before source removal:

| Bundle | SHA-256 |
| --- | --- |
| `docs-mobile-smoke-20260826.tar.zst` | `fa031ab86e414581f445ede2e721a95a7c9ddee60d38cad72693c396291f332f` |
| `docs-archive-historical-v1-20260826.tar.zst` | `801773423c0e50977675ae3dd517512a29e759a71995472087016c093e4adc50` |
| `docs-archive-evidence-migration-v1-20260826.tar.zst` | `df7eb2ee84ea02336d2a32e305bb50bfba5143dab5e426b5857d17ce06f04853` |
| `packaging-openclaw-android-20260826.tar.zst` | `0c44ce73f2d9df615db1125c6ce0da2a46c8754673570667ae92873a160272af` |
| `superseded-top-level-docs-20260826.tar.zst` | `fb1a36619131776df2431c384b036dd52973467cb9158e21035d6b19a847b03e` |
| `historical-evidence-july-20260826.tar.zst` | `fe7c33f7482118f9fce154351d10d9745ac3086bdb3a1fe489251f87815580f7` |
| `tools-evidence-migration-index-retired-20260826.tar.zst` | `835d3bb1339e40646b9241354dfc3cbc314842d580b146617236e5194e7144cb` |

The obsolete remainder of the Android aggregation checkout was moved intact
out of the AOSP tree to
`.../trillionnium-retired-artifacts/2026-08-26/android-aggregation-
trillionnium-os-20260826` (3.3G, 204,921 regular source files after excluding
nested `.git` and generated `target` entries). Its relative-file path-list
digest is `2cb5318520e2d231cc54fb5bb2e6aaadca172f1de31c512170032d320af49538`.
Only the three manifest-managed `contracts`, `schemas` and `tools` projects
were restored to the active AOSP path; the old UI/browser/design/probe
siblings remain custody-only.

The detached `/home/qian-qi/.openclaw/workspace` Git worktree is deliberately
not removed: it is the host workspace and contains unrelated user material.
Its Git administrative records and dirty files are outside this cleanup scope.

The shared repository's old safety/master/release history refs are likewise
not active trees and are excluded by source/BOM discovery. Only the
`p0-agent-native-integration-20260731` branch is checked out for Trillionnium;
purging shared Git history would require a separate retention decision because
the host workspace uses the same repository.

After the host-estate move, the Trillionnium parent contains only the
canonical `trillionnium-release-sources` tree, the AOSP `android` tree, the
current v27/v28 release evidence and declared build/release stores, plus the
`trillionnium-retired-artifacts` custody root. The latter categories are
explicitly non-source and are excluded from source/BOM discovery; no additional
Rust or Android control-plane checkout remains at the parent level.

The old sibling `release-sources/history-archives/` directory was also moved
into `trillionnium-retired-artifacts/2026-08-26/host-estate/` after verifying
its single archive (`trillionnium-os-old-workspace-20260803.tar.zst`, SHA-256
`4232a2b801a681b63a53e942a799d8c4cbad7601bf384a1d5d5523272ee50826`). The
release-sources parent now has no history/archive sibling beside the canonical
tree.

The stale host-level `p0-source-bom-20260803-v12.json` was moved to the same
custody area (SHA-256
`759c0728da9c46782243b704a0511f7ebf9e41887eb0a6cb5f626943fc4ed5ec`). It was
explicitly a non-product userdebug observation with `release_pin=false`, so it
must not participate in current BOM discovery.

The same boundary now applies to `rootfs/data`: only the current
`data/trillionnium/root-linux` state and the pre-existing OpenClaw archive/
quarantine roots remain at that level. Thirty-nine old Provider/Codex/
Root-Linux/kernel/userdebug/P01 artifacts (aggregate post-move `du` bytes
40,089,260,382) are in
`host-estate/data-legacy-20260826/`. A separate root-owned 68-GB Provider
ARM64 image was removed after its seven audit metadata files were retained in
the SHA-pinned provider metadata archive listed in `MANIFEST.md`.

## Removed from the active control-plane tree

After the archive step and reference scan, the following exact legacy surfaces
are removed from the active source graph:

- `docs/mobile-smoke/` (362 May-2026 Mobian/Phosh/Waydroid/Shell/Bridge
  experiment files);
- `docs/archive/historical-v1/` (eight superseded design/prototype files);
- `docs/archive/evidence-migration-v1/` (the old deletion-plan/index wrapper,
  replaced by this receipt and the external archive hashes);
- `packaging/openclaw-android/` (untracked retired packaging residue, already
  covered by the 2026-08-06 OpenClaw custody archive).
- the 25 `docs/evidence/2026-07-14-*`, `2026-07-23-*`, `2026-07-24-*` and
  `2026-07-28-*` checkpoint records; their bytes are in the
  `historical-evidence-july-20260826.tar.zst` custody bundle above. Current
  2026-08-22 through 2026-08-26 evidence remains active and is the only dated
  evidence set linked by `docs/README.md`.
- `tools/materialize_evidence_migration_index.py` and its test were retired
  after their source roots were removed; the exact two-file source bundle is
  in `tools-evidence-migration-index-retired-20260826.tar.zst` above. No tool
  in the active graph writes a historical index back into the product tree.

The accepted Codex-only ADR, current v2 contract, current audits, tests, Root
Linux inputs and production-retirement absence policy remain. Small tombstone
links in the documentation index point to the canonical plan; historical PASS
markers are not release evidence.

The Android optional test that hard-coded the deleted detached Rust path was
updated to use `TRILLIONNIUM_RUST_WORKTREE` (defaulting to the canonical tree)
and to treat the old non-authorizing probe as absent. The optional v20 test now
requires an explicit `TRILLIONNIUM_V20_RELEASE_ROOT` instead of a stale dated
host path. Generated `__pycache__` files are cleanup candidates and never
product inputs.

Four dangling, unreferenced Android-root symlinks from abandoned builder
attempts (`out-eng-root` and three 2026-08-09 sepolicy out aliases) were
removed after their targets were verified absent and no build source referenced
them. The manifest-managed `trillionnium-os/contracts`, `schemas` and `tools`
projects were explicitly restored and remain active inputs; the move/restore
race did not change their contents.

The following exact, owner-controlled scratch/cache paths were then removed
after `fuser` found no users and no source/reference scan found a consumer:

- five empty or `.rustc_info.json`-only `trillionnium-feature-validation-20260807.*`
  probes (4,164 bytes total, one empty);
- empty `trillionnium-p01-core-test-tmp`;
- `trillionnium-generated-python-cache-20260812.Fc6CTe` (125,585 bytes);
- `trillionnium-android-build-cache-quarantine-20260811` (250,184 bytes);
- `trillionnium-authority-generated-cache-quarantine-20260812.09q9bU` and
  `.UjiTbT` (125,307 bytes each);
- empty-artifact probe `trillionnium-source-bom-calibration-20260808T210038Z-v1`
  (one zero-byte manifest).
- the one-file `trillionnium-source-ignored-quarantine-20260811T231415+0800`
  Python-cache quarantine (125,092 bytes).

These were generated probes/caches rather than source or release evidence, so
they were not copied into custody. The remaining calibration, release and
quarantine directories are explicitly classified below as retained evidence or
custody and are not active inputs.

## Retained, but not active source

The following are intentionally retained outside the main source tree because
they are rollback/recovery evidence or current Android build inputs:

- `/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-retired-artifacts/`
  (hash-verified custody, including prior OpenClaw/WindowsCompat/legacy UI
  archives and the exact archives listed above);
- `trillionnium-retired-artifacts/2026-08-26/host-estate/` contains the
  renamed v20–v26 release snapshots, old shell-exec/calibration/rootfs
  artifacts, host/Android quarantine copies and the detached Direct source
  tree. The two Android source-custody quarantines formerly nested directly
  under `android/` are included there as `android-source-custody-*`. Its
  byte/file inventory and move receipt are in the custody
  `MANIFEST.md`; none is an active source or BOM input;
- `trillionnium-release-targets`, `trillionnium-release-materialization`,
  `trillionnium-release-runs`, `trillionnium-source-boms`, secure-release-input
  custody, and P0 freeze/escrow manifests. These are not source authority and
  must not be auto-discovered as a new plan or product package;
- Android `out/target/*` directories and the current device OTA evidence. They
  are retained until the corresponding build/rollback audit is closed;
- six `.direct-binding-publisher-test-*` fixtures containing symlink/FIFO and
  incomplete-transaction cases were moved to the hash-recorded
  `trillionnium-retired-artifacts/2026-08-26/binding-publisher-fixtures-20260826`
  custody directory (tree digest
  `2224bbd7b7f98085029951292bff754cd39739325d68328c5428d39e4ae80d52`). They
  are not active source or product inputs;
- the canonical Rust `target/` directory while verification artifacts are being
  consumed. It is generated output, not source, and may be removed later only
  by an exact, quiesced cleanup.

## Verification performed

On the canonical tree, sequential Rust tests passed:

- `trillionnium-os-types`: 197 passed;
- `trillionnium-agent-direct-tools`: 286 passed;
- `trillionnium-agent-privilege-broker`: 99 passed;
- `trillionniumd`: 372 passed, 2 ignored.

Python agent/release-gate suites and `cargo fmt --check` also passed in this
lane. No Cargo/Rust process remained after the run. The device was not changed
by this reorganization; its previously verified userdebug OTA state and USB
reverse tether remain as recorded in the current dogfood evidence. Product
HOLDs (trusted authority/transport, ACK/replay, rollback anchor, fault
evidence and release admission) remain explicit in the canonical plan.
