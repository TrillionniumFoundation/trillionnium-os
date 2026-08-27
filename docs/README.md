# Trillionnium OS Documentation

This index separates current product truth from retained development history.

## Canonical current documents

1. [`TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
   — the only active implementation plan: Codex-only, Android-managed Root
   Linux, owner-open direct shell/ADB, mechanism substrate and practical
   validation.
2. [`CURRENT_STATE.md`](CURRENT_STATE.md) — implemented boundaries, capability
   matrix, Root Linux and WindowsCompat status, release evidence matrix, and
   next development priorities.
3. [`architecture/2026-08-06-codex-native-direct-shell-adb.md`](architecture/2026-08-06-codex-native-direct-shell-adb.md)
   — historical ADR amended by the canonical owner-open plan: inference stays
   off-device while Codex directly invokes shell and ADB.
4. [`contracts/agent-exec-adb-windows-product-boundary-v2.json`](contracts/agent-exec-adb-windows-product-boundary-v2.json)
   — transition machine contract; the owner-open contract in the plan
   supersedes its semantic approval/allowlist fields.
5. [`contracts/codex-sovereign-direct-tools-v1.json`](contracts/codex-sovereign-direct-tools-v1.json)
   — current owner-open Codex/shell/ADB contract (implementation in progress).
6. [`audits/2026-08-06-ai-agent-native-os-full-audit.md`](audits/2026-08-06-ai-agent-native-os-full-audit.md)
   — repository/history/device audit, architecture grading, cleanup inventory
   and release remediation order.

These are the current architecture and planning entry points. The owner-open
amendment in the canonical plan is the active implementation decision. A later
ADR or explicit amendment must name what it supersedes and update
`CURRENT_STATE.md` and the machine-readable contract in the same change.

## Supporting implementation contracts and checkpoint evidence

The entries below are the current source/checkpoint evidence set. They are
bounded records, not a substitute for a live Codex turn or the release
evidence described in the canonical plan. The plan is normative for current
owner-open behavior; older ADR/contract fields are migration context.

### Current source and dogfood checkpoints

- [`evidence/2026-08-22-adb-transport-boundary-source-audit.md`](evidence/2026-08-22-adb-transport-boundary-source-audit.md)
- [`evidence/2026-08-22-fixed-settings-route-agent-host-integration-source-audit.md`](evidence/2026-08-22-fixed-settings-route-agent-host-integration-source-audit.md)
- [`evidence/2026-08-23-accessibility-live-adapter-snapshot.md`](evidence/2026-08-23-accessibility-live-adapter-snapshot.md)
- [`evidence/2026-08-23-accessibility-selinux-source-fix.md`](evidence/2026-08-23-accessibility-selinux-source-fix.md)
- [`evidence/2026-08-23-android-security-surface-preflight.md`](evidence/2026-08-23-android-security-surface-preflight.md)
- [`evidence/2026-08-23-device-readonly-keymint-accessibility-probe.md`](evidence/2026-08-23-device-readonly-keymint-accessibility-probe.md)
- [`evidence/2026-08-23-device-tee-keystore-probe.md`](evidence/2026-08-23-device-tee-keystore-probe.md)
- [`evidence/2026-08-23-freshness-bound-bom-preflight.md`](evidence/2026-08-23-freshness-bound-bom-preflight.md)
- [`evidence/2026-08-23-init-agent-observer-preflight.md`](evidence/2026-08-23-init-agent-observer-preflight.md)
- [`evidence/2026-08-23-internal-dogfood-ab-ota.md`](evidence/2026-08-23-internal-dogfood-ab-ota.md)
- [`evidence/2026-08-23-keymint-rollback-accessibility-source-audit.md`](evidence/2026-08-23-keymint-rollback-accessibility-source-audit.md)
- [`evidence/2026-08-23-production-allocator-android-ack-replay-bridge.md`](evidence/2026-08-23-production-allocator-android-ack-replay-bridge.md)
- [`evidence/2026-08-23-production-allocator-android-ack-replay-source-audit.md`](evidence/2026-08-23-production-allocator-android-ack-replay-source-audit.md)
- [`evidence/2026-08-23-production-feature-gate-repair.md`](evidence/2026-08-23-production-feature-gate-repair.md)
- [`evidence/2026-08-23-production-material-audit.md`](evidence/2026-08-23-production-material-audit.md)
- [`evidence/2026-08-23-safe-order-execution.md`](evidence/2026-08-23-safe-order-execution.md)
- [`evidence/2026-08-23-usb-reverse-tether.md`](evidence/2026-08-23-usb-reverse-tether.md)
- [`evidence/2026-08-24-dogfood-test-lane-activation-probe.md`](evidence/2026-08-24-dogfood-test-lane-activation-probe.md)
- [`evidence/2026-08-24-init-agent-activation-host-contract.json`](evidence/2026-08-24-init-agent-activation-host-contract.json)
- [`evidence/2026-08-24-init-agent-activation-host-contract.md`](evidence/2026-08-24-init-agent-activation-host-contract.md)
- [`evidence/2026-08-24-init-agent-observer-live.md`](evidence/2026-08-24-init-agent-observer-live.md)
- [`evidence/2026-08-24-usb-reverse-tether-recovery.md`](evidence/2026-08-24-usb-reverse-tether-recovery.md)
- [`evidence/2026-08-24-userdebug-dogfood-source-bom.json`](evidence/2026-08-24-userdebug-dogfood-source-bom.json)
- [`evidence/2026-08-26-development-tree-inventory.md`](evidence/2026-08-26-development-tree-inventory.md)

Current component contracts and implementation notes:

- [`../crates/trillionnium-agent-direct-tools/README.md`](../crates/trillionnium-agent-direct-tools/README.md)
  — pre-r2 System API/Accessibility and sealed-broker implementation notes;
  the owner-open plan supersedes its typed/HOLD sections.
- [`../apps/trillionnium-agent-privilege-broker/README.md`](../apps/trillionnium-agent-privilege-broker/README.md)
  — pre-r2 sealed/history Authority foundation; it is not linked or started
  by the owner-open product and is not a raw shell/ADB fallback.

The 25 July 14–28 evidence records were removed from the active source index
after hash-verified custody. They remain recoverable in
`trillionnium-retired-artifacts/2026-08-26/historical-evidence-july-20260826.tar.zst`
(SHA-256 `fe7c33f7482118f9fce154351d10d9745ac3086bdb3a1fe489251f87815580f7`)
and must not be treated as current release evidence.

## Superseded architecture

- The former dual-Agent, typed-only shell/ADB ADR, v1 boundary contract and
  plan/approval/Authority execute/undo design were removed from the active tree
  on 2026-08-26 after hash-verified custody. Their recovery archives are listed
  in `docs/evidence/2026-08-26-development-tree-inventory.md`.
- The May 2026 Mobian/Phosh/Waydroid/Hepta/local-model line was removed from
  the Android aggregation checkout and is likewise custody-only. The three
  manifest-managed Android projects `trillionnium-os/{contracts,schemas,tools}`
  remain because the current AOSP build consumes them.
- The pre-Direct long-form root README remains recoverable from Git as
  `e163970a2d46b6ce1cb722fd7a24f414ddf1108c:trillionnium-os/README.md`; it is
  not duplicated into the active tree.
- Old v20–v26 release snapshots, calibration outputs, retired host/source
  quarantines and the detached Direct source copy are recoverable only under
  `trillionnium-retired-artifacts/2026-08-26/host-estate/`. That directory is
  custody, not a second source tree, and must be excluded from source
  discovery.

No superseded document is a current implementation or release claim. The
canonical plan revision 2026-08-27-r3 is the normative implementation
direction; the 2026-08-06 ADR remains useful historical context.

Do not cite a superseded document, old smoke artifact, package hash, or prior
device observation as proof for the current Android Direct product.
