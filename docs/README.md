# Trillionnium OS documentation

This index separates current product truth, active implementation sequencing,
implementation status, supporting evidence and retained history.

## Active owner-open documents

1. [`TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md`](TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md)
   — the only active implementation sequencing and closeout plan. It defines
   W0-W9, status/evidence levels, file ownership, acceptance gates, immediate
   batches and the owner-open definition of done.
2. [`contracts/codex-sovereign-direct-tools-v1.json`](contracts/codex-sovereign-direct-tools-v1.json)
   — the normative r3 product/protocol semantics: one Codex semantic control
   plane, direct shell/ADB, mechanism-only substrate and honest uncertainty.
3. [`status/owner-open-r4-status.json`](status/owner-open-r4-status.json)
   — machine-readable implementation status. This is authoritative for r4
   progress and claims; a source test may not promote a capability to device or
   release status.
4. [`status/owner-open-r4-traceability.tsv`](status/owner-open-r4-traceability.tsv)
   — requirement-to-plan/source/test/evidence mapping.
5. [`protocols/owner-open-direct-agent-host-v1.md`](protocols/owner-open-direct-agent-host-v1.md)
   — first implementable connection/frame/turn/tool/shell/ADB protocol subset.
6. [`security/owner-open-threat-model.md`](security/owner-open-threat-model.md)
   — trust boundaries, accepted dogfood risk, required mechanical mitigations
   and residual-risk statement.
7. [`contracts/owner-open-forbidden-default-graph-v1.json`](contracts/owner-open-forbidden-default-graph-v1.json)
   — negative Cargo/Android product-graph contract.
8. [`TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
   — r3 semantic architecture baseline. Its sequencing/status sections are
   superseded by r4, but its owner-open product decisions remain normative.
9. [`CURRENT_STATE.md`](CURRENT_STATE.md)
   — long-form implementation/release observations, including pre-r3 history.
   Product or release claim changes must update it; routine r4 task progress is
   represented first in the machine status.

A change that alters protocol semantics must update the r3 machine contract or
an explicit ADR. A change that alters implementation order, status or evidence
must update the r4 plan/status/traceability package in the same pull request.
Generated codec output must remain policy-free.

## Architecture and audit entry points

- [`architecture/2026-08-06-codex-native-direct-shell-adb.md`](architecture/2026-08-06-codex-native-direct-shell-adb.md)
  — historical ADR amended by the r3 owner-open decision.
- [`audits/2026-08-06-ai-agent-native-os-full-audit.md`](audits/2026-08-06-ai-agent-native-os-full-audit.md)
  — repository/history/device audit, architecture grading, cleanup inventory
  and remediation order.
- [`contracts/agent-exec-adb-windows-product-boundary-v2.json`](contracts/agent-exec-adb-windows-product-boundary-v2.json)
  — transition record. Its semantic approval/allowlist fields do not govern the
  owner-open path.

## r4 foundation implementation

- [`../apps/trillionnium-owner-open-host/`](../apps/trillionnium-owner-open-host/)
  — isolated default executable root with strict stdio/file-UDS framing, one
  synchronous turn lineage per connection, provider-event normalization and an
  honest unavailable-provider default. It is not yet the Android integrated
  Host and does not keep control frames serviceable during a live provider.
- [`../crates/trillionnium-owner-open-types/`](../crates/trillionnium-owner-open-types/)
  — isolated codec/mechanical-validation crate. It deliberately has no
  dependency on broad legacy OS types, policy, privilege, shell broker or
  direct-tools crates.
- [`../schemas/codex-sovereign-direct-tools.schema.json`](../schemas/codex-sovereign-direct-tools.schema.json)
  — extensible JSON codec schema; not an allow/deny validator.
- [`../tools/generate-owner-open-types.py`](../tools/generate-owner-open-types.py)
  — codec-only constant generator from the semantic contract.
- [`../tools/verify-owner-open-foundation.py`](../tools/verify-owner-open-foundation.py)
  — default graph, generated output, status and known Android hold verifier.

The foundation provides L0/L1 source/unit coverage and a spawned Host-process
JSONL test for L2 evidence once CI passes. It does not claim a live Codex turn,
direct shell runtime, raw ADB transport, Android image or device effect.

## Supporting implementation contracts and checkpoint evidence

The entries below are bounded source/checkpoint records. They are not a
substitute for the live same-turn and fault evidence required by r4.

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
  r3/r4 supersede its typed/HOLD sequencing for owner-open.
- [`../apps/trillionnium-agent-privilege-broker/README.md`](../apps/trillionnium-agent-privilege-broker/README.md)
  — sealed/history Authority foundation. It is not an owner-open product root
  or raw shell/ADB fallback.

The 25 July 14–28 evidence records were removed from the active source index
after hash-verified custody. They remain recoverable in
`trillionnium-retired-artifacts/2026-08-26/historical-evidence-july-20260826.tar.zst`
(SHA-256 `fe7c33f7482118f9fce154351d10d9745ac3086bdb3a1fe489251f87815580f7`)
and must not be treated as current release evidence.

## Superseded architecture

- The former dual-Agent, typed-only shell/ADB ADR, v1 boundary contract and
  plan/approval/Authority execute/undo design were removed from the active tree
  after hash-verified custody. They are not owner-open implementation inputs.
- The May 2026 Mobian/Phosh/Waydroid/Hepta/local-model line was removed from the
  Android aggregation checkout and remains custody-only.
- Old v20–v26 release snapshots, calibration outputs, retired host/source
  quarantines and detached Direct copies are recovery records, not a second
  source tree.
- The current Android `working-tree/` is an audit overlay over a repo-manifest
  checkout. It is evidence of uncommitted integration state, not a clean build
  or product claim.

No superseded document, package hash, static source receipt or prior device
observation proves the current owner-open product. r3 defines the semantics; r4
defines what must now be implemented and evidenced.
