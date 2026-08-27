# P0-1 non-product launch-package conformance (superseded)

Status: **SUPERSEDED HISTORICAL CHECKPOINT — NOT CURRENT PRODUCT AUTHORITY**

This file formerly described a dual-provider, userdebug-only
`launch_package(com.android.settings)` custody experiment. That identity model
is retired. Its old commands, hashes, provider matrix and evidence vocabulary
must not be used to build, admit or describe a current Trillionnium image.

Current authority is defined by:

- [`CURRENT_STATE.md`](CURRENT_STATE.md);
- [`architecture/2026-08-06-codex-native-direct-shell-adb.md`](architecture/2026-08-06-codex-native-direct-shell-adb.md);
- [`contracts/agent-exec-adb-windows-product-boundary-v2.json`](contracts/agent-exec-adb-windows-product-boundary-v2.json);
- [`audits/2026-08-06-ai-agent-native-os-full-audit.md`](audits/2026-08-06-ai-agent-native-os-full-audit.md).

The remaining P0-1 source lane is Codex-only and non-product. It keeps a
narrow System API conformance contract, daemon custody shapes and fail-closed
collector tests, but it has no current product effect authority:

- the checked-in common/P01 helpers and daemon must be rebuilt from the
  Codex-only source authority;
- no real Codex-only v3 artifact/receipt set exists in the checked-in trees;
- Android packaging and final SELinux/Soong materialization remain HOLD;
- no physical effect, reboot, response-loss, power-loss or locked-device
  receipt has been collected;
- source JSON or a host test cannot substitute for device evidence.

The collector must continue to reject any retired secondary identity,
secondary provider artifact, mutation authority, synthetic success receipt or
cross-spliced manifest. Its only honest terminal state before real artifacts
and a device run is HOLD.

This tombstone is retained so old links fail safely. Detailed historical text
remains recoverable from Git history and should be moved with the wider P0
evidence archive rather than copied into current architecture documentation.
