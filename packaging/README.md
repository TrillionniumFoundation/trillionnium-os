# Packaging boundaries

The active packaging tree supports the Codex-only Android product and its
headless Root Linux runtime. Current source-authority areas are:

- `codex-android/` for the measured Codex launcher boundary;
- `android-release-gate/` for the read-only target-files release/flash
  preflight (it cannot sign or flash);
- `root-linux/` for neutral Root Linux policy inputs;
- `operation-replay-sync-static/` for the replay helper build boundary;
- `provider-post-exec-bootstrap/` for the measured post-exec bootstrap;
- `production-retirement-policy-v1.json` for fail-closed legacy absence.

There is no active alternate distro image, desktop/mobile UI package, bridge
APK, user-session installer, or user-systemd/D-Bus product surface in this
tree. Their exact pre-retirement working-tree bytes are recoverable only from
the external read-only 2026-08-07 retirement archive. That archive is not a
build input, test-discovery root, or release authority.
