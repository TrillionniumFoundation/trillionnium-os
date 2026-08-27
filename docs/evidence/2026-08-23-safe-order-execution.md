# Safe-order execution record (2026-08-23)

This record covers the requested continuation from the canonical external
checkout. It is host/source evidence only. No private-key contents were read,
no device input or shell command was sent, and no install, flash, reboot or
power-loss action was performed.

## Canonical inputs and dirty-tree rule

- source checkout: `p0-agent-native-integration-20260731/trillionnium-os`
- Android OUT: `out/target/trillionnium-userdebug-v28-standard-relative-20260814.9YHOOi`
- source HEAD observed: `7cba499c46fb8f28cb94aea5b5e41c28420995e5`
- all pre-existing tracked and untracked changes were retained; no commit or
  destructive reset was performed

## Ordered source/host work

1. The allocator now retains a borrowed, non-serializable
   `VerifiedAllocatorCommitForAndroidAck` proof. It rechecks the durable
   `AdapterPrepared` record and binds the exact receipt, provider attempt,
   adapter ordinal, journal sequence, canonical request and backend-request
   digests before an ACK/replay correlation can be accepted.
2. The Android evidence-shape gate requires a future `user`/`release-keys`
   target, non-empty OTA keys, issuer/consumer lineage, KeyMint/Verified-Boot
   and rollback evidence, and exact Accessibility protocol/domain/replay/ACK
   evidence. It contains no private-key field and cannot mint effect
   authority. Product flags remain false.
3. The ADB boundary now rejects a completed result without an explicit exit
   code and refuses key-generation rotation away from OS-owned custody. The
   release verifier rejects parent symlinks, AVB argument sets without
   rollback indices and unexpected rollback-evidence partitions.

## Regression results

- `cargo test -p trillionnium-os-types --lib`: **197 passed**
- `cargo test -p trillionniumd --bin trillionniumd direct_tool_call_allocator
  --no-default-features`: **23 passed**
- `cargo test -p trillionnium-agent-direct-tools --lib --no-default-features`:
  **283 passed**
- ADB boundary focus: **12 passed**
- Android release-gate Python suite: **13 passed**
- signing/OTA policy fixtures (`test_android_release_ota.py`): **39 passed,
  1 skipped** (the skipped case requires an explicitly supplied Android source
  root)
- `cargo check -p trillionnium-agent-direct-tools
  --features production-durable-hotpath`: **pass** (warnings only; product
  authority flags remain closed)
- `rustfmt --check`, `py_compile`, and `git diff --check`: **pass**

## Release/device HOLD evidence

The current target-files ZIP is present, but its metadata is not release
eligible:

- `META/misc_info.txt`: `build_type=userdebug`, AVB rollback index `28`, and
  AOSP test-key AVB paths;
- `SYSTEM/build.prop`: `ro.build.type=userdebug`,
  `ro.build.tags=test-keys`, fingerprint ending `userdebug/test-keys`;
- `META/otakeys.txt`: one byte (newline only);
- capability-lease trust config: `enabled=false`, verifier/pins/rollback all
  `HOLD`;
- capability-lease issuer and KeyMint evidence APK entries are signed with
  `testkey.x509.pem`/`testkey.pk8`;
- no production KeyMint attestation, hardware rollback high-water proof,
  measured Accessibility ownership/replay/ACK closure, signed metadata or
  detached rollback evidence is present.

The release verifier's fixture suite proves the gate's fail-closed behavior.
A full digest scan of the 3.3-GB external target ZIP was attempted but hit the
external-disk I/O timeout; this does not weaken the HOLD because the extracted
metadata already fails the gate and the required detached evidence is absent.

The USB device was observed by `adb devices -l` only to confirm presence; the
host ADB server was stopped immediately afterward. The OS-held-key transport
has no production constructor, so no real ADB session was attempted.

## Next unlock conditions

Do not start signing, OTA generation or flashing until the OS-owned allocator
listener/provider delivery, real KeyMint/rollback evidence, measured
Accessibility adapter and OS-held-key ADB transport exist. Then rebuild from a
new exact-clean source/BOM, produce `user`/`release-keys` artifacts and signed
OTA/rollback documents, rerun the release gate to `ELIGIBLE`, and only then
collect device Root Linux/direct-host/shell-broker/reboot/power-loss replay
evidence. Windows remains deferred.
