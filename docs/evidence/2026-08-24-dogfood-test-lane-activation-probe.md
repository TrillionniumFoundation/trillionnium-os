# 2026-08-24 userdebug dogfood activation lane

This record deliberately separates the local test-device lane from the
release lane.  It does not authorize a public release, an OTA, or an effect;
it records the exact dirty source state that may be used for a local
userdebug/dogfood build only.

## Current source identity

- `repo manifest -r --no-local-manifests` completed with 1,172 projects and
  195,467 bytes.
- Resolved-manifest SHA-256:
  `9a0c8be03881096bde3e4413e58429c90f9c11dc06d3a2a5407d1b234828732d`.
- The strict v2 source BOM remains `HOLD_LOCAL_SOURCE_GRAPH`.  Its blockers
  are three ignored-path findings and seven dirty project findings; no
  artifact or manifest-drift blocker was substituted for them.
- The separate host-only snapshot is
  `2026-08-24-userdebug-dogfood-source-bom.json` (SHA-256
  `c5e90a0860bd07b4c12b66cdf075c82e618d9d7a49c408f81b377ed92b3399a6`).
  It is schema `org.trillionnium.userdebug-dogfood-source-bom.v1`, decision
  `PASS_USERDEBUG_DIRTY_DOGFOOD_SNAPSHOT`, and carries
  `device_write_authorized=false`, `effect_authority=false`,
  `release_allowed=false`, and `public_release_allowed=false`.

The dogfood materializer requires an explicit
`--allow-dirty-userdebug-dogfood` switch, validates the real resolver output,
and uses exclusive publication.  It does not weaken the canonical release
BOM or receipt verifier.

## Host conformance

- `device_launch_package_conformance_replay_sync`: 14/14 passed with the
  userdebug conformance feature.
- Full direct-tools conformance group: 23/23 passed.
- Focused current-target replay/ACK tests passed, including sealed-proof ACK
  publication, response-loss recovery, replay idempotence, compaction and
  restart readback, fixed-settings System API routing, and terminal-crash
  recovery.
- Dogfood BOM fixtures: 10/10; Python compilation and source-only Android
  adbd-root contract: 2/2.

## Explicit source opt-in

The fogos product now has an explicit `TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT`
opt-in.  The common policy still sets
`PRODUCT_NOT_DEBUGGABLE_IN_USERDEBUG := true` unless that product-level
userdebug switch is present; user/release variants are not changed.  The
source-only contract test prevents the switch from becoming a global policy
or an Android shell/effect bypass.

## Device and network observation

- Device `ZY32JLVHGN` remains `device`; `wlan0=192.168.0.10/24`,
  `tun0=10.0.0.2/32`, host `192.168.0.4`; Gnirehtet reverse-tether remains
  online and ADB server must stay running for the relay.
- Read-only state is `ro.debuggable=0`, `ro.build.type=userdebug`,
  `sys.boot_completed=1`, slot `_a`.
- The installed image predates the opt-in source change.  `adb root` is
  therefore rejected by adbd and a shell property write is denied.  No
  privilege escalation, SELinux bypass, install, reboot, effect, ACK, or
  journal mutation was attempted.

## Remaining mechanical blocker

A new `trillionnium_fogos-bp4a-userdebug` target-files/OTA build was started
in a separate output directory, but the canonical USB disk entered sustained
`usb-storage`/`jbd2` D-state I/O.  The bounded build attempt was stopped; no
partial image was treated as a product.  The next device action is therefore
still: resume the exact current-source userdebug build, verify its target-files
and OTA hashes, then install it through the existing dogfood updater path and
observe init-owned activation.  The historical 2026-08-14 OTA remains a
fixture only and is not used as evidence for current-source closure.
