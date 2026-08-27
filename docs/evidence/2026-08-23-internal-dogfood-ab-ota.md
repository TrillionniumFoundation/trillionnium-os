# Internal dogfood A/B OTA record — 2026-08-23

This record covers the explicitly authorized local experimental-phone lane. It is
not a production release record and does not satisfy the production custody,
KeyMint/Verified-Boot attestation, or release-signing gate.

## Artifact

- Device: `ZY32JLVHGN` (`trillionnium_fogos` / `fogos`)
- Host artifact:
  `out/target/trillionnium-userdebug-v28-standard-relative-20260814.9YHOOi/internal-dogfood-ota/trillionnium_fogos-userdebug-testkeys-1786679844-full.zip`
- OTA type: full A/B, `ota-type=AB`, `pre-device=fogos`
- `post-build-incremental=1786679844`
- Size: `1,356,454,975` bytes
- SHA-256: `a993dddefb4d8a909f1d804ac61aaa9a50423347837f2fb4ca131d4d8ed64af5`
- `payload_properties.txt` was kept multiline; the ZIP passed `unzip -tqq`.

The same size and SHA-256 were verified on-device before import. The package was
then imported through the installed privileged `org.trillionnium.updater`
(`UpdatesActivity` → Local update → DocumentsUI → Install), which invokes the
Android `UpdateEngine` A/B API. The shell-domain binder path was not used.

## Device transition

Read-only baseline immediately before install:

- slot: `_b`
- build type/tags: `userdebug` / `test-keys`
- verified boot: `orange`, device state `unlocked`
- boot complete: `1`
- `/data` free: approximately `108,397,368 KiB`

UpdateEngine reported successful payload application, filesystem verification,
all post-install commands, and `waiting to reboot`. The updater performed one
guarded reboot. After boot:

- slot: `_a`
- `sys.boot_completed=1`
- fingerprint:
  `trillionnium/trillionnium_fogos/fogos:16/BP4A.251205.006/eng.qian-q:userdebug/test-keys`
- incremental: `1786679844`
- verified boot remained `orange` / `unlocked` (expected for this dogfood device)
- UpdateEngine log reached `MergeCompleted` for `product_a`, `system_a`,
  `system_ext_a`, and `vendor_a`, then removed update state and completed cleanup.
- `/data` free after boot: approximately `105,769,944 KiB`; no wipe command was
  issued and user data was not intentionally cleared.

The temporary ZIP copies in `/data/local/tmp` and `/sdcard/Download` were removed
after the post-reboot merge/readback. No fastboot command, raw partition command,
private-key read, or second reboot was issued in this lane.
