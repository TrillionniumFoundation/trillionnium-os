# Droidian/Halium Base Pivot

Date: 2026-05-21

## Decision

Use a Droidian/Halium-style Android hardware-adaptation base as the technical
foundation for the phone port. Do not turn the product into a direct LineageOS
fork, and do not adopt Sailfish OS or Ubuntu Touch wholesale.

The target architecture is:

- Motorola/FOGOS Android base as the hardware donor.
- Halium/libhybris-compatible Android HAL sidecar for vendor hardware services.
- Debian/Mobian userspace as the primary OS surface.
- Phosh as the mobile shell.
- `trillionniumd` and Hepta gates as the capability/control layer.
- Existing vendor_boot capsule and USB status channel as the rescue and
  bring-up control plane.
- Razr/foldable-first policy above hardware posture, display, input, power, and
  capability exposure.

## Why This Replaces The Current Micro-Probe Path

The current vendor_boot capsule path proved we can boot the Debian/Mobian userspace
shape, show Phosh, expose USB status, and confirm touch UI response. It is useful
as a rescue/control-plane capsule, but continuing to patch each subsystem in the
initramfs is too slow.

Droidian is already positioned as Debian on Android phones using libhybris and
Halium. Halium's core scope is a minimal Android distribution in an LXC container
that exposes Android HAL interfaces to the host. Sailfish HADK contributes the
right workflow discipline: build or obtain an Android base, verify it works on the
device first, then use that base and its binary drivers as the hardware adaptation
donor.

## What We Keep

- The working Motorola vendor kernel / vendor_boot capsule path.
- USB HTTP status and bring-up receipt discipline.
- The Mobian/Debian rootfs and Phosh session work.
- Touch/display fixes already proven on ZY32JLVHGN.
- Trillionnium packages, `trillionniumd`, Shell, Command Center, and Hepta gates.
- Existing serial-scoped Fastboot safety gates and release-push separation.

## What We Stop Doing

- No more default path of one-off vendor_boot patches for every hardware issue.
- No Android UI/framework fork as the product surface.
- No switch to Lomiri/Ubuntu Touch or Sailfish UI/tooling.
- No release push just because the touch blocker is fixed.

## Donor Stack

Use LineageOS/AOSP/CAF or the closest Motorola stock-derived base as a donor, not
as the user-facing OS. The donor is responsible for the vendor BSP, kernel
configuration, proprietary blobs, Android services, and HAL contracts.

The Debian side owns:

- systemd boot and services
- Phosh/Phoc session
- packaging and update policy
- Trillionnium application and capability layers
- release artifacts and audit receipts

The Android side owns:

- vendor HALs and proprietary services
- binder/hwbinder/vndbinder endpoints
- radio, camera, audio, sensors, GPS, power, fold posture, and other device
  services where native Linux support is not already good enough

## Near-Term Gates

1. `android-base-donor-inventory-smoke`
   - Record the exact Android base candidate: stock Motorola OTA, LineageOS tree,
     kernel source, device tree, vendor blobs, partitions, boot/vendor_boot/dtbo,
     vbmeta policy, Android version, and kernel version.
   - No flashing.

2. `halium-droidian-kernel-config-gap-smoke`
   - Compare current kernel/capsule evidence against Droidian/Halium requirements
     such as devtmpfs, namespaces, modules, USB configfs, binder devices, cgroups,
     LXC prerequisites, and pstore.
   - Emit a patch plan only.

3. `android-hal-sidecar-rootfs-plan-smoke`
   - Define how system/vendor/product/odm images or extracted trees mount into an
     Android sidecar.
   - Define binderfs, property service, ueventd, lxc/container lifecycle, and
     libhybris loader boundaries.
   - No device action.

4. `halium-sidecar-first-boot-smoke`
   - Boot the existing Debian/Mobian primary userspace and start the Android
     sidecar enough to prove `getprop`, binder service discovery, and one harmless
     HAL query through the USB status surface.
   - This is the first point where target-hardware execution may be useful, and it
     still needs explicit authorization.

5. `hardware-subsystem-matrix-smoke`
   - Track display/touch, Wi-Fi, Bluetooth, audio, modem/SIM/data, GPS, sensors,
     fold posture, camera, suspend/resume, charging, thermal, and power buttons.
   - Prefer native Linux paths where already working; use Halium/libhybris for the
     rest.

6. `release-readiness-review`
   - Separate from bring-up.
   - Must include recovery path, rollback, logs, physical interaction checklist,
     and explicit release-push authorization.

## Source References

- Droidian describes itself as Debian for mobile devices, with the goal of running
  Debian on Android phones through libhybris and Halium:
  https://droidian.org/
- Droidian's porting guide says Droidian runs on Halium, Android 9+ devices can
  be ported, and GSI-capable devices often reduce the work to kernel changes:
  https://docs.droidian.org/porting-guide/kernel-compilation/
- Halium's scope is a minimal Android distribution in LXC that provides interfaces
  for a host Linux system to use Android HALs:
  https://docs.halium.org/en/latest/project/Scope.html
- Sailfish HADK's useful part for us is the donor workflow: a GNU/Linux system on
  Android hardware using an existing Android hardware adaptation kernel, Android
  base, binary drivers, hybris patches, and middleware:
  https://hadk.sailfishos.org/overview/
- Sailfish HADK also requires flashing and testing the Android base first so
  hardware defects and base-image problems are not misdiagnosed as Linux-port bugs:
  https://sailfishos.org/content/uploads/2021/02/SailfishOS-HardwareAdaptationDevelopmentKit-4.0.1.2.pdf

## Current Project Reclassification

The existing ZY32JLVHGN vendor_boot capsule is now classified as a working
bring-up and rescue capsule, not the final hardware abstraction strategy.

Touch UI response is confirmed for the currently flashed devnode-rebind artifact,
so the immediate blocker is not touch. The next engineering boundary is to build
the Android-base donor inventory and Halium/Droidian compatibility map, then
bring up an Android HAL sidecar under Debian/Mobian.
