# GitHub → desktop external-disk Android build → real-device test

`.github/workflows/android-remote-package-device.yml` is now the single
desktop lane. GitHub supplies the exact protected-`main` commit; the Linux
`desktop` self-hosted runner performs the Android build and the bounded APK
install/function smoke against the approved handset.

## What runs where

The job is admitted only on `main` and uses the runner group
`trillionnium-real-devices` with all four labels `self-hosted`, `linux`, `x64`,
and `desktop`. The `desktop` label is deliberate: the ROG runner is in the
same group but has no Android USB device, and the Mac runner is not a Linux
Android host.

The workflow does **not** use `actions/checkout`. It clones the exact
`GITHUB_SHA` into
`/data/toshiba-dev/TrillionniumOS/.android-ci-runs/<run-id>/control`, so the
control source, Android checkout, `OUT_DIR`, ccache, temporary files, APKs,
receipts, and logs stay on the canonical external filesystem. The job fails if
that path is not backed by UUID
`63df6e1a-baf3-4680-8bbb-8019fb025341`. The normal runner `_work` directory is
not a source or build directory; hosts that require zero project bytes on the
system disk should move the runner work folder to the same external mount
before enabling the workflow.

## Build and source contract

`tools/android_ci_desktop_build.py` holds one exclusive external lock for the
whole transaction. Before any copy it checks:

- the exact Git commit and tree cloned by the workflow;
- the frozen `trillionnium-fogos.xml` SHA-256 and its 1,172 project entries;
- every overlay file in `PROJECT_STATUS.tsv`, including its SHA-256 and project
  HEAD;
- absence of undeclared dirty files in the Android projects;
- the external mount and a 400-GiB free-space floor; and
- absence of another Android `ninja`/Soong build.

The checked-in `android-integration/working-tree` overlay is then copied to the
canonical Android tree. Existing files are backed up below the run directory;
no automatic cleanup or destructive reset is performed. A post-copy status and
digest check must pass before the build starts.

The fixed host command is equivalent to:

```sh
source build/envsetup.sh
lunch trillionnium_fogos-bp4a-userdebug
m -j8 \
  TrillionniumAiShell \
  TrillionniumAiAuthority \
  TrillionniumCapabilityLeaseIssuer \
  TrillionniumAgentAccessibility \
  TrillionniumAiShellAgentProviderSecurityContractTest \
  TrillionniumAiAuthoritySecurityContractsTest \
  TrillionniumCapabilityLeaseIssuerContractTest \
  TrillionniumAgentAccessibilityContractTest \
  target-files-package
```

The resulting target-files ZIP must be a newly refreshed, non-symlink regular
file with a valid ZIP/CRC and the required `META/` metadata. The four APKs are
extracted only from that ZIP, checked with `aapt2`, and verified with
`apksigner`; their package names and SHA-256 values are bound into the build
receipt.

## Device operation boundary

The device phase is behind the `android-real-device` environment, whose
required reviewer must remain enabled. `TRILLINNIUM_DEVICE_SERIAL` is a
repository Variable and must equal the fixed allowlist entry `ZY32JLVHGN`.
The preflight requires `fogos`, `userdebug`, SDK 36, completed boot, and a
usable ADB transport. Commands are always issued as `adb -s ZY32JLVHGN`.

The only write/launch operations in this lane are:

1. `adb install -r -d --no-streaming` for the four APKs extracted from the
   current target-files archive;
2. package-manager readback for each package; and
3. `am force-stop` followed by the fixed exported AiShell activity launch.

The receipt records the APK digest, package paths, device properties, and
bounded before/after logcat. There is no `adb root`, `push`, `remount`,
`setprop`, reboot, fastboot, flash, sideload, OTA, partition, or arbitrary
shell command. Because Authority, CapabilityLeaseIssuer, and Accessibility
are system-ext applications, an install failure is reported rather than being
worked around with a remount or image write.

This is an APK install/launcher smoke, not proof of a new system image. Changes
to framework, APEX, kernel, init, SELinux policy, vendor binaries, or other
system-image inputs require a separately reviewed OTA/image lane and are not
silently represented as APK success.

## One-time host setup

Set the serial variable and keep environment review enabled:

```sh
gh variable set TRILLINNIUM_DEVICE_SERIAL \
  --repo TrillionniumFoundation/trillionnium-os \
  --body ZY32JLVHGN
gh variable set TRILLINNIUM_ADB_PATH \
  --repo TrillionniumFoundation/trillionnium-os \
  --body /opt/android-sdk/platform-tools/adb
```

The desktop runner must be online with the `desktop` label. Before the first
run, drain any manually running Android build and ensure the external disk has
at least 400 GiB free. The current disk has only about 200 GiB free, so the
workflow is expected to fail closed until space is reclaimed or the external
disk is replaced; it will not delete old outputs automatically.

The prior package-only/read-only workflow was intentionally replaced. It is
not valid evidence of a newly built APK and must not be reintroduced with the
generic `real-device` selector.
