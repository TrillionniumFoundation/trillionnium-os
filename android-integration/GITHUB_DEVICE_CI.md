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
`/data/toshiba-dev/TrillionniumOS/.android-ci-runs/<run-id>-<attempt>/control`, so the
control source, Android checkout, `OUT_DIR`, ccache, temporary files, APKs,
receipts, and logs stay on the canonical external filesystem. The job fails if
that path is not backed by UUID
`63df6e1a-baf3-4680-8bbb-8019fb025341`. The normal runner `_work` directory is
not a source or build directory; on the configured desktop it resolves to
`/data/toshiba-dev/TrillionniumOS/actions-runner-desktop-work`. The workflow
also checks `GITHUB_WORKSPACE`, `RUNNER_WORKSPACE`, `RUNNER_TEMP`, and
`RUNNER_TOOL_CACHE` before creating the control checkout, and checks the
400-GiB floor before creating
any run directory or cloning source. The runner binaries and service diagnostics
remain host infrastructure on the system disk; project data does not.

## Build and source contract

`tools/android_ci_desktop_build.py` holds one exclusive external lock for the
whole transaction. Before any copy it checks:

- the exact Git commit and tree cloned by the workflow;
- the frozen `trillionnium-fogos.xml` SHA-256 and its 1,172 project entries;
- every overlay file in `PROJECT_STATUS.tsv`, including its SHA-256 and the
  five declared project HEADs;
- absence of undeclared dirty files in those declared overlay projects;
- the external mount and a 400-GiB free-space floor; and
- absence of another Android `ninja`/Soong build.

A read-only device preflight is completed before any Android overlay file is
materialized. If the approved handset is absent or has the wrong product/build,
the transaction stops without changing the checkout.

The checked-in `android-integration/working-tree` overlay is then copied to the
canonical Android tree. Existing files are backed up below the run directory;
no automatic cleanup or destructive reset is performed. A post-copy status and
digest check must pass before the build starts.

The frozen manifest hash and project count are checked, but this lane does not
re-clone or independently re-attest all 1,172 base Git projects on every run.
The remaining base projects are a pre-provisioned external input; a full
all-project dirty-tree attestation is a separate, slower qualification step.

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
shell command. A read-only device preflight runs before the build so a missing
or wrong handset fails fast; it is repeated immediately before installation.
Because Authority, CapabilityLeaseIssuer, and Accessibility
are system-ext applications, an install failure is reported rather than being
worked around with a remount or image write.

This is a deterministic APK install/launcher function smoke (the checked-in
`*SecurityContractTest` targets are host-test build inputs; they are not
instrumentation runs). It is not proof of a new system image. Changes
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
disk is replaced; it will not delete old outputs automatically. The 400-GiB
gate is a minimum safety floor, not a guarantee that a clean build fits: the
existing checkout and `out` already consume roughly 724 GiB, so additional
headroom is required.

The ccache is persistent, bounded at 64 GiB, and stored at
`/data/toshiba-dev/TrillionniumOS/.android-ci-ccache`; it is not put on the
system disk and is not uploaded as an artifact. Re-runs use a distinct
`<run-id>-<attempt>` receipt directory and artifact name. The runner binaries
and system logs remain host infrastructure; the project checkout, build
outputs, cache, temporary files, and receipts are the data guaranteed to stay
on the external mount.

The configured service drop-in
[`desktop-runner-external-disk.conf`](desktop-runner-external-disk.conf) adds
`RequiresMountsFor`/`BindsTo` for the canonical mount and uses
`KillMode=control-group`; therefore the listener and its workers stop if the
removable disk disappears. Keep the equivalent drop-in installed when
re-registering the runner.

The prior package-only/read-only workflow was intentionally replaced. It is
not valid evidence of a newly built APK and must not be reintroduced with the
generic `real-device` selector.
