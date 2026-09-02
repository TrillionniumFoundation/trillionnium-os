# GitHub package → local Android device CI

The workflow at `.github/workflows/android-remote-package-device.yml` is the
supported path for development that is hosted on GitHub and checked against a
physical Android device attached to the self-hosted runner.

## What the workflow does

1. A GitHub-hosted job checks out the exact triggering commit and refuses a
   dirty checkout.
2. `tools/android_ci_source_package.py` creates a `git archive` containing all
   tracked files in this repository, plus a strict manifest and SHA-256
   sidecar. The manifest says explicitly that this is a control-repository
   source package, not an Android checkout or a built image.
3. A self-hosted job is admitted only after the package has been downloaded and
   its repository, commit, tree, size, digest, sidecar and tar member set have
   been verified. It then runs the fixed, read-only ADB vocabulary in
   `tools/android_ci_device_smoke.py`.
4. The device job uploads a bounded JSON receipt. The receipt's claim ceiling
   is package integrity and device connectivity/environment; it does **not**
   claim that the packaged source was compiled, installed, flashed, or tested
   as a newly built APK.

The device job uses the runner group `trillionnium-real-devices` and labels
`self-hosted`, `linux`, `x64`, `real-device`. The old
`owner-open-r5-l2` label is intentionally not used: it is absent from the
current runner and causes an indefinitely queued job.

## One-time repository setup

Set a repository Variable containing the exact USB serial that this workflow
is allowed to address. Do not put a serial in a workflow command or accept a
serial from an untrusted pull request.

```sh
gh variable set TRILLINNIUM_DEVICE_SERIAL \
  --repo TrillionniumFoundation/trillionnium-os \
  --body ZY32JLVHGN
```

The default ADB path is `/opt/android-sdk/platform-tools/adb`. If the runner
uses another fixed executable, set `TRILLINNIUM_ADB_PATH` to an absolute,
non-symlink executable path. The `android-real-device` environment should be
configured with required reviewers before enabling automatic runs on a
protected `main` branch.

The workflow has no `pull_request` or `pull_request_target` trigger. A
maintainer can use **Run workflow** for a trusted branch; `main` runs
automatically. This boundary is important because the repository is public and
self-hosted jobs execute on a persistent machine.

## Local runner contract

The runner host must provide:

- the `real-device` label in the `trillionnium-real-devices` group;
- an executable ordinary `adb` client;
- the allowlisted device in `device` state; and
- no requirement for `sudo`, `adb root`, USB flashing, or a reboot.

The smoke helper samples `get-state`, reads a small fixed set of properties,
checks SELinux mode and shell UID, and checks the expected package paths. It
never calls `adb install`, `push`, `root`, `reboot`, `shell setprop`,
`fastboot`, or any service/activity mutation. A failing check still produces a
receipt when the helper reached the output step, and the job remains failed.

## Why this is not yet a full remote Android build

`android-integration/` contains a pinned repo-manifest and the Trillionnium
overlay; it does not contain the roughly 1,172 independent LineageOS projects.
The complete local Android checkout is hundreds of gigabytes. A normal
GitHub-hosted runner and standard artifact storage are therefore not a viable
place to archive or transfer the whole tree. A target-files archive is also
multi-gigabyte and is not a suitable ordinary GitHub artifact for this repo.

To test newly built code, add a separately provisioned, trusted Android
builder (a large-disk runner or an external object-storage-backed build
service). That builder must consume the pinned manifest and overlay, emit an
APK/target-files artifact with its own source/tree/tool digests, and expose a
workflow-call or run-ID artifact contract. The existing device job is the
consumer boundary for that future artifact; it must remain behind the same
environment approval and must add an explicit, separately reviewed install
operation. Until that contract exists, this workflow deliberately performs no
install or image mutation.
