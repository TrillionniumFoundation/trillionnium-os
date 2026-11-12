# Prepared v54 upgrade, single attempt

This is a local script draft for the exact, original-signer v51 → v54 upgrade. It has **not been run against a phone**. Preparing or importing it does not contact H, start ADB, install a package, or launch an app. The fake-I/O tests use a local dictionary in place of the phone and a fake lease in place of the kernel lease.

The signed assembly was not confirmed when drafting began. The parent task has since reported its actual successful receipt and APK values below. The script retains **no default target APK digest, APK size, assembly-result digest, or runtime-config digest**: all are compulsory runtime inputs, and the actual files are independently rechecked. A configuration digest still requires the exact current-baseline byte copy. Do not substitute a guessed or example value.

| Newly reported signed artifact | Exact value (not an installation result) |
|---|---|
| Assembly receipt | `/home/alex/hepta-v54-a356-20261111-r1/assembly-r1/RESULT.json`, 5,047 bytes |
| Receipt SHA-256 | `6739dc861c1207d2c7a35e9584893daa03c583d2eb9e33b1d9621524bff69143` |
| APK | `/home/alex/hepta-v54-a356-20261111-r1/out/hepta-local-0.54.0.apk`, 20,879,187 bytes |
| APK SHA-256 | `d16f1aae63152497288729547f7ef81a66b9ba7cfde8e5203c82d293aaae6b7c` |

These values were supplied by the parent task from the successful assembly receipt; this draft's author has not issued H requests or phone commands to obtain them. The original lock was still reported busy, so they are not authorization to bypass that lease.

## Fixed code and baseline

The script only loads `background_notes_v54_acceptance.py` if its exact SHA-256 is:

`604f72e2654b777adc4a2a5b079dfcf455873f42681ee780a597994b2fbd86ae`

It compiles those just-read bytes, without a mutable path import or bytecode cache, then calls the pinned `verify_source`, `load_helpers`, and `verify_candidate`. Those functions bind the full 1,362-member manifest, the 186 compiler inputs, actual build identity, Mac build receipt, exact DEX, the 17 native libraries, and the successful original-signer assembly receipt. The installer also runs the supplied host `apksigner` and `aapt2` against its private staged APK and checks the actual signature, package, version and empty permission list. It records the host executable hashes. These SDK tools and their own runtime dependencies are part of the trusted host environment; this draft does not install or replace them.

The accepted installed baseline is fixed to the parent task's explicit, previously observed identity:

| Field | Required value |
|---|---|
| Package | `org.trillionnium.hepta.local` |
| Installed version code | `51` |
| Installed version name | `0.51.0-local-notes-workflow` |
| Installed APK SHA-256 | `e34775cd587ae1a68a04805dbdd42efd9a389cae21b11c83558d3a1306ec4313` |
| UID / `run-as` UID | `10481` |
| Android user | `0` |
| Target version | `54`, `0.54.0-local-unified-observation` |
| Target signer SHA-256 | `202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5` |
| Target DEX SHA-256 | `77b8e3dd6d727f713617c77ca258bc7dfac91fa86a368f4447ca8070da31ac90` |

An unknown v52/v53/v54, a different v51 APK, a split APK installation, an altered UID, or inaccessible identity causes refusal. No branch-name assumption can override these checks. Remote GitHub history does not establish the absence of private host/device changes.

The prior formal v51 assembly is `/home/alex/hepta-local-007f-20261111/v51-build-r2/assembly-r1/RESULT.json`, SHA-256 `e96ba5683322ef8d113cb14fde7580d42441e360da2c0547c813d302dadc3d01`; this is also the baseline receipt pinned by the v54 assembler. The parent task reported an actual installed v51/version-name/UID/APK-hash check around **2026-11-11 23:44 UTC**. That historical observation is separate from this installer's mandatory fresh read of the actual installed hash. The four native-inference receipts are not used as APK provenance.

## Required inputs

The CLI has only the explicit `install-once` mode. There is no automatic install, retry, downgrade, permission grant, recovery, or cleanup mode. The following arguments are mandatory; obtain their concrete values from the reviewed assembly and current baseline evidence before any execution:

| Arguments | Meaning |
|---|---|
| `--harness`, `--source` | Absolute paths to the SHA-pinned harness and complete frozen controller source. |
| `--assembly-result`, `--assembly-result-sha256` | Actual successful signed-assembly `RESULT.json` and its reviewed digest. `all_pass` must be the JSON boolean `true`. |
| `--apk`, `--apk-sha256`, `--apk-bytes` | Actual signed APK path, digest and byte count, identical to the assembly receipt. |
| `--certificate-sha256`, `--dex-sha256` | Explicit actual values; they must also equal the fixed reviewed pins above. |
| `--runtime-config`, `--runtime-config-sha256` | Existing host copy of the current private configuration, including its exact original whitespace/bytes. The phone copy must match exactly. |
| `--apksigner`, `--aapt2`, `--adb` | Absolute non-symlink paths to existing host executables. |
| `--adb-host`, `--adb-port`, `--serial` | Explicit intended ADB server and device. |
| `--out` | New absolute private output directory; its parent must already exist. Existing output directories are refused. |

Configuration must remain the reviewed LFM3 local NPU profile, 8,192 context tokens and 4 threads (including the supported v1 representation). The script does not write configuration or change models. Defaults are an 8-second read-command timeout and a 180-second install-client timeout; both have enforced upper bounds.

## Lease, preflight and single submission

The exact pinned `v35_identity.operation_lock` opens the already-existing `/home/alex/.local/state/hepta/razr-operation.lock` read-only, acquires its nonblocking exclusive kernel lease, and checks file identity continuity. The installer does not create, replace or reacquire this lock. All read-only phone commands go through its `guard_adb`; the one direct install subprocess has an additional explicit `require_operation_lock` immediately before invocation.

After acquiring that lease and before any ADB construction/contact, the installer also requires its recorded held inode to equal **58890228**, the original lock independently reported by the parent task at 00:44:35 and 01:15:36 UTC on 2026-11-12. A different inode is refused even at the same path. This check reads the existing helper's lease report; it does not open or introduce another lock.

A busy lock refuses immediately at the phone phase, before ADB construction or any ADB command. Host-only artifact verification may already have produced private evidence; it has not contacted the phone. There is no wait loop or automatic retry.

Two preflight passes verify the exact known v51 installation, unchanged configuration bytes, clean terminal or absent control/diagnostic/permission sessions, no pending/running task, no interrupted or uncommitted journals, no qualification scope, no recovery-pending barrier, no live Hepta native worker/broker, and no Hepta background display. Permission history is accepted only with a matching archived terminal receipt; reading it does not verify current root authorization or run a root probe. Administrative recovery states and unknown schemas are conservatively refused rather than repaired. The two passes must agree on package identity and the relevant private journal digests.

After all checks, under the original lease, the script creates a durable, exclusive host receipt at:

`/home/alex/.local/state/hepta/razr-v54-upgrade-attempt.json`

This is a consumed-attempt journal, **not another lock**. The original helper fsyncs both file and parent directory. Any existing path at that location refuses a later invocation before phone contact, even when a previous attempt timed out or appeared to leave v51 installed. There is no reset, delete or override option. This deliberately requires separate read-only reconciliation after an ambiguous result rather than a second installer invocation.

The only device mutation is exactly one argv of the form `adb … install -r <verified-staged.apk>`. There is no `-d`, uninstall, runtime permission grant, app launch, Notes input, settings edit, model change, direct broker invocation, root grant modification, PID kill, or automatic acceptance run. Installation itself may cause ordinary Android package/service lifecycle behavior; the script does not claim that Android will leave a bound service process untouched.

The lease only coordinates host operators using that original lock. It cannot freeze a user pressing the Start button or another actor ignoring the lease. The preflight samples are read-only observations, not an atomic UI freeze. A remaining interval exists between the final observations and Android receiving the install. No stronger guarantee is claimed.

## Outcome and next step

After the one submission attempt, the script reads actual installed package identity and configuration once, including when the client timed out, returned failure, or was interrupted. It never replays installation. A changed UID or unexpected installed version is retained in the report when readable. Successful `all_pass` requires a successful install-client response, actual target APK/version/UID, exactly preserved config, acceptable private terminal state, evidence publication, and verified original-lock release/continuity. A timeout followed by an observed v54 is reported as observed v54 with `all_pass: false`, not silently promoted into confirmed installation.

If ADB reads fail, the outcome remains unknown. SIGKILL, host power loss, or a severed connection may prevent any immediate reconciliation; the consumed-attempt receipt remains the no-replay barrier. The script neither resumes the command nor rolls back. Evidence lives in the private output directory and may contain app-private/system output from the guarded readers; do not publish those raw files.

The original lease is released in `finally`. A later acceptance harness must acquire a fresh original lease independently. An installation report is **not** a phone qualification result, background-agent pass, or full shopping/flight/Notes test. The script always labels `phone_qualified` and `background_agent_qualified` false.

## Local verification only

`v54_upgrade_once_fake_tests.py` exercises success, busy original lock and changed inode with zero ADB commands, changed baseline/UID/unknown versions, active or malformed sessions, recovery and qualification barriers, live workers/displays, config races, actual-state reconciliation after timeout/nonzero result, preserved config, lost lease, modified staged inputs, consumed-attempt refusal, permission-receipt binding, and rejection of an unreviewed harness. It intentionally does not execute a real ADB binary, original kernel lock, APK signer, Android package manager, or the installer CLI. An explicit fuse rejects any real `subprocess.run` reached by those fake tests.

The harness's existing source/candidate verification is reused rather than replaced by a parallel verifier. Host fake-I/O success does not establish that an actual signed assembly exists, that the current phone still matches v51, or that an installation/acceptance test has happened.
