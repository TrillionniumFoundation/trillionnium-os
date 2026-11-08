# Init-owned local NPU provider candidate

This directory builds the missing init-owned launch path for the phone-local provider. It does not grant a new execution identity to ordinary shell or Magisk callers, change the r6 caller check, or replace the original bootstrap's two-child readiness algorithm.

## Current state and exact limits

The following work is complete:

- The production ARM64 entry is built from `provider_entry.cpp` revision recorded in `build-r3/BUILD-MANIFEST.json`. It checks real PID 1 parentage, the bootstrap SELinux domain, exact capabilities, immutable Python, the original rootfs/state mounts, three staging views, source/config hashes and preserved claims before its single exec.
- The original active `init_boot_a` has two independently hash-verified copies, on pocket4 and Mac. Its complete 8,388,608-byte SHA-256 is `ff159c91e06c34b0611ed5b071575dded3955e62f263fb5fec7d96b42c19436f`. An ordinary-file unpack/repack with the phone's pinned Magisk tool reproduced the image byte for byte. No partition was written.
- The generators for a fresh staging directory, final configuration, read-only runtime copy, source closure, additional init service and one-member CPIO modification exist and have scoped host tests. The new health-r5 checks are reported separately from the earlier 35-test startup snapshot.
- The first static artifact candidate is retained. Its immutable model files can be reused, so the final runtime update needs 52 library files and two small executables rather than another model copy.

The final private health/layout source closure, actual new staging inode observation, complete generated startup bundle and modified init-boot image have **not** yet been materialized. The remote connector is unavailable. The latest init-owned entry, actual UID/GID 2000 phone-worker NPU access, listener readiness and real App operations have not run. Root-domain model success does not establish those qualifications.

Current USB bootloader enumeration and a tested fastboot recovery channel are also unverified. The existing image backups and ordinary-file roundtrip alone do not establish that a failed boot could be recovered over the present USB topology.

## Why a new early init entry is needed

The observed original bootstrap service is a fixed init-owned executable with fixed `--run-mounted` arguments. It has no reviewed hook to launch this provider as a same-domain child. The existing sidecar accepts execution only from the bootstrap domain; Magisk is allowed to inspect/health-check it but cannot issue execute requests. The new service therefore preserves this boundary by starting the new C++ entry directly from init in the existing bootstrap domain.

The additional service is `disabled` and `oneshot`. It carries exactly `CHOWN DAC_OVERRIDE KILL SYS_CHROOT`, uses a private mount namespace inherited at start, and stops when the original stop property is asserted or the original bootstrap stops. It does not auto-start at boot. The original service and all original ramdisk entries remain unchanged.

Putting a new rc file in an ordinary late Magisk system overlay is not a proven early-init loader on this device. The concrete candidate uses one new `overlay.d` ramdisk member. In the topology actually inspected, this requires an updated init-boot image and a reboot before init can know the service. No `runcon`, live init replacement or caller-check relaxation is an alternative in this candidate.

## Materialization order

All generated private files stay with the device's existing operational files. Public reports contain source/artifact hashes and scoped results, not the private provider bindings or App catalogue.

1. **Close the new provider source.** Run `broker/apply_provider_overlay.py` against the retained private r9 base into a new output directory. The closure must include `startup_health.py`, the actual layout-r4 backend logic, the R3 core/VLM profile, the Python schema compiler and daily's updated `PARENTS`. Run the full original r6 host suite, new startup cases, selected private parser flows and original private regression on those exact bytes. Preserve old R3/R4 reports with their original hashes.
2. **Prepare only new immutable artifacts.** `prepare_final_artifacts.py` verifies the retained artifact manifest and the exact R3 runtime manifest. It renders a create-only copy script for 52 libraries plus the frozen worker/counter, reusing 24 verified read-only model files. It verifies source and destination bytes and root ownership, directories `0755`, libraries/data `0644`, and the two executables `0755`. Original artifact trees are not rewritten.
3. **Create a fresh inverse stage while stopped.** Use `staging.provision_script(instance)` once with a new 32-hex instance. It checks the observed stop/claims hashes, original state permissions, SELinux enforcing, old bootstrap stopped and the real init mount namespace, then exclusively creates the new private candidate and two UID/GID 2000 `0700` directories. A partial result is reconciled at that identity; it is never deleted and retried blindly. Parse the actual output with `parse_provision_output`; a made-up inode is rejected.
4. **Build the private bundle.** `build_startup_bundle.py` consumes the actual stage observation, exact source manifest, preserved old configuration/base hash, artifact manifest, selected tokenizer bytes, immutable rootfs manifest, production entry build and the pinned original r9 native policy. Its CLI requires every input and expected source/config digest. It emits a complete private payload, exact `--geniex-config` path, source/launch plans, dedicated labeling/bind scripts, module directory, additional init rc, and a manifest of all emitted bytes and modes. Use `--mode serve` for the final qualification instance.
5. **Build the modified image as an ordinary file.** `build_init_boot_candidate.py` consumes that exact generated bundle and the verified original image/CPIO. It preserves every original record byte and adds only the new service member, repacks with the pinned tool, re-unpacks for equality checks, and rechecks that the active partition remains the original hash. It cannot flash, reboot or start a service. Preserve its complete original/modified member and image manifests.
6. **Review the concrete installation and recovery package.** It must contain the exact original and candidate full-image hashes, both verified backup locations, actual active-slot observation, the final source/runtime/plan manifest, additional policy/rc delta and a working physical recovery route. Until those facts are available there is no qualified flash step or final activation claim.

## Staging, capabilities and labels

The stage is an ordinary new directory under the existing state bind. GNU sees it through the original state mapping; Android receives a dedicated `/data/local/tmp` alias bound to the same directory. Neither writable `/run` nor execution from a `noexec` state mount is required. The schema compiler is Python source interpreted by the already pinned immutable interpreter.

The bind script must run only after the original bootstrap is running and its `ready` and `mount_ready` properties are both `1`. These checks bracket the bind operation, so the original post-fs-data restorecon has already completed. It creates a per-boot bind intent, labels only the new source and alias, binds them in init's real mount namespace, remounts `nosuid,nodev,noexec`, and verifies the measured inode and flags. It does not start either provider.

Before the new service starts, the actual r6 executor must see that same Android alias inode. Prove this through the real executor PID/root/mount view and original endpoint/server-instance, or start the unchanged executor only after the bind in the verified namespace. A check of PID 1 or the provider namespace alone cannot establish the executor's view. The original executor journal and any UNKNOWN entries remain in place.

The new provider needs CHOWN to stage request files for UID/GID 2000 and DAC_OVERRIDE to traverse the private shell-owned stage. UID 0 alone is not treated as proof of those capabilities. The entry checks exact effective/permitted masks before and after exec. The worker still runs as UID/GID 2000, with supplementary groups cleared, in the original phone-worker domain.

The policy delta introduces only dedicated stage, artifact data/library/exec types and the provider capabilities above. Stage files stay non-executable. Library execution/read mapping is confined to the new artifact labels. No global permissive mode, group addition, broad shell-data grant or blanket DSP allowance is supplied. Actual FastRPC access is a required runtime gate: the observed nodes allow other-read and the inspected vendor code opens read-only, but that does not prove ioctl/SELinux/PD access for the production worker.

## One serve attempt and pre-listen health

Do not run `preflight_only` and then try to serve the same candidate in the same boot. The entry and post-exec records are create-only for that candidate/boot; preflight also consumes them. The final `serve` path already includes identity/transport preflight, the fixed NPU health request and only then the daily provider handoff.

The startup request asks a fixed arithmetic question, uses no image or owner turn, and goes through the exact selected counter, unchanged r6 supervisor, frozen worker and strict receipt validators. The grammar does not contain the answer. Only the original complete JSON answer `42`, with valid token/formatter/runtime/process evidence and no cancellation, authorizes entering serve. Failure, timeout, SDK error or UNKNOWN prevents listening. No retry is scheduled and no intent is removed.

Before successful health is published, terminating signal handlers are restored and the sticky cancellation/stop/deadline state is checked. A new signal after that point terminates the interpreter normally. Health evidence explicitly says `listener_ready=false`; the later listener and App readiness require independent observations.

The original `owner-authorized emergency stop` file and stop property are real earlier stop state. The user's current repair/install/test request covers necessary reversible preparation, but this candidate has not removed the stop or resumed anything. Once a qualified concrete package and activation sequence are accepted, retain the exact original stop bytes/property observation and claims before a controlled recovery of the new path. Do not erase earlier evidence or revive the retired CPU daemon. Any failed startup returns to a stopped state while keeping its original attempt evidence.

## Failure handling and recovery boundaries

| Point of failure | Required response |
| --- | --- |
| Host source/config/bundle generation | Retain the new failed output and exact inputs; correct in a new candidate. No phone state has changed. |
| Static directory/copy request loses its transport acknowledgement | Inspect the original job and target identity before another mutation. A timeout or `error: closed` does not establish absence. |
| Stage bind or init preflight fails | Preserve the per-boot bind/entry intent. Do not delete it or silently rerun. Diagnose actual inode, mount, label, capability and endpoint facts. |
| Model health has known cleaned-up failure | Do not listen. Preserve the typed startup receipt and original output. A later attempt needs a new legitimate startup context; it is not replay of an accepted user turn. |
| Native cleanup is UNKNOWN | Do not listen, remove claims or execute another request. Inspect only the original action until its real process/receipt state is resolved. |
| Service exits after it has listened | Stop new admission, retain original user claims and task evidence, inspect native completion, and use a reviewed new startup context or a new boot. `oneshot` intentionally does not erase the one-attempt guard or auto-restart. |
| Roll back before using the stage | The emitted unbind script works only with both services stopped, the exact verified alias/source, and an empty stage. It never removes evidence. |
| Roll back after requests exist | Do not force the empty-stage script or delete request directories. Stop the new service, preserve its evidence, disable the new module as part of the reviewed recovery, restore the verified original init-boot through the confirmed recovery channel, and reboot. Bind mounts disappear; retained files/claims remain. |
| Image flash or boot fails / ADB disappears | Use the already verified physical bootloader/recovery route and the complete original `init_boot_a` image. Target only the observed active partition; do not switch slots or overwrite unrelated boot/vbmeta/userdata. That route is currently unverified, so these actions are not yet executable approval steps. |

Before any image write, the final private runbook must replace the last row's missing transport facts with observed device/slot enumeration and exact working recovery commands. After restoration, verify the original image hash, original module/bootstrap/stop state, retained claims and absence of the new service. Restoring boot configuration is not permission to replay a pending phone action.

## Evidence references

`evidence/init-boot-backup-r1/PUBLIC-SUMMARY.json` records the two full backups and ordinary-file roundtrip. `build-r3/BUILD-MANIFEST.json` records the actual Android entry build. `evidence/startup-host-r3/RESULT.json` is the earlier scoped 35-test snapshot. `../broker/evidence/startup-health-r5/VALIDATION.json` records the separate health/layout candidate's exact local gates and remaining remote/native qualifications.
