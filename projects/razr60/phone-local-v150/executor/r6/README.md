# Phone-local executor r6 RC1

This is a frozen, host-reviewed candidate. It is not installed or qualified on the phone. The Magisk parser and actual SELinux transitions remain independent gates. The unchanged r5 instance and its original journals remain historical evidence.

## Boundary

Native shell.exec runs the reviewed client in the exact bootstrap context. The r6 server requires UID/GID 0 at startup and the exact parent SELinux context, global Enforcing, and NoNewPrivs 0. It accepts execute only from UID 0 plus exact bootstrap SO_PEERSEC. UID 0 in Magisk may only query health or inspect. The client must independently verify the new server context; no fallback endpoint is permitted.

The parent retains its private root journal and forks the same owned process group as r5. It clears supplementary groups and sets all real/effective/saved UID/GID to 2000, then execs the fixed worker entry without another fork. The new entry must transition to the exact worker domain and verify credentials, PID=PGID=SID, parent identity, global Enforcing, and NoNewPrivs 0 before it writes S. It then execs /system/bin/sh in the same PID and worker domain.

The S receipt proves the fixed worker entry and its credentials/context; it does not independently prove a business action or postcondition. Cancellation, output bounds, timeout, durable intent-before-fork and duplicate inspect-only semantics are retained. Cleanup never signals a reaped or lost-wait single PID. A missing worker handshake or incomplete cleanup remains indeterminate and blocks new execution across restart. An inspect lookup returns not_found only for ENOENT.

## Fixed Android placement

- Parent: /data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-sidecar-r6
- Worker: /data/local/tmp/hepta-phone-executor-v150-r6/bin/phone-tool-worker-r6
- Abstract socket: hepta_phone_executor_v150_r6
- Suggested new journal: /data/trillionnium/owner-open/state/phone-local-v150/executor-r6
- Parent context: u:r:trillionnium_owner_open_phone_executor:s0
- Worker context: u:r:trillionnium_owner_open_phone_worker:s0
- Execute caller: u:r:trillionnium_owner_open_bootstrap:s0, UID 0
- Read-only operator: u:r:magisk:s0, UID 0

Start argv is the parent path followed by --state-dir and the new journal path. Do not point r6 at the r5 journal. The worker path is compiled into phone_security.h; a different platform placement requires a separately pinned build.

Both entries need their distinct new *_exec labels. The private journal and the parent stdout/stderr log files need the new executor_data_file label. Do not relabel old state or grant new parent write access to the old state type. The worker receives pipe FDs and has no journal access.

## Policy artifacts and limits

policy/magisk/sepolicy.rule is Magisk 31.1 statement syntax. policy/platform/phone_executor.te is separate TE source syntax. The latter compiled only as a standalone require-backed module; full AOSP platform, neverallow and compatibility inputs were not built. The frozen platform source does not define magisk, so launcher/type integration remains required before any platform-build claim.

The captured device has policycap nnp_nosuid_transition and /data is nosuid. The candidate uses exact parent/worker process2 nosuid_transition rules, keeps NNP 0 and does not remount. Both new domains are explicitly enforcing. Neither gets coredomain, appdomain, netdomain, mlstrustedsubject or an unconfined attribute.

The existing Magisk-modified policy nevertheless grants broad access through the domain attribute, including magisk_file, Magisk FD use and binder calls. Those inherited baseline grants are disclosed, not created by this patch. Magisk 31.1 type creation also adds a new type to all existing roles. The independently generated patched snapshot must be queried for the actual result.

This policy only enables IPC, private journal, lifecycle and the fixed shell. It does not yet authorize the reviewed Android public service interfaces, screenshots or UiAutomation. It cannot establish business or fixed-19 qualification.

## Verification included

- 11 targeted host tests at the final source hash: peer authorization, deny-without-recovery-poisoning, real-ENOENT handling, worker handshake, exact output, timeout/cleanup, duplicate read-only response and restart recovery.
- 9 tests execute the exact final cleanup code with syscall mocks and send no OS signals.
- 45 rule symbol/permission checks against the captured policy, plus checkmodule 3.9 standalone TE module compilation.
- Android ARM64 API 28 build with the pinned installed NDK r28b/clang19, static C++ runtime.

Host fixtures use synthetic SELinux context labels and the current host UID. They are not evidence of phone domain transitions or Android business success. Every actual new combination needs a fresh bounded health request and later native/worker/business evidence. Old requests, text, pending action IDs and unclear effects must not be replayed.

## Build

Run build_android_r6.py with --ndk pointing to the recorded NDK and --out pointing to a new empty path. The original NDK directory name differs from source.properties; preserve the recorded package revision and compiler hash.

No script in this source package installs a module, changes a live policy, relabels a phone file or sends a phone/model request.
