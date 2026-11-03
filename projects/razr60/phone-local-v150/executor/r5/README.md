# RAZR phone-local executor v150 r5

r5 fixes the execution identity required by the frozen phone helpers. UnicodeInput requires Android Process.myUid()==2000; ScreenshotCodec requires real/effective UID2000 and a shell-owned source PNG. r4 ran effect children as root and therefore cannot qualify those helpers. The original r4 source, binary, state and test records remain retained.

The production sidecar parent must run as root. It keeps the same private journal, authenticated abstract socket hepta_phone_local_v150, one-effect mutex, output files, original action IDs and no-redispatch rules. The tool_client.py bytes are unchanged.

Within the same forked child and owned PGID/session, after setsid and IO setup and before the S handshake or /system/bin/sh exec, production performs:

1. setgroups(0, nullptr);
2. setresgid(2000, 2000, 2000);
3. setresuid(2000, 2000, 2000);
4. getresuid/getresgid plus getgroups verification of all real/effective/saved IDs and zero supplementary groups.

There is no su wrapper, extra credential-helper process, new mount or different shell dispatch. Root parent cancellation still targets and joins the original group. New receipts keep execution UID/GID/effective UID/effective GID and supplementary-group count null until the verified handshake. execution_credentials_verified then becomes true. The production scope is android_shell_uid2000. A failure before that handshake records an indeterminate original outcome and retains the existing recovery gate; it is never advertised as successful execution.

The added credential fields are additive. Existing r4 original process terminal receipts remain read-only evidence with their original scope; they do not acquire UID2000 or Unicode/screenshot qualification. Reusing the same journal never replays them.

## Scope of verification

The Android API28 ARM64 production binary was compiled with the same recorded NDK content and static C++ linkage. Readelf and embedded-string checks confirmed AArch64, /system/bin/linker64, no libc++_shared dependency, and absence of fixture-only overrides.

Four directed Linux host checks passed: independently observed fixture process identity/group, cancellation after its verified credentials with no late output, forced credential-setup failure before exec plus restart gate preservation, and actual production-build refusal under a nonroot parent before state creation. Host fixtures deliberately retain their actual host UID and state host_fixture_current_identity_not_android_shell. They do not attempt setuid2000 as nonroot and do not establish Android/SELinux credential success.

Actual production UID/GID2000, Android helper behavior and process cleanup must be checked on the phone by the sole phone operator. No phone operation was performed while building or running these host checks. Native r5 task protocol, model business acceptance, the fixed 19-item suite and display/posture qualification remain separate.

## Target paths

- Binary: /data/local/tmp/hepta-phone-local-v150-r1/bin/phone-tool-sidecar-r5
- Root-owned private journal: /data/trillionnium/owner-open/state/phone-local-v150/sidecar
- Client: /var/lib/trillionnium/owner-open/phone-local-v150/tool_client.py
- Socket: abstract hepta_phone_local_v150

Do not relax HOSTSTATE permissions for shell child tests. Synthetic phone tests can print unique markers to stdout; the root parent captures these in its private original stdout.bin. No test effect needs to write or traverse the private journal directory.

Build Android using build_android_r5.py with --ndk and a new --out directory. Changing source location may change embedded path bytes; delivered hashes identify the actual frozen build, without claiming arbitrary-path bit identity.
