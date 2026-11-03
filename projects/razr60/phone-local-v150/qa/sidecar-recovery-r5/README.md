# Sidecar r5 actual-phone directed recovery suite

This script is prepared for the sole phone operator. Preparation on Pocket4 has not executed a phone action. Running without --execute-new-suite prints review-only metadata and opens no socket or evidence files.

## Inputs and scope

Use the existing GNU chroot and installed unchanged tool_client.py, pinned to b298ac86fdf57dd0c7dc5159febf114ed176398d32ea672c9abda4a6eb621539. The authenticated abstract socket is hepta_phone_local_v150. The live server executable must match r5 SHA30a495061ec8370e15391fd579a254ce35818c7b019725538e0a34755a36ccaa, and its peer UID must be 0. The script checks /proc/<peer PID>/stat and executable bytes before any execute request. If those paths are unavailable from the existing chroot, stop at the precheck; do not add mounts, change policy or escape the chroot merely to run a test.

The root parent retains its private journal. The production child runs as UID/GID2000 with zero supplementary groups. Synthetic commands only print identity and fresh nonce markers to stdout, optionally sleep two seconds and try to print a late marker. They do not write or traverse HOSTSTATE. The root parent captures stdout in the original private sidecar/actions/<action ID>/stdout.bin. QA evidence is written by the root Python process under one new qa-<nonce> directory. Existing permissions and prior journals are preserved.

Five fresh random IDs exercise:

1. Disconnect before a complete dispatch frame: not_found, no intent, no marker; no terminal is invented.
2. Disconnect only after original effect_started, verified credentials and stdout marker: original cancelled terminal, joined child and absent process group.
3. SIGTERM of this suite's exact original client after tool start: socket closure causes the same original group cleanup.
4. Executor timeout at 650 ms with a possible output scheduled after two seconds: original timed_out terminal and no late output.
5. Complete once, then invoke the exact original client with the same ID: its O_EXCL claim sends only inspect, exits 76, echoes no old output and leaves all four journal files unchanged.

There are at most four new synthetic executions. An uncertain result is only inspected. The script never submits a replacement ID for an uncertain command. Original terminal receipt, command SHA, raw output hashes, dispatch_count==1, waitpid_joined and process_group_absent are required. New execution fields must verify real/effective UID/GID2000 and zero supplementary groups. Live stdout also independently reports uid=2000, gid=2000 and groups=2000 (id -G includes the primary GID).

## Bound and operator invocation

Each tool has a maximum 3,000 ms bound; the timeout case uses 650 ms. The suite has an internal 70-second timer and preserves failure evidence. The operator must apply the already observed Android BusyBox timeout outside the chroot, using 85 seconds plus a three-second kill grace:

    /data/adb/magisk/busybox timeout -s TERM -k 3 85 EXISTING_CHROOT_COMMAND /usr/bin/python3 -B SCRIPT --execute-new-suite

Replace EXISTING_CHROOT_COMMAND and SCRIPT with the already established chroot invocation and newly staged script path. /usr/bin/timeout is not assumed to exist. There is no phone, ADB, model or native task dispatch in the preparation commands.

The output announces the new evidence directory before requests and ends with immutable SUMMARY.json and EVIDENCE-MANIFEST.json paths and hashes. Keep them and the original action journal. An actual run that fails stays failed or incomplete; do not reinterpret it as success.

## Qualification boundary

This directly tests the production sidecar component and original client. It does not use the native r5 tool ledger or the model provider. It does not complete the fixed 19-item protocol, a visual/Unicode business contract, product-budget exhaustion, physical display-state qualification or a cold boot test. The suite's wall-clock bound is not a product-budget exhaustion test. The earlier r4 suite remains preserved as a historical prepared artifact and does not establish UID2000 helper compatibility.
