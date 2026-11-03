# Phone-local tool executor r4

The frozen C++ source, tool client and Android build script are unchanged from executor-v150-r4. The original package manifest is retained in provenance/FROZEN-EXECUTOR-MANIFEST.json; binary payloads are represented by hashes, not committed. Public projected build receipts replace operator workspace paths and preserve the original artifact SHA in the project publication manifest.

The current Android journal is /data/trillionnium/owner-open/state/phone-local-v150/sidecar/actions/<action-id> with intent.json, receipt.json, stdout.bin and stderr.bin. The GNU rootfs observes it under /var/lib/trillionnium/owner-open/phone-local-v150/sidecar/actions/<action-id>. The client is /var/lib/trillionnium/owner-open/phone-local-v150/tool_client.py. Production UDS is abstract hepta_phone_local_v150; both directions require peer UID 0 or 2000.

Each request is a four-byte big-endian length followed by one UTF-8 JSON object. Execute binds version=1, op=execute, a fresh lowercase 32-hex action_id, lowercase command_sha256, reviewed command and timeout_ms (1–60000). Only one effect may be active. Health/inspect do not execute an effect. A duplicate original ID inspects its existing receipt and cannot dispatch again. The client additionally keeps an O_EXCL claim and returns 76 on a repeated call without echoing old output as fresh output.

The child creates one owned session, runs /system/bin/sh -c with null stdin and captures original output up to 8 MiB combined. Synchronous typed mappers may not invoke su, setsid, nohup, daemonization or background jobs. Already accepted Android service effects cannot be rolled back merely by killing the process group.

Safe terminals require a whitelisted state, terminal=true, effect_started=true, process_group_established=true, waitpid_joined=true and process_group_absent=true. Actual completed exit zero is necessary for a client exit zero. r4 startup does not discard its recovery gate for terminal=true / indeterminate. Original uncertain action records are retained; no automatic redispatch or destructive reset is supplied.

Build Android from the pinned NDK using build_android.py. All vendored sources are fixed by VENDOR-MANIFEST.json; materialize_vendor.py can verify/restock them from an already obtained matching llama.cpp source tree. To reproduce the sole r4 restart regression on Linux, run run_targeted_r4.py with a new --out path. The wrapper builds a separately marked HEPTA_TESTING binary in that directory and runs the byte-identical targeted_r4_fixture.py there, keeping its fresh result separate from original provenance.

Production runtime, real native r5 cancellation and business acceptance remain distinct qualifications. The five-case actual-phone sidecar script under ../qa/sidecar-recovery is prepared only until the sole phone operator executes it and records the actual result.
