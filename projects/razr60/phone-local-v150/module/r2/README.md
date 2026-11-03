# HEPTA phone-local module v150 r2: independent source candidate

This directory is a new release. The installed r1 source, sealed directory, package and per-boot history remain unchanged.

## Boundaries and paths

| Item | r2 |
| --- | --- |
| Module id | trillionnium_hepta_phone_local_v150_r2 |
| Installation | /data/adb/modules/trillionnium_hepta_phone_local_v150_r2 |
| Per-boot history | /data/adb/trillionnium-hepta-phone-local-v150-r2 |
| Provider source inside GNU root | /var/lib/trillionnium/owner-open/phone-local-v150/provider-r2/source |
| Production config inside GNU root | /var/lib/trillionnium/owner-open/phone-local-v150/local-config-r2.json |
| Existing provider state | /var/lib/trillionnium/owner-open/phone-local-v150/provider-state |
| Sidecar executable | /data/local/tmp/hepta-phone-local-v150-r1/bin/phone-tool-sidecar-r5 |
| Existing sidecar journal | /data/trillionnium/owner-open/state/phone-local-v150/sidecar |
| Existing local abstract socket | hepta_phone_local_v150 |

The provider keeps all original claims and the failed r1 health01 claim, currently18 as observed by root. New source paths do not create a new task ledger. Original action receipts, in-flight/unknown outcomes, restart barriers and slot checks retain their meaning.

## Changes from the installed r1 module

The module id and history are independent. Provider entry and config use new r2 paths; the forthcoming sidecar r5 has a distinct binary filename. The service and role guard refuse to start/admit if the r1 module directory exists without a nonsymlink regular disable or remove marker. The module only checks that marker. It never stops, disables, removes or edits r1. Root must first read original receipts and prove all old owned roles and effects quiescent before the switch. A disable marker alone is not that proof.

The literal supervisor identity call remains identity "$$"; source generation must preserve both dollar signs. The inherited role barrier admits only the recorded PID=PGID=SID/starttime under a live matching parent. No role executes its application before admission.

Sidecar r5 is required because the frozen Unicode helper requires Process.myUid()==2000 and ScreenshotCodec requires both real and effective UID2000 plus a shell-owned PNG. The sidecar root parent retains its journals, locking, cancellation and wait responsibilities. The bounded effect child drops supplementary groups/GID/UID before exec in its existing group. Exact r5 identity and model/provider/config pins are mandatory sealing inputs; the earlier r4 package is not a substitute.

## Startup behavior

This module uses skip_mount and adds no system overlay, general service.d hook, mount, cloud fallback, ADB forwarding, profile property or automatic request. It validates exact Stock16 SDK/fingerprint, Enforcing, private state ownership and all sealed payload hashes, waits at most120 seconds for existing native bootstrap/mount readiness, and creates one retained current-boot claim. It starts only the model, sidecar and provider. The native profile remains leap-stock16-codex-host-relay-v1; runtime-location is separately phone_local.

The model remains the same pinned GUI-Owl2B Q4_K_M plus Q8 projector and CPU llama.cpp build. Context4096, one slot, four threads, image minimum1024 and maximum1024, phone localhost18087, slots/metrics and no warmup are preserved. Provider localhost is18080. All tools use the local abstract sidecar path; no host ADB fallback is added.

Unsealed source lacks SEALED and cannot start. Sealing runs only on an operator/build host after final reviewed bindings are supplied. The sealer writes static quoted argv and hashes into a new directory; it does not install or start anything. Module installation and real-phone readback belong to root.

## Stop and recovery scope

The service inhibits on the existing emergency-stop/property and module flags, stops provider then sidecar then model, and signals only matching owned group identities. It does not claim business success, effect quiescence or absence of all descendants merely from leader exit. Unknown leader cleanup remains UNKNOWN. SIGKILL of the supervisor after admission is not a demonstrated complete cleanup path.

Provider startup may refuse an unresolved spawn-intent lacking joined evidence; sidecar may require original-receipt recovery. The module never deletes claims, fabricates joined, retries an old request or interprets a new boot as success. New r2 history preserves old r1 history rather than clearing a per-boot claim.

## Current evidence and qualification

Root installed r1 and observed all three services ready in the current boot. The fresh native health01 then ended provider_failed with zero tools/effects: the model failed nonce-only instruction and proposed invalid action arguments. Its 8.10-second model round used601 prompt/73 completion tokens. R2 prompt changes and shell-identity correction address those specific observed problems; they do not predeclare the next result.

Root selected r5 binary SHA30a495061ec8370e15391fd579a254ce35818c7b019725538e0a34755a36ccaa and service manifest SHAa2fe45cff43f7270a43e4d0738ef921812cb534e66ae45fe7b33970612488362. Final provider source seal SHAcbbf47ba6eafae475d5f7ee76a9e90e68c47639938d57451f6fb73b5e6612095 and production config SHA0e3b3e1448a45f7948501518441fc3b18b808c238958fe43860c54c8ef4b689d are independently read back and bound. Sealing and packaging are static operator-host steps; actual phone installation/start remains root-owned. No cold boot, detached-phone session, visual/Unicode business success, fixed19 qualification or fold/external-display support is claimed by this source package. Source, model download, runtime build, current-boot readiness, native health and business acceptance are separate records.

Public source publication must omit actual instance key hashes, private claim files, actual production config and sealed private binding/tar. Publish a sanitized binding template with unresolved instance placeholders instead.
