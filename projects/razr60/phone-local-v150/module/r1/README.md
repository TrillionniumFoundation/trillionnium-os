# Phone-local v150 startup module candidate

This is a new, independent Magisk module source candidate, not installed and not boot-qualified. Its module id is `trillionnium_hepta_phone_local_v150`; intended Android directory is `/data/adb/modules/trillionnium_hepta_phone_local_v150`. It uses `skip_mount`, creates no system overlay, does not alter the existing `trillionnium_hepta_stock16_v143` module, and adds no general `service.d` script.

## What startup does

The late_start `service.sh` checks exact Stock16 SDK/fingerprint, enforcing mode, owner/permissions, sealed input hashes, native emergency-stop and stop property, and both module disable/remove flags. It waits at most 120 seconds for the existing native bootstrap and mount readiness, creates one retained claim for the current kernel boot id, then launches model, Android tool sidecar and GNU-chroot Python provider in individually identified sessions. It monitors owned services and stop/inhibit. It submits no health prompt, business task, old request, text, UI action, resume or retry.

The native bootstrap profile remains `leap-stock16-codex-host-relay-v1` in this runtime-only phase. The startup record separately says `runtime-location=phone_local`; it never changes properties to claim a formally upgraded phone_local profile. HEPTA49 continues its existing native abstract socket and business profile `owner-open`.

A provider starts on phone localhost port 18080 only after root has transferred ownership: the Mac watcher `org.trillionnium.hepta.transport-watch` must be stopped and disabled, owned old host provider/bridge stopped, and only the owned ADB reverse tcp:18080 removed. This module performs none of those host/ADB operations.

## Files and sealing

`module-root/` contains `module.prop`, `skip_mount`, `service.sh` and `role_guard.sh`. Each role guard establishes its own session and writes PID/group/session/starttime identity before waiting for the supervisor's exact admission marker; it executes no application without that marker and an unchanged live parent identity. An unadmitted guard exits within five seconds. No `SEALED` marker is supplied, so copying this source candidate alone will not start services. `bindings.example.json` deliberately has reviewed_for_installation=false and invalid placeholders.

After root has fixed actual frozen paths and hashes, append every imported provider module, client, model-server dependency, model file, exact config, retained-claim input and any key file to the payload inventory. Private credentials belong in root-only files, not argv or this note. The provider source freeze manifest is the source of the complete Python import list. Use actual root-reviewed readbacks, not guessed hashes.

Run on a build/operator host:

```sh
python3 seal_module.py --bindings /absolute/reviewed-bindings.json --output /absolute/new-sealed-module-directory
```

The sealer writes static shell-quoted argv launchers and input manifests; it neither connects to a phone nor installs or starts anything. `service.sh` independently verifies actual phone payload hashes before starting. Root installs only after reviewing the sealed content, sets the module directory to root:root 0700, service.sh to 0700, all other files to root:root 0600, and reads back every file/hash. The final path convention is PHONE=/data/local/tmp/hepta-phone-local-v150-r1 with bin/llama-server, bin/phone-tool-sidecar and models/two GGUF files; HOSTSTATE=/data/trillionnium/owner-open/state/phone-local-v150 with provider/source, tool_client.py, provider-state and sidecar journal. Model localhost port is18087; provider is18080. The existing model key PHONE/state/api.key may remain shell-owned0600 as root specified; the provider copy HOSTSTATE/private/llama-api.key is root-owned0600. Both key files must have identical observed size/SHA, but their contents are never put in launch argv, environment or the binding file. The service entry is intentionally the only executable module file.

## Runtime path split

The Android Bionic model server and tool sidecar run outside the existing GNU chroot. The stdlib provider runs inside `/data/trillionnium/owner-open/root` with `/usr/bin/python3 -B`. Its source and state live under the existing shared state mount; noexec does not prevent the trusted Python interpreter from reading source.

The tool client connects to abstract Unix socket `hepta_phone_local_v150`; the sidecar author reports SO_PEERCRED uid 0/2000 validation. Root must observe actual SELinux connectto from the bootstrap domain to the sidecar domain. There is no /system bind and no /proc/1/root escape. No sepolicy.rule is supplied in this candidate. If root observes an actual connectto denial and approves a narrow persistent policy rule, place the reviewed rule in module-root/sepolicy.rule and bind its exact SHA256 plus policy_change_evidence in the sealing inputs; the sealer refuses an unbound policy file. A one-time live policy change does not prove next-boot policy persistence.

Model inference uses phone localhost. The example launch parameters follow root's final-config candidate: 4096 context, one slot, four CPU threads, image minimum 1024 and maximum 1024 tokens. Root observed a Qwen-VL grounding minimum warning; the earlier image cap768 is retained only as historical pure-text health context and must not be used as the final visual setting. This revised configuration still needs its own fresh nonce health and visual task. Root must replace them with the observed frozen combination, including a safe local API authentication choice.

## Honest shutdown and recovery limits

The hook first stops provider admission, then sidecar, then model. It signals only identities observed as own session/group leaders and checks PID/starttime before group signals. Graceful stopping gives each role up to 12 seconds before forced KILL. The hook's records distinguish a verified live leader, an absent/unknown leader and forced cleanup. The hook never claims a business terminal or full descendant/effect quiescence merely because its own process or a leader ended.

Provider and sidecar own operation-level cancellation. The sidecar must wait for actual effect groups and persist terminal receipts; provider must join owned HTTP workers and reconcile model slots. Those claims require their independent fixtures and on-phone tests. If a spawn occurs before a process identity can be observed, only the unadmitted guard can exist; it has a five-second bound and cannot execute the model/provider/sidecar. The hook still records cleanup UNKNOWN and does not retry. Unexpected supervisor death after admission and full descendant cleanup remain separate qualification cases; source-level startup barriers are not substitutes for those observations.

Provider startup intentionally refuses retained spawn-intent without joined evidence. Sidecar startup enters recovery_required for original unfinished intent. The boot hook never deletes claims, fabricates joined, or treats boot change as business success. Root must read original receipts and determine the unfinished part before any new effect.

## Acceptance before claiming usable/persistent

1. Fresh bounded model health with a true terminal.
2. Real bootstrap-domain client health to the actual sidecar; current display/focus identity.
3. Fresh visual and Unicode task with exact public text readback, actual business result, HEPTA return and consistent task terminal.
4. Disconnect, started-tool cancel, late result, absolute timeout and budget exhaustion with original receipt recovery.
5. Stop/inhibit visibly ends all newly owned roles and real effect/HTTP groups; unknown cleanup stays unknown.
6. A controlled subsequent cold boot without a Mac/Pocket4 request execution dependency. Installing a late_start script alone is not boot qualification.

The final formal phone_local bootstrap/profile/rootfs rebuild is specified in ../provenance/PHONE-LOCAL-CLOSURE-PLAN.json and is separate from this runtime substitution.

## Sources

- Current native/module source baseline: TrillionniumFoundation/trillionnium-os commit 0152dc425b6eec188dfd0efdd62aa004b59c76c5, projects/razr60/stock16-v149.
- Official Magisk developer guide: https://topjohnwu.github.io/Magisk/guides.html — module service.sh uses nonblocking late_start; module scripts run only when enabled; modules should not install general boot scripts.
