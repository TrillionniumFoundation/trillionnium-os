# Actual entrypoints and missing inputs

This inventory is a read-only source finding. No existing input, frozen source, actual success slot, operation label or device state was changed.

## First actual dependency

The original current44 cleanup invocation is reported by Root as phone exit 1 before the first deletion, with zero deletions. That is an original failure to preserve; it is not successful cleanup. The current first missing input is a successful, independently verified current44 cleanup closure followed by a fresh current44 admission from the actual current directory state. Historical current41 closure and the old current44 capture cannot substitute for it.

The current44 reader source is:
`/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/owned-neg02-cleanup-source-recovery-a1055-20261106-01/verify_owned_current44_cleanup_UNBOUND06.py`.
Its actual driver/core/preservation/host/job/operation/construction/publication slots remain unbound. Its successful API schema differs from the historical current41 reader. No values were inserted here.

## Existing source entrypoints

| Purpose | Existing source | SHA256 / actual need |
| --- | --- | --- |
| Actual component host freezer | `/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/final-runtime-actual-adoption-source-a1055-r1/source/freeze_final_component_runtime_v6.py` | 63506 bytes; bb0c8f73f465c4d0e1271d79e1dcf9171a260f50fe5b617512c0479209585866. Its --verify-only and --freeze-once take --adoption, --adoption-bytes, --adoption-sha256. Its R4 output already exists; its 15 production bytes are frozen to the old tuple. |
| Host component plan preparer | `/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/final-runtime-actual-adoption-source-a1055-r1/source/prepare_final_component_plan_v4.py` | 59395 bytes; 77c7c1007f951e35843f6a4e0908fd7652bd9bc30ce3527c978233abc840d6e2. Requires reviewed source SHA, actual freeze bytes/SHA, case, actual previous input bytes/SHA; --create-host-plan-once generates the one-use plan. |
| Formal host BUILD | `/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/source/build_release_r10.py` | 61822 bytes; 991465020b2012372d677cc4c7cf9fc02c668a406a0af0fc6fc08514d3f0073e. Requires formal inputs, retirement inputs, two-case component boundary inputs, policy-adoption inputs and shared-materials, each actual SHA, plus a fresh output directory. --material-only does not BUILD an installable release. |
| Actual BUILD reader | `/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/source/verify_final_release_inputs_v3.py` | 28483 bytes; e947a3b2de75a0820fcc3cb5cfe758f874cd85625cb11bac793b38256a670c43. Pure callback reader, currently fixes old builder/formal/shared/combination pins. |
| Phone installer body | `/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/source/install_phone_release_r10.py` | 34100 bytes; 714a2916680e2313bfcee5a4319d6484b3c6ea5539854818c1134ad84ea02446. Actual GNU publication and readback precede use. |
| Phone READY body | `/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/production-release-owner-finalizer-a1055-r1/source/collect_r10_readiness.py` | 16407 bytes; 2b4ff90f7078af2481feb8a2d33c39d1a0e260102cd769a4ee3b46d9bec47e11. Installed GNU path: /var/lib/trillionnium/owner-open/phone-local-v150/provider-r10-r1/collect_r10_readiness.py. |
| Four-role/eight-stream reader | `/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/fivefault-source-reconstruction-a1055-r2/source/verify_resident_output_bindings_bound02.py` | 29027 bytes; 24db28bee38671322b11ce4c2afd5dd47425381101dd85f887141f567811b490. Connects actual BUILD, installed module, READY supervisor, three actual child bind originals and all eight stream origins. |
| Installation execution-originals reader | This package source/verify_install_start_ready_UNBOUND.py | 35031 bytes; d1de5b63f24cee899c47f7c3019ac4d7939d6212c9c798f812dc0266a97b569f. Both FROZEN slots remain None and refuse before I/O. |

The v4 preparer binds historical cleanup/current41 sources, and its final04 NEG-01/NEG-02 labels have already been consumed. It cannot legally create a new operation using those labels, nor use its historical cleanup gate as new current44 success. A successor must preserve the consumed history, use actual fresh current44 proof under the current reader, and bind the reviewed new source tuple. No new label or nonce is generated in this package.

## Source propagation for the two native changes

The reviewed native candidate is:
- phone_observation_tools.py: 43954 bytes; 22580b8aa22d5c0ab4040888872e642a5176042023dd7bcf50e67efe51248409.
- daily_phone_local.py: 22059 bytes; 689db3908014940a1e39689b966d30ab16ac6f9c0d7892becf1718b9840c824f. Its only change is the first file's PARENTS entry.

The current R4 COMBINATION is 4695 bytes / 02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708.
Current SHARED-MATERIALS is 3519 bytes / 2ea9a478b366d6a69fdb8942699b6241d72330cfa789baa4b3132fdaca169e68.
Those old values cannot identify the new 15-file production tuple.

The minimum source propagation is two production rows and daily PARENTS, then service.provider_sources, config.service_manifest_sha256, the production source seal, SHARED-MATERIALS, COMBINATION, runtime production pin references and dependent runtime/root manifests. The host formal input's two production source descriptors must point to the actual new files. The existing owner-builder permits only the already reviewed readiness helper change to its parent formal input and hardcodes the old daily/config/service hashes; it deliberately rejects an arbitrary two-source substitution. Its owner wiring also fixes the configuration digest. A source-derived successor builder and fixed reader chain are therefore needed, with full byte inverse/provenance controls rather than guessed constant replacements.

The install reader is a host verification source, not one of the 15 phone production files. This d1de candidate combines its type fix with the reviewed full GNU environment prefix. Once the formal BUILD reader changes, the release/exact8 source descriptors in the installation chain must be explicitly derived again from the actual reviewed reader bytes. d1de is not claimed to be the final reader for an unbuilt future tuple.

Historical NEG-01 success remains historical evidence for its original tuple. It is not automatically qualification of the new 22580b/689db tuple. New same-tuple component cases, complete closures and the required fresh final admission must exist before formal BUILD.

## Inputs still required for BUILD and stage/start/READY

1. Current failed cleanup reconciliation and a real successful cleanup closure plus fresh current44 admission. No historical-success substitution.
2. Reviewed new source tuple/freezer and successor preparer bindings. The actual policy adoption is separately pinned, currently 32638 bytes / 98b5db3d2c9680fff13e50bf64b18ddf9822689641427d204fded84f690d04c7, with live policy 69aa6433a11ac4cffb2f1d349cc9f36ec2349a601911c173ebe7d92fff9e0c5b. No policy load is performed here.
3. Actual qualified current-combination NEG-01 then NEG-02, complete native/history/role/retirement closures and final fresh admission. Existing release reader requires the closed two-case current47 shape.
4. Actual formal BUILD output: BUILD-RESULT, complete archive, release/module/source seal and the original Mac process invocation, terminal and full streams. Source controls and material-only output do not satisfy this.
5. Actual publication/readback of the unchanged installer and actual BUILD archive at the planned GNU paths.
6. One immutable actual execution plan with three distinct labels/request paths/keys. This package generates none.
7. Three actual configured-pocket4 actor invocations: stage, start, ready, with complete dispatch/start/status/read originals, original actor source bookends, private request/intent/baseline/result, full phone streams and guard receipts. Actor exit 0 alone is insufficient; phone exit must be integer 0.
8. Five full actual installation files: INSTALL-INTENT.json, STAGED.json, STAGED-PRESERVATION.original.json, START-INTENT.json and STARTED.json.
9. Actual installed module/source/claim identities, READY and three actual H05 child-bind records, tied to the same supervisor generation and eight original output streams.
10. An explicitly reviewed installation-scope large-original retention producer/binding. The existing retention contract leaves it null: STAGED-PRESERVATION allows 32 MiB while a shell's combined stream bound remains 8 MiB. Existing bounded artifact/chunk code is a reference, not already admitted for this new scope. No truncation, tail, guessed alias or raised cap can replace full retention.
11. Explicit original-namespace-to-host exact4/full9 mappings and final readback bookends. Independent task/terminal/output/footprint/fresh/rollback gates remain separate existing requirements.

## Existing operation API shape, for source review only

The protocol's pure `expected_phase(plan, phase, verified_release, actual_release_inputs, actual_retirement_sha256)` returns the request bytes and exact actor dispatch. It does not dispatch.
The actor stays /home/alex/razr60-local-model-v150/ops/phone_once.py, 5652 bytes / 179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22, configured host pocket4.

Installer actual CLI fields are --archive, --archive-sha256, --retirement-sha256, --component-boundary-inputs-sha256, --policy-adoption-inputs-sha256, --phase stage|start, --execute-reviewed-operation-once.
READY actual CLI fields are --expected-boot, --source-seal-sha256, --configuration-sha256, --module-manifest-sha256, --component-boundary-inputs-sha256, --policy-adoption-inputs-sha256.

The actual GNU prefix was re-read from current44 REQUEST 61232 bytes / d8bcef88d6e56e9641ddbbf16432d95b62183db1d52b66df17ed3f2043044619. Only its exact execution environment is adopted by protocol v2; no current44 task or cleanup success is inferred.

## Sources retained in this package

references/ENVIRONMENT-V2-DERIVATION.original.json records the actual request path and original/selected source pins.
The original input and producer-retention contracts remain under references, where their obsolete source pins and historical wording are visibly preserved. They are not a new candidate contract.
The original installer/readiness/release/exact8/consumer bodies are retained byte-for-byte.
No private authorization or credential contents are included.
