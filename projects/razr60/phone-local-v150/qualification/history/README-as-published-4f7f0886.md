> Rendering note (2026-11-04): The [previously published bytes](README-as-published-4f7f0886.raw.txt)
> remain unchanged. This display copy adds this note and rebases navigation
> links from the former project-root location to this history directory.
> Historical results and qualification statements are unchanged.

# RAZR60 phone-local model — r7-r1 measured checkpoint

**Phone-local model health passed. Both new real phone business tasks failed. The formal nineteen-case result is 7 PASS / 2 FAIL / 10 BLOCKED; daily-use qualification has not been established.**

The model and inference runtime are installed on the phone. The current failure is in the first Android application operation: both original workers reached execution and timed out while their stderr reported denied servicemanager property reads. Original actions and drafts have been independently closed without replay. A future property-permission correction is a separate combination, not a retroactive pass for this one.

Read the [complete quality and cost report](../r7-r1-checkpoint/README.md) and [machine-readable result](../r7-r1-checkpoint/actual-01/QUALITY-PUBLIC.json).

## Current source and execution boundary

The phone runs GUI-Owl-1.5-2B-Instruct Q4_K_M with its Q8 vision projector, a pinned Android ARM64 llama.cpp runtime, the existing HEPTA native turn/tool ledger, and the dedicated r6 executor/worker SELinux domains. Model inference is local to the phone. The fresh r7 health request has passed; this alone does not establish ordinary phone-operation reliability.

r7 changes two of the thirteen production Python files: the provider accepts a constrained named mobile_use JSON projection and daily_phone_local pins that exact provider. It keeps the original typed phone tools, native admission, executor, model weights, SELinux policy and resource limits. The health path remains separate and does not force the expected nonce as a decoder constant or enum.

This named JSON shape is a deterministic transport projection informed by the model's official mobile action vocabulary. It is not a claim that the model emits the cookbook's literal XML/action transport. The original model object and HTTP response, the mapping record, and the mapped legacy decision are retained separately. The business collector independently recomputes the projection from the pinned source and requires the original native and executor evidence. A model summary never proves that an action occurred.

## Version and evidence map

| Item | Frozen identifier | Public entry |
| --- | --- | --- |
| Production source | source seal 7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab | provider/r7 |
| Provider | 8f57e86ec66e4588e2e6f43ea761f17e9ae02361791995ff2f5831a16e46dbe6 | provider/r7/source/provider_phone_local.py |
| Daily entry | 92122fcc8bf01511971075fce2ad94b628dadf2c0c342f0fb940e8b00c636ec3 | provider/r7/source/daily_phone_local.py |
| Private module manifest | c0e31ecac9168218e7b6a622e4a3df138859743bd83911add42c32906d173a06 | module/r7-r1 review-source projection |
| Whole-combination original | ab038c5533a7459c8bb4d94cca008ca0f61ade0d90ad6db0e8ece3ab1af99ae8 | qualification/combinations/COMBINATION-v150-r7-r1.PUBLIC.json |
| Combination canonical hash | 87609ca2d6b6701071a1f175acd417e1f3036617884dc09666b9154de25e93f8 | Same combination projection |
| Formal fixed-19 protocol | d68dd5c17d0ec061f52b60656918867453d67217ac2dc8f5eb43be7dd3ffdf43 | acceptance/r7/fixed-acceptance-set-r7.json |
| Mapping-aware collector | e5fc961d5cec94ab2e075c84dd5672b0d616863a616d59270d92cfd527dfddc7 | acceptance/r7/business-collector |
| Original client | 500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f | client/r6 history and source seals |
| Live policy observation | 05756784090a574be850a068576fbded2842f3fa8c1af0aa5b430f875c78a31f | policies and module/r7-r1/source/sepolicy.rule |

The public combination and seals are projections and have their own byte hashes. Their original_artifact_sha256 identifies the retained private manifest; it does not imply that projected bytes equal the private original. The module archive, actual sealed bindings and configuration are not distributed here.

The formal acceptance protocol is the r7 metadata adaptation of the current r6-r2 protocol: all nineteen case objects, limits and geometry are retained, including the host-plus-physical requirements for NEG-04/05/07/08/09. The source package's provider/r7/qa/fixed-acceptance-set.HISTORICAL.json is retained historical material, not the current acceptance authority.

## Actual health cutoff

[HEALTH-v150-r7-stage01.json](../checkpoints/HEALTH-v150-r7-stage01.json) is an immutable cutoff after the first r7 health request and before admission of any r7 business result. It records one health pass and zero business samples at that cutoff.

The native task completed after one local HTTP/model round and zero phone tools. The original worker joined, the slot was idle, and the exact original draft was restored without submission. Root checked the actual host/actor/phone/collector exit statuses and the original task evidence. Three selected native records and two visible predecessor links passed hash verification; this is not a complete-global-journal claim.

| Measurement | Observed value |
| --- | --- |
| Model HTTP round | 3.607201196 s |
| Native completion observed by | 4.236559475 s |
| Native persistence interval | 3.037658847–4.236559475 s |
| Prompt / output / total tokens | 169 / 76 / 245 |
| Model-reported output rate | 33.697627 tokens/s |
| Model RSS before / after | 3,100,676 / 3,123,156 kB |
| Model after-sample high-water value | 3,142,964 kB |
| Hardware energy and monetary cost | Not measured |

A single health sample does not characterize model success rate, tail latency, daily-use suitability, fold states or cold boot. Model HTTP time and native task observation time are separate measurements.

## Business and protocol results

The final r7-r1 checkpoint contains two real business samples, both failed: complete 0, verified partial 0, failed 2, cancelled 0, unconfirmed 0. Health remains a separate one-sample pass. The full fixed protocol is 7 PASS / 2 FAIL / 10 BLOCKED.

| Real request | Model HTTP | Prompt / output / total tokens | Native terminal observation | Original phone tool |
| --- | ---: | ---: | --- | --- |
| Health | 3.607 s | 169 / 76 / 245 | completed by 4.237 s | 0 |
| Visual E2E-01 | 12.182 s | 1124 / 27 / 1151 | provider_failed, observed in 72.303–73.551 s | one open_app; original worker timed out at 60.011 s |
| Unicode E2E-02 | 15.327 s | 1562 / 46 / 1608 | provider_failed, observed in 75.444–76.676 s | one open_app; original worker timed out at 60.024 s |

Both named model actions selected the correct registered application and passed deterministic mapping verification. Neither task reached image input, visual tapping or Unicode text entry. The original stderr records servicemanager property read denials. There is no per-command stage receipt, so the precise blocked subprocess and whether an application launch effect occurred are not asserted. The effect_started flag is true; these are not zero-effect failures.

Each original action has a terminal timed_out receipt with a joined child and absent process group. The model HTTP workers joined, their slots were idle, and original-action inspection closed the outstanding ledger entries. Original native failures, provider/native error-text differences and proof_complete=false are preserved. All original drafts were restored exactly without submission. Process cleanup and draft restoration are not business return, partial completion or recovery success.

The two business samples consumed 2759 model tokens; health adds 245 for 3004 across three real requests. Six independent resource observations found model RSS from 3100676 to 3286676 kB and a lifetime high-water value of 3301680 kB. These are sampled process values, not per-task peaks or energy measurements. Hardware energy and monetary cost remain unmeasured.

The official 19-case table and the per-layer requirements are in the final report. Its fourteen fixed-set samples comprise two real model tasks, eleven host-isolated negative cases and one geometry component case. The 462 runtime assertions and fourteen evidence-closure assertions are checks within those samples, not independent task counts.

The r7 host results are new samples on this exact source and combination:

- NEG-03, NEG-06 and NEG-10 through NEG-14 each passed once: 308 runtime assertions plus 14 original-evidence closure assertions. NEG-03 is component_direct; the other six are host_isolated. Their subset is 7 PASS / 0 FAIL / 12 BLOCKED and contains zero real phone/model requests.
- NEG-04/05/07/08/09 passed their host-isolated layers once: 154 checks. These five cases retain separate physical lifecycle requirements. Host success does not close their full protocol cases.
- Synthetic host HTTP responses and disposable subprocess counters are identified as fixtures. They are not phone actions or actual GUI-Owl predictions.

The previous r6-r2 [stage02 quality report](../checkpoints/QUALITY-v150-r6-r2-stage02.json) stays under its own frozen combination: 7 PASS / 3 FAIL / 9 BLOCKED. Its two model business tasks failed with no phone tools. Its physical cancellation task ended cancelled but the model slot was still busy; the physical lifecycle case failed and the service stopped. The independent original-task/draft/retirement closure is not a retroactive success. None of these old samples is relabelled as an r7 result.

## Preserved execution rules

Every accepted task and effect is tied to a fresh request, one-use contract and original native scope. Old requests, text and actions are not replayed. The provider preserves an unresolved mutation gate across tasks. Recovery reads the original action's receipt and requires a supported disposition before any new action.

An effect reaches the Android namespace through the original native shell.exec path and the fixed r6 client. The executor records a durable intent before dispatch, checks peer identity and the dedicated execution domain, and runs the worker with UID/GID 2000 and no supplemental groups. Terminal evidence includes the original exit, joined child and process-group absence. These cleanup facts do not undo an Android action already received by a system service.

A complete business result requires the original actions, text readback, application postconditions, HEPTA return and task terminal to agree. A timed-out or partially executed task cannot become a complete success because a model says it finished.

The unchanged model/tool budgets are seven tools, eight rounds, a 300-second task budget, a 120-second HTTP bound, 256 generated tokens per response and a 24,576-byte prompt limit. The runtime context remains 4,096 tokens with four CPU threads and one slot. No automatic retry or extra resolver was added by r7.

## Capture workflow correction

The sealed business-export README contains a historical four-phase instruction error. The normal workflow is:

1. preview
2. capture, which already performs export before returning
3. collect

Read [WORKFLOW-ERRATA.md](../../acceptance/r7/business-original-export/WORKFLOW-ERRATA.md). A separate export command is not a fourth normal step. It is only an independently reviewed incomplete-transfer recovery. A duplicate export refuses an existing archive with O_EXCL and preserves that original; do not recapture or replay the task to work around the refusal.

Successful transfer is not business success. The original capture actor and phone exits, complete evidence, actual collector exit and business postconditions all remain necessary.

## Public source and reproduction boundary

PUBLIC-PROJECTION-INDEX.json records every original/public SHA256 and the exact transformation for newly published sources. Twelve production Python modules are byte-identical to the frozen r7 source. The thirteenth, retirement_recovery.py, replaces private retained-action, proof, boot and process bindings with required placeholders and records the original source SHA256. Review-only operators may also contain explicit private-binding and workspace substitutions. These projections are not installable module packages.

PUBLISH-MANIFEST.json maps the full public project tree to SHA256 and Git blob hashes and preserves the previous publication head. Older source revisions and failed checkpoints stay present. The previous main README and publication boundary are preserved under qualification/history.

The host build, source pin closure and Pocket4 byte readback are recorded. They are not an independent bitwise rebuild of the whole phone/rootfs. HEPTA49 and complete historical rootfs reconstruction remain separate work with their original compiler/system-image inputs.

Private task requests, fresh nonces, draft contents and content digests, actual claims, native histories, keys and key hashes, model weights, runtime executables, full policy binaries and sealed deployment archives are excluded. The only newly included image files are pinned synthetic host-test fixtures.

## Next qualification steps

Qualify the separately versioned minimal servicemanager property correction using the actual compiled policy and real transition/permission evidence. The frozen r7-r1 sources and both failed requests remain unchanged. The revised combination first needs a new bounded health request and then entirely new visual and Unicode materials. No original request, text or effect is replayed.

Then complete the physical fault-recovery layers and the remaining fixed protocol cases. Real outer-screen, landscape and fold transitions require their own display identity, coordinates, focus and recovery evidence. Daily-use qualification remains withheld until the fixed task quality, latency, recovery and resource evidence support it.
