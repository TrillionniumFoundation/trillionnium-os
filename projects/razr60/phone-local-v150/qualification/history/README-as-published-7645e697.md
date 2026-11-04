> Rendering note (2026-11-04): The [previously published bytes](README-as-published-7645e697.raw.txt)
> remain unchanged. This display copy adds this note and rebases navigation
> links from the former project-root location to this history directory.
> Historical results and qualification statements are unchanged.

# RAZR60 phone-local v150 — r6-r2 health checkpoint

**The phone-local r6-r2 combination has passed one complete, bounded native health task. Business and daily-use qualification remain pending.** The checkpoint records one actual Send, one local model HTTP request and zero dispatched phone tools. Its original model response matched the new nonce, the provider and native terminal both completed, the model worker joined, the slot returned idle, and all captured originals and actual process exits were checked. This is the health-stage cutoff; later business attempts belong in a new evidence snapshot.

Read the [health checkpoint](../checkpoints/HEALTH-PASS-v150-r6-r2-01.json) for the exact version and evidence hashes. The [public source boundary](../../PUBLIC-SOURCE-BOUNDARY.md) and [projection index](../../PUBLIC-PROJECTION-INDEX.json) distinguish byte-identical production source from explicitly redacted operator or metadata copies.

## Current measured result

| Measure | Actual r6-r2 health sample |
| --- | --- |
| Native terminal | completed |
| Original model requests / tool dispatches | 1 / 0 |
| Model HTTP elapsed time | 3.198154530 seconds |
| Prompt / output / total model tokens | 170 / 60 / 230 |
| Model-reported output rate | 33.148637 tokens per second |
| Send to observed native terminal | at most 4.215477534 seconds |
| Terminal persistence interval | 2.986361244 to 4.215477534 seconds |
| Original capture | 31 files and 3 native records |
| Capture actor / phone / collector exits | 0 / 0 / 0 |
| Original owner draft | restored once, not submitted |
| Model RSS before / after | 3,101,380 / 3,122,796 kB |
| Model high-water RSS | 3,143,504 kB |
| Fixed 19 cases closed at this cutoff | 0 / 19 |
| Daily-use qualification | pending |

The latency interval uses one Pocket4 monotonic clock and includes polling uncertainty. The model HTTP time is not total task latency. Memory values are Android process snapshots, not whole-device peak memory. No hardware-energy or monetary-cost measurement is claimed.

The raw model summary matches the nonce. Native display intentionally keeps the inherited business-unverified prefix, because a zero-tool health task does not verify an App outcome. The health collector explicitly reports complete_business_success=false.

The private report SHA is 47ce2d5ecf9a6948b097975f0a9b06b1a217e551a44524269732850c7233b285. Its 27,753 original bytes were independently read for publication. The operator's final admission review, 83db5f3b086bdc73e1d025c4b6f66b1e4f823299dfd9c9d5eacc0f566dae48e0, verifies all originals and four actual host stages. Raw inputs, nonces, native identity fields and captures are not published.

## What runs on the phone

GUI-Owl-1.5-2B-Instruct Q4_K_M and its Q8 projector run in an Android ARM64 llama.cpp CPU server. The provider runs in the existing GNU rootfs. Native tools use the original shell.exec admission and journal, a pinned Python client, an authenticated abstract Unix socket, and an Android Bionic executor with a separate worker domain.

The selected model endpoint is phone loopback. Mac and Pocket4 are build and operator hosts; they are not inference servers for this combination. The health sample made no cloud model request.

| Component | Frozen identity |
| --- | --- |
| Provider source seal | a8bd87b3d50c993b3e4ac7799ca66dd8e84cbd7925deb7e641e5cc66c1bdb7c1 |
| Module manifest | 9e5a8c3f9a5a7f4426d109beba1073edcfa2dfe4712760e446054b04906afb4a |
| Full combination file | 1cca670c3d51e0319ba9a07921319d1bf36af160780eed4e7e0c68e2b7a72802 |
| Canonical combination | 5c04f6d4b27be786387e83998c2f8e350c263835bb12d629278d0d252c36e418 |
| llama.cpp source | 8642541b255bfb5dc39cd351a178be09013a55d6 |
| Main GGUF | 5fd2c77781a14a91128928b5bd313252aab076b44682396af4bb2c99667f5ef5 |
| Projector GGUF | 16748786911f630d0c14869ac28999f77715053a62b2a00d2327021bd6d2afb7 |
| Executor client | 500e27037738deead0e213321b43bb66e8150e534a65071b2b6ffd211aa3899f |
| Actual live policy | 05756784090a574be850a068576fbded2842f3fa8c1af0aa5b430f875c78a31f |

The runtime uses four CPU threads, a 4,096-token context, one slot and a fixed 1,024-token vision budget. The published source and model reference manifests identify inputs; model weights, device executables and full rootfs images are not included here.

## Changes since the previous publication

The previous published tree is preserved. This increment adds provider r4, r5, r6 and r6-r2 source history; executor r6 and its worker; client r6; explicit IPC and business policy source; current module source projections; original-evidence validators; bounded capture/export operators; and r6-r2 acceptance metadata.

Provider r6 fixes a concrete health-terminal bug: the owner input became a plain string while the validator still expected a content block. The first r6 startup then exposed one stale embedded health-source hash in the daily entry. Provider r6-r2 changes that binding and preserves the other twelve production modules, four operator helpers and the business behavior. It has actual isolated entry/import evidence and the complete phone health sample above.

The new capture wrappers require actual process completion alongside report predicates. A raw report saying PASS cannot qualify a nonzero collector process or a failed capture process. Partial originals remain available for diagnosis. The focused host negative check really printed PASS and then exited 7; each process fence rejected qualification.

SELinux remains Enforcing. The executor parent and worker use dedicated domains, pinned entry labels and explicit peer checks. The parent keeps private durable intents and receipts; each production effect runs as UID/GID 2000 with zero supplementary groups. Its receipt binds the worker domain and handshake, process identity, exact command and action, child join and process-group absence. An interrupted or uncertain effect remains blocked until its original evidence is resolved; changing a call identifier does not authorize replay.

The policy audit checks expanded permissions and non-rule tables, not just text or binary size. The full combined rule parsed cleanly using the installed Magisk parser; the actual live serialization was separately compared with the reviewed offline candidate. A policy audit is not proof that every App operation works.

## Preserved failures and recovery

| Stage | Retained result | Qualification limit |
| --- | --- | --- |
| Earlier r4 visual task | native provider_failed; socket access denied | no business success |
| IPC-only executor component03 | native provider_failed, tool exit 127; printf inaccessible | correct worker identity and cleanup do not turn it into success |
| Provider-r5 / module-r3 health01 | correct local nonce response, then provider string.get exception | native failure remains a failure |
| Initial module-r5-r3 retirement | partial: supervisor/provider exited while model/executor remained | no invented supervisor wait result |
| Separate remaining-role recovery | original two roles each received one TERM; groups absent | observation is not waitpid proof |
| Provider-r6-r1 startup | stale embedded source pin rejected before any task | zero health samples |
| Provider-r6-r2 current health | complete bounded health PASS | one health sample; no business sample at cutoff |

Earlier source, reports and public snapshots remain under their versioned paths. The [previous published README](README-as-published-82dd4497.md) and [previous publication manifest](../manifests/SOURCE-PUBLISH-as-of-82dd4497.json) preserve the exact prior checkpoint. Later recovery records do not rewrite the original failed tasks.

## Source map

- [Current provider](../../provider/r6-r2/source/) — thirteen frozen production Python modules.
- [Provider r6 history](../../provider/r6/source/) and [provider r5 history](../../provider/r5/source/) — independent previous revisions.
- [Executor r6](../../executor/r6/) and [client r6](../../client/r6/) — durable action receipts, credential and domain validation, and cancellation cleanup.
- [Module source history](../../module/provider-r6-history/) — instance-specific review sources and explicit public projections.
- [Current acceptance metadata](../../acceptance/r6-r2/) — unchanged nineteen case objects, limits and geometry, with the current source binding.
- [Business evidence collector](../../acceptance/r5/business-collector-r1/) — the unchanged frozen collector used with the new source-seal override.
- [Current business original export](../../acceptance/r6-r2/business-original-export/) — bounded snapshot and original receipt capture.
- [Current business registration operator](../../operators/business-r6-r2/registration/) — separate one-use contract registration, no automatic Send.
- [Sender r5](../../operators/r5/) — exact-draft compare-and-swap protection and one Send.
- [Current health checkpoint](../checkpoints/HEALTH-PASS-v150-r6-r2-01.json).

Some source manifests appear as .PUBLIC.json projections. They preserve the original sealed-input SHA and safe source hashes, but deliberately omit private deployment fields. They cannot replace the private runtime manifest. Operator paths and retained-claim digests may be placeholders. Read PUBLIC-PROJECTION-INDEX.json before comparing a projected file against its original hash or attempting a rebuild.

## Next qualification work

1. Run a wholly new visual task and a wholly new Unicode task against the same frozen combination. Use new nonce and text, the complete owner request, and one-use postcondition contracts. Require original action and text readback, business outcome, correct HEPTA foreground, and native task terminal to agree.
2. Exercise the native cancellation, disconnect, late-result, timeout and budget routes. Read the original receipt before attempting recovery. A standalone executor fixture cannot substitute for a native/model-chain case.
3. Complete the fixed nineteen-case protocol and report full success, partial completion, failure, cancellation and recovery separately. Keep sample counts, latency, resource observations and available token use. Health and host checks are auxiliary evidence.
4. Validate external display, rotation and folding separately. Confirm display identity, coordinate mapping, focus and recovery before expanding support.
5. Keep the completed core reproduction evidence. Remaining HEPTA49 and full rootfs bit-level reproduction require their own pinned historical compiler and system-image inputs.

The current publication grants no daily-use, cold-boot or folded-display qualification. Those claims require their own original evidence.
