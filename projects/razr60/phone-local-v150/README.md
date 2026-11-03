# RAZR60 phone-local v150 source candidate

This project records a phone-local GUI model path: GUI-Owl-1.5-2B-Instruct runs through an Android ARM64 llama.cpp server on the phone, the provider runs in the existing GNU rootfs, and reviewed phone tools cross an authenticated local Unix socket to an Android Bionic executor. Mac and Pocket4 are build/operator hosts; the selected request path does not send inference to them.

**Business and daily-use qualification remain pending.** The current r3 was installed and the sole phone operator observed a fresh health task ending native completed with the exact raw model nonce and zero tool events. Its original HTTP attempt took 9.078923 seconds and reported 669 input plus 57 output tokens (726 total). This is one bounded health sample; independent collector verification and business acceptance are separate follow-up evidence. The observed health readback artifact is identified by SHA2565e0840cb877007506a79d0375b47f4a9354d44fa0e7c1f8ed17f951939b4605d and is not embedded with private run text in this source publication.

 The first native r1 health task reached a real model HTTP 200 / stop response in about 8.10 seconds, but the model violated the nonce-only instruction and proposed an invalid open_app operation. The typed guard rejected it with zero tools dispatched; the native task ended provider_failed. This is an observed model-instruction failure, not a successful native health task or business task. The operator's detailed evidence is tracked separately; it must not be replaced with the earlier pure inference health result.

The frozen r1 source and the uninstalled r2 prompt-layout candidate are retained as separate histories. The current frozen provider/r3 adds a dedicated one-use health contract which permits no phone tool dispatch; it requires its own fresh native health result. Original requests, accepted identities and consumed contracts are retained. No current file activates a new root Cargo member, changes the global module catalog, promotes the project to a qualified product profile, or supplies an integration/release approval.

The r5 executor has now passed five actual-phone component recovery cases in 3.970 seconds. Four synthetic commands ran once, and the incomplete-frame case never created an action. Original receipts and stdout independently establish UID/GID2000 with zero supplementary groups, owned-group cleanup, timeout/late-output suppression and duplicate inspect-only behavior. This component result does not qualify the native/model business chain or the fixed 19-item protocol. The exact original evidence is under qa/actual-r5-component.

## Publication baseline

The publication baseline is 2541c380f3f718803983c918f6a20793479c1127, including parent 47430d52ede072c12f83a354e932adc0f3b3905b. It preserves the existing v149 publication at 0152dc425b6eec188dfd0efdd62aa004b59c76c5, the concurrent executable-binding fix at 038f33f85e6b2e4796c369d310ed4e256e23ca78, and that fix's later deployment/recovery records. The original v149 branches are not moved.

The provider's implementation parent is the frozen v149-r1 protocol/typed-tool source, as recorded in its seal. The v149-r2 CLI executable-binding work remains in the Git ancestry and its original project directory. The phone-local provider uses its own fixed HTTP worker and does not launch that cloud CLI.

| Directory | Contents and authority |
| --- | --- |
| provider/r1, provider/r2, provider/r3 | Exact frozen runtime sources in separate histories, one-use business/health contract and inspection helpers, fixed 19-case specification, public config template, projected source seals and offline test programs |
| executor/r4, executor/r5 | Historical r4 and current r5 C++ sources, unchanged rootfs client, Android build scripts, complete pinned vendor inputs and focused host regressions |
| runtime | Pinned llama.cpp CPU build inputs, delivered artifact hashes, and a portable operator build recipe |
| model | Official model/runtime references, model and quantization revisions, licenses, prompt references, acquisition hashes and projected download readback |
| module | Separate startup/guard/sealer source histories with deliberately unsealed public binding templates; runtime activation requires independent private bindings and observed phone state |
| qa/sidecar-recovery-r4, qa/sidecar-recovery-r5 | Historical r4 preparation and frozen r5 stdout-only five-case script; only the sole phone operator executes a fresh suite |
| qa/actual-r5-component | Exact synthetic phone evidence: five cases passed, four executions, 92 manifest entries independently read back, plus original summary and hashes |
| qualification | Current claim ceiling and source/lifecycle references; no guessed business PASS |

PUBLISH-MANIFEST.json binds every published file by size, SHA-256 and Git blob identity. Runtime source bytes retain their original frozen component hashes. Public source seals and metadata explicitly project private retained-claims digests or operator workspace paths and record the original frozen artifact hash. Those projections are not the private original seal bytes and cannot silently substitute for a private installation binding. No model weights, executable binaries, rootfs images, keys, instance-specific key hashes, retained claim bodies, user text, captures, or live raw private receipts are included.

## Frozen combination

| Input | Pin |
| --- | --- |
| llama.cpp | ggml-org/llama.cpp v0.8.0, commit 8642541b255bfb5dc39cd351a178be09013a55d6 |
| Source archive | SHA256 1688a167a8edd9499cdd0c19b8bd044f0fa184b466981977bbf2222d884953a4 |
| Android NDK content | r28b / 28.1.13356709; the original directory name said 28.2.13676358, so use source.properties and input hashes |
| Android CPU | API28 arm64, static C++, armv8.6-a+dotprod+i8mm+bf16+fp16; no Vulkan/OpenCL/Metal/OpenMP |
| Delivered llama-server | 7e8ea2c601bc3415f8698cca00fbe4737a2093873ba0705d749ae8d6908b3176 |
| GUI-Owl official source revision | mPLUG/GUI-Owl-1.5-2B-Instruct at 528ceaec795bbfbe6103bd79e03db849feadfb24 |
| Community GGUF revision | mradermacher/GUI-Owl-1.5-2B-Instruct-GGUF at a0592aa615540e507a918bc6281fdbfc1b441361 |
| Q4_K_M weights | 1,107,410,432 bytes; 5fd2c77781a14a91128928b5bd313252aab076b44682396af4bb2c99667f5ef5 |
| Q8 projector | 445,053,216 bytes; 16748786911f630d0c14869ac28999f77715053a62b2a00d2327021bd6d2afb7 |
| Current sidecar r5 | 30a495061ec8370e15391fd579a254ce35818c7b019725538e0a34755a36ccaa |
| Historical sidecar r4 | 796f223a98553afc83eb875b3a89aa03f07d0d069a3fb5ab953f849a7f8e84c0; root effect identity does not satisfy frozen phone-helper guards |
| Rootfs tool client | b298ac86fdf57dd0c7dc5159febf114ed176398d32ea672c9abda4a6eb621539 |
| Current provider/r3 original seal | 17a438628070a7fffd9d9c3f92221c00ca92134c3dd91532eb5008fe2cf30564; public projection retains runtime source hashes |
| Current module/r3 service source | 804037c9b94a4f5d98bf4335c5703a80c91b2e6109c681216bf2c70ac7d0433a |
| Shared runtime/model/executor service input | a2fe45cff43f7270a43e4d0738ef921812cb534e66ae45fe7b33970612488362; qualification fields describe its historical freeze time |

The final service parameters are loopback 127.0.0.1:18087, one slot, four CPU threads, 4096 context tokens, batch 256, ubatch 128, GPU layers 0, no projector offload, and image minimum/maximum 1024 tokens. The earlier 768-token pure-text health result belongs to an earlier combination. The provider retains eight model rounds, seven tools, a 120-second model-round bound and a 300-second turn bound.

## Interfaces, state, and ordering

Affected logical boundaries are MOD-PROVIDER, MOD-TOOL-RUNTIME, MOD-ROOTLINUX, MOD-ANDROID and MOD-EVIDENCE, using the existing MOD-PROTOCOL, MOD-TURN-ENGINE and MOD-EVENT-STORE contracts. This is a project candidate involving D2/D3/D4/D5 concerns; publication alone supplies no required maintainer, architecture, semantic-authority or release approval.

For r3 health, the raw model JSON summary must equal the new nonce exactly. The grammar leaves summary as an ordinary string rather than forcing the nonce with const or enum. Both decision validation and native-frame emission forbid tools. One HTTP 200/stop attempt, exact original owner bytes, original request/response hashes, joined worker and idle inference slot are required before health-outcome can pass. Native completed and zero tool events still require independent journal verification. The existing native display layer adds `[无动作；业务未独立验证] ` before the model summary; this is recorded separately and is not claimed to be nonce-only native display text. A health PASS does not establish business qualification.

The native r5 task protocol remains the authority for native tool acceptance, start, output and terminal frames. The provider emits a genuine shell.exec call with the pinned Python client argv. It never executes a model-authored shell string; reviewed typed mappers construct the command and bind current screen/focus/text observations.

The sidecar protocol is a four-byte big-endian JSON length over abstract hepta_phone_local_v150. Both directions require an approved SO_PEERCRED UID. One effect may run at a time. A new action ID and command hash are durable before fork; an original action can be inspected but never redispatched. Timeout, cancellation and disconnect require owned child/group cleanup and a preserved original receipt. r4 preserves the global recovery gate across restart for a sealed but indeterminate receipt. r5 retains that rule and the root journal owner, while the same owned child clears supplementary groups and changes real/effective/saved UID and GID to2000 before its verified startup handshake and exec. The frozen Unicode and screenshot helpers require this Android shell identity. There is no su wrapper or extra credential-helper process.

The provider action ledger prevents a new call ID or turn from bypassing an unresolved original effect. Reservation, inspection and resolution use one filesystem lock. A known cancellation before the native tool frame is distinguished from an uncertain dispatch. A visual contract allows one selection attempt; a Unicode editor contract allows one input attempt. Business success still requires exact public readback, business receipt, verified HEPTA foreground and a consistent native task terminal.

## Build and reproduce

Source publication is not a new Android rebuild record. The original build/provenance records identify the delivered binaries. The included portable CPU recipe validates the source archive, full source manifest, actual NDK input hashes and CMake version before building in a new directory:

    python3 runtime/build_android_cpu.py \
      --source /absolute/llama.cpp-8642541b255bfb5dc39cd351a178be09013a55d6 \
      --source-archive /absolute/verified-source.tar.gz \
      --ndk /absolute/pinned-ndk --out /absolute/new-build-directory

The official archive URL and expected SHA are in runtime/SOURCE-REFERENCE.json. Obtain external inputs through the operator's permitted network mechanism; these recipes do not alter proxy, credentials or host configuration. A relocated build may have different embedded path bytes. The resulting receipt reports exact output hashes and comparison with delivered bytes, without claiming arbitrary-path bit identity.

For the sidecar:

    python3 executor/r5/build_android_r5.py --ndk /absolute/pinned-ndk --out /absolute/new-android-executor-build

Vendored JSON/hash sources are pinned to the same official llama.cpp commit. executor/r4/materialize_vendor.py can verify or restore missing historical r4 vendor files from that exact, already obtained source tree. It performs no network or phone operation.

A Linux host may reproduce only the r4 sealed-unknown restart regression in a new output directory:

    python3 executor/r4/run_targeted_r4.py --out /absolute/new-linux-fixture-directory

That helper builds a HEPTA_TESTING binary, uses a fresh abstract fixture socket and synthetic files, and preserves the new result. The production Android build has no fixture UID allowance. The four r5 host checks independently cover identity, cancellation after verified credentials, pre-exec credential failure plus restart blocking, and actual production refusal under a nonroot parent. Host fixtures deliberately retain their actual host identity; Android UID2000 is established only by the later actual-phone component evidence. The retained 17 r2 checks, five r3 regressions and one r4 regression are component evidence with different source identities; they are not 23 model tasks and not the fixed 19-item phone protocol.

Provider tests remain separate synthetic local fixtures:

    python3 -B provider/r1/tests/local_provider_checks.py
    python3 -B provider/r1/tests/local_contract_capacity_checks.py
    python3 -B provider/r1/tests/local_capacity_race_checks.py
    python3 -B provider/r1/tests/local_action_fence_checks.py

## Deployment, recovery and rollback

The public templates cannot start a production instance. A private instance must supply observed config/claim/key bindings, retain every accepted identity and consumed contract, and verify the actual phone bytes before starting. The module source contains no SEALED marker and performs no automatic health request, task, resume or effect replay. The final module/r3 also removes the unsupported `--` argument from the two BusyBox group-signal calls; the exact phone-observed compatibility reason is recorded in SOURCE-PATCH-KILLCOMPAT-v150-r3.json. Older module sources remain historical and are not the selected current service.

Runtime startup still uses the existing legacy native profile; the source audit describes the remaining local legacy-relay coupling and the later formal phone_local profile/rootfs work. A locally running model does not by itself prove cold-boot persistence or a complete independent user task.

Stop admission first, then reconcile the original model worker/slot and sidecar action receipts. If an effect may have happened, inspect it and current public state before authorizing only the unfinished portion of a new task. Preserve claims and sealed unknown receipts across rollback. Replacing a source file, clearing a claim or changing the action ID is not an approved recovery method.

## Qualification still required

- A fresh native nonce-only health task must actually honor its contract.
- New visual and Unicode tasks must satisfy the complete one-use business contract.
- Native in-flight disconnect, started-tool cancellation, late-result handling, timeout and budget exhaustion require actual native/model evidence.
- The five-case r5 sidecar component test passed on the phone. Its own 70-second safety bound is not a product budget-exhaustion test, and its direct client path is not the native r5 tool-ledger cancellation chain.
- The fixed 19-case protocol needs per-case sample counts, real outcomes, latency, resource and available model usage data.
- Only the existing display0 portrait 1224×2992 guard is claimed by the source. Outer screen, landscape and fold changes each require physical identity/coordinate/focus/recovery observations.
- Current-boot service startup, cold boot, real host/USB removal, full descendant quiescence and complete HEPTA49/rootfs bit reproduction remain separate gates.

The actual r5 component summary SHA256 is 3006a16eb0c7014235a936483329aa51b1b881e02dbe028d551a4105f7358eff; its original evidence-manifest SHA256 is 4a11316b288591d9bf53fa8e5535a97f1595e7b436398e0248aa65328419a403. Synthetic raw evidence is retained so readers can distinguish no dispatch, cancelled, timed out and completed originals instead of treating them all as business success.

Use qualification/STATUS.json for the publication claim ceiling. Consult the original component manifests and any later independently published evidence, not this README alone, to decide whether the exact active combination is usable.
