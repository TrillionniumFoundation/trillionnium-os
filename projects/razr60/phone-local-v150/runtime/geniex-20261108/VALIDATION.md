# Snapdragon 8 Elite local inference validation

Evidence date: 2026-11-08. This is a candidate runtime validation record, not a production Hepta qualification certificate. Subsequent QAIRT results must be appended with their actual inputs and outcomes.

## Current outcome

Actual disconnected Android execution has established Hexagon v79 inference on the target Snapdragon 8 Elite. The hardware-targeted **Qwen3-VL-4B W4A16 QAIRT candidate has passed a text smoke, two image-position cases, and two revised strict-JSON click-decision cases**. An earlier action-prompt case failed JSON syntax and remains recorded as failed. No generated decision was executed on the phone. The full Hepta APK-to-model-to-action path remains unqualified.

The separate R2 QAIRT core repair passed four positive model cases and both full-53-entry catalogue decisions, but its malformed-grammar case aborted. The newer R3 VLM repair now passes all five isolated phone model gates, including graceful malformed-grammar rejection and recovery. The initial R3 provider source passed 31/31 backend host tests and 38/38 original private r9 regressions. Subsequent real-directory admission and startup-health changes have separate local contract results; they cannot inherit those earlier full-suite passes. Production worker permissions and actual App operations remain unqualified; the original fixed19 acceptance remains 0/19. The new R3 full-catalogue run is awaiting reconciliation after a connector-level launch-acknowledgement failure. Detailed original and follow-up evidence is retained below.

The existing GUI-Owl 2B GGUF model/runtime combination has **not passed visual grounding**. `MODEL-CANDIDATES.json` records the selected QAIRT bundle's fixed source and download version, compiled context limits, actual test scope and remaining acceptance gates.

## Target and actual accelerator evidence

- Motorola XT2551-3, SM8750 / Snapdragon 8 Elite, Android 16, Adreno 830.
- Runtime hardware identification: Hexagon v79; HTP0 reports `threads 6, hvx 6, hmx 1, vtcm 8 MB`.
- HTP0 and HTP1 are two virtual sessions on physical device 0, not two physical NPUs.
- Debug logs show a FastRPC session loading `libggml-htp-v79.so`, 29/29 model layers offloaded, approximately 1149.13 MiB HTP model allocation and 224 MiB HTP KV allocation at context 2048.
- Fixed power mode: `sustained_high_performance` (GenieX enum 6).
- The tested GGUF visual graph includes an unsupported HTP `UPSCALE` operation on f32 `[92,92,1024,1]`; CPU fallback remains. Full-operator NPU execution is not claimed.
- Per-operator cycle profiling returned `0x8000040e`; no reliable utilization percentage or wattage was obtained. No global DSP permissions were changed to obtain profiling.

GenieX v0.10.0 and its complete Android package are pinned in `ABI-PINS.json` and `RUNTIME-ASSET-PINS.json`. Vendor and bundled QAIRT libraries must not be mixed across releases.

## Qwen3-VL-4B QAIRT acceptance

All 24 regular model files were pushed to a separate phone directory and rehashed before inference. The model loaded its compiled context variants `[512, 1024, 2048, 4096]`. Both no-image and image cases used the VLM API, `model=genie_config.json`, explicit `tokenizer.json`, `n_ctx=0`, `n_gpu_layers=0`, and the fixed QAIRT package.

| Case | Actual output / result | Outcome |
| --- | --- | --- |
| Initial text42 | `42`; all SDK calls zero, EOS, process exit 0; 11.01 s including cold load | Passed |
| Initial image position 1 | Correct upper position; 11.09 s including cold load | Passed |
| Initial image position 2 | Correct lower position; 11.45 s including cold load | Passed |
| Initial nested click 1 | Coordinate `[499,238]` is geometrically inside the blue rectangle, but the 144-byte JSON is missing its outer closing brace | Failed strict JSON; no action; subsequent initial click 2 not run |
| Revised nested click 1 | Native complete JSON, coordinate `[500,250]`, correct screenshot ID and blue target | Passed; 13.47 s including cold load |
| Revised nested click 2 | Native complete JSON, coordinate `[499,728]`, correct screenshot ID and blue target | Passed; 13.54 s including cold load |
| Grammar discriminator | Prompt requests A while `root ::= "B"` permits only B; runtime aborts with `Grammar constraint violated: EOG token not allowed` | Failed; exit 134 after 10.68 s, no worker result/raw output; subsequent grammar image cases not run |
| Required post-abort recovery | New no-grammar request returns native `42`, all SDK phases zero, EOS; no remaining worker process rows | Passed; 10.49 s including cold load |

The revised prompt demonstrates one complete example unrelated to the target coordinate. No output repair, appended brace, substring extraction, or host-generated target coordinate was used. Both revised cases generated 38 tokens from 407 prompt tokens, stopped at EOS and returned zero for every SDK phase. Their original output bytes match the worker's SDK-output digest. These are synthetic screenshot decisions, not real App operation tests.

On the two revised cases the SDK reports image processing of 143.7/142.5 ms, prefill of 1044.6/1057.6 tokens/s, decode of 16.20/15.95 tokens/s and TTFT of 533/527 ms **after model creation**. Cold process duration is approximately 13.5 s; the sub-second SDK TTFT must not be presented as full user-visible latency. These short decision cases are not a fixed-length throughput benchmark.

Original evidence: `evidence/qairt-acceptance-r1/ACCEPTANCE.json`, SHA256 `9b1fbaba62320b4391bc5cdc0f5ac18d00165dcdce3a9e25c91fb252178f0dc8`; revised cases: `evidence/qairt-protocol-r2/PROTOCOL-CHECK.json`, SHA256 `d377fcc3e7bdff78caae85e2be45e6be4a72a708d98489b8b7834b6aadac8211`. The original manifest's `blue_hit=false` follows failed JSON parsing; it does not establish a geometric miss.

The QAIRT sampler has a grammar implementation in fixed source, but the actual discriminator failed at runtime. Passing a grammar flag is not proof that constraints work. The original v1 candidate therefore keeps QAIRT grammar disabled and checks complete native output against JSON syntax, the original strict action schema and the current observation after generation. Malformed output is rejected without repair or action execution. Grammar evidence is `evidence/qairt-grammar-r3/PROTOCOL-CHECK.json` (SHA256 `18368bade247c7f85b3eac5815c0af61a4ec08ef2e533339402027153c6c3be5`); recovery is `evidence/qairt-recovery-r4/RECOVERY.json` (SHA256 `f6d4ef5b595bcf7a64279e6b104d650eff3ea8c30fad1743d85098bd5a6cc4ab`). Recovery does not convert the original failed grammar case into a pass.

The requested QAIRT power mode is sustained performance (enum 6). Fixed source shows that it overrides the bundle's burst default. Successful QAIRT power votes are not logged by the compiled INFO/WARN macros, so source/config and absence of power errors do not establish actual frequency, utilization or watts.

### SDK tokenizer and context admission

The frozen Android token-count helper uses the same official `libgeniex-proc.so` tokenizer C ABI as the model runtime. It preserves the model tokenizer's NFC normalization and ByteLevel handling; it does not replace real tokenization with UTF-8 byte counts. The helper loads only the tokenizer library and data, without creating a model or opening the NPU. Its Android binary is 19,416 bytes, SHA256 `09c2c8fb4b0c0095ffe612be82bc1b2124d47f9351c53fd0a77384c74395589c`.

Two distinct real-phone counts were compared to the already-recorded SDK runs of the revised image prompts. Both counted 148 text tokens across the exact two QAIRT formatter segments, plus 256 image pads, two image boundary tokens and a one-token BOS upper allowance, yielding **407**. Both original SDK runs also reported **407** prompt tokens. Counter process times were approximately 1.260 and 1.074 seconds. Source input, tokenizer/library, segment and formatted-prompt hashes were checked. The accepted general contract is SDK prompt tokens in `[counter_upper - 1, counter_upper]`; these two cases had delta zero. This is a conservative bound with at most one optional BOS token, not a claim that every unseen prompt has been measured.

The first comparison harness incorrectly required delta one. Its original failure record remains byte-identical; the supplemental assessment applies the actual zero-or-one contract to the original evidence without rerunning that first case. The second counter run and supplemental assessment are in `broker/evidence/token-counter-r1/phone-count-r2/PHONE-COUNT-COMPARISON.json`, SHA256 `028c9b0ae03ce702f3a62506cf9724e71e2230db3e0629653d363022792536f5`. These are root, network-isolated tokenizer checks, not production-domain or real App actions.

The candidate admission budget is 3584 prompt tokens, 256 output tokens and 256 reserved tokens within the compiled 4096 context. Its broker runs the counter before the worker in the same supervised process group, and then requires both matching formatted-prompt identity and a matching actual SDK token range before accepting output. Full real-catalogue prompt and production-domain qualification remain separate gates.

### Grammar failure source analysis

`QAIRT-GRAMMAR-FAILURE.json` records a source-level explanation for the actual discriminator abort: the fixed QAIRT model prepares a grammar-aware sampler and initializes it with input prompt tokens; the processor's acceptance path feeds those tokens into the attached output grammar. This is consistent with the observed EOG constraint exception. At this initial checkpoint, no patched SDK or per-token exception trace had been tested and grammar remained disabled. The subsequent R2 and R3 investigations and independent candidate results are recorded later in this document; the original runtime stays unchanged.

### Actual 53-App catalogue and retained-history prompts

The separate provider fixture uses the actual 53-entry registry and actual private r9 `compose_local_messages`, then the candidate's prompt presentation. It preserves the exact synthetic instruction and, for the second case, the complete synthetic open/observe/screenshot history. The registry and original action schema remain authoritative. Private catalogue/body data are not published; public summaries bind their hashes and disclose only outcomes. No phone action is executed.

| Presentation | Native token admission | First-round model decision | Outcome |
| --- | --- | --- | --- |
| Initial compact action menu, catalogue test r1 | First/second prompts 735 / 1943 tokens; both admitted | 79-byte complete JSON with `action=open` and `summary`, but no required `text`; 11.07 s, SDK actual 735 prompt / 18 generated | Original strict schema rejects; second model case not run |
| Required-field explanation, catalogue test r3 | 795 / 2004 tokens; both admitted | 149-byte complete JSON with `action=open`, invalid `screenshot_id` and `coordinate`, and still no `text`; 12.52 s, SDK actual 795 prompt / 38 generated | Original strict schema rejects before the typed mapper; second model case not run |

Both executed models returned zero SDK statuses and EOS, but that does not make their decisions valid. No omitted alias was filled, no invalid field removed, and no coordinate executed. The initial presentation listed allowed field names without expressing all required fields; adding the explicit requirement did not resolve the model's field mixing. The universal click example is a plausible presentation influence, not an established sole cause. These failures block promotion of those presentations despite the smaller image-only click cases passing.

The two preserved public reports are `evidence/qairt-catalogue-acceptance-r1/PUBLIC-SUMMARY.json` (SHA256 `6448c778a48e36dd0ffb7fb42281e0f8c608b8cc298d9c161083d33b412afc1d`) and `evidence/qairt-catalogue-acceptance-r3/PUBLIC-SUMMARY.json` (SHA256 `8cd3ac1c1bdce7350e0ad04e20688203678b7bb52362119b6fc025a4fc618215`). Each ran in the root-only isolated network test context, with 256 output tokens, 55-second worker and 60-second phone limits. Production-domain testing remains pending.

### Backend host regressions

`broker/evidence/host-r2/HOST-VALIDATION.json` (SHA256 `b183add7ed527a576cd958699fa2de97d63c09736d239e9dd0116e531286e815`) pins the exact tested source and preserves preceding fixture failures. The real r6 host native-supervisor suite passed 20/20 (10.744 s), the tokenizer fixture suite passed 20/20 (4.458 s), and the original private r9 regression harness passed 38/38 (7.680 s). Private source-pin import also passed. These suites use explicit host fixtures, not a phone model or production Android domain.

The selector test reaches the original parser through generated actual r9 `daily.main(--geniex-config)`, without CPU `READY`, `model.identity` or slot-cleanup binding; any old HTTP transport call fails that test. CPU mode without its original binding still rejects. Native cancellation at task expiry, process cleanup and unknown-state handling remain tested. The later required-field presentation change received eight relevant contract checks; those checks did not predict or override the actual model failure above.

## Fixed-length text performance

The evidence file `evidence/npu-throughput-pp128-tg64-r3.json` is byte-identical to the corresponding phone-test manifest. Conditions: GUI-Owl-1.5-2B-Instruct Q4_K_M, context 2048, four threads, HTP0, sustained performance, profiling/verbose disabled, one model load, no preliminary warmup, three consecutive repetitions. The benchmark generates random token IDs; this measures throughput, not semantic task accuracy.

| Repetition | Actual prompt tokens | Actual generated tokens | Prefill tokens/s | Decode tokens/s | TTFT ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 128 | 64 | 1216.325367 | 35.042801 | 105.921 |
| 2 | 128 | 64 | 1351.365618 | 35.228343 | 95.639 |
| 3 | 128 | 64 | 1352.093632 | 35.183509 | 95.765 |
| Median | 128 | 64 | 1351.365618 | 35.183509 | 95.765 |

All three runs stopped at the requested length. The whole process took 8.4014 seconds. The phone was USB powered, battery 97%, battery temperature 23.0 C before and after. Battery temperature is not a power measurement.

Earlier CPU/OpenCL measurements used a different llama-bench harness. Those results may be shown separately, but an unqualified speedup ratio would conflate harness, context, batch, and timing differences.

## Correctness and failure evidence

| Case | Observed outcome | Acceptance |
| --- | --- | --- |
| Short text asking for 42 | Correct `42`, SDK success and EOS; repeated in independent runs | Text smoke passed |
| 384x768 synthetic blue-button image, NPU vision and language | Blue button is above; response says below. Image has 288 visual tokens and triggers a minimum-token warning | Failed |
| Same geometry at 768x1536, NPU vision and language | 1152 visual plus 43 text tokens; blue button is above; response says middle | Failed; insufficient visual-token count alone does not explain the error |
| CPU vision with NPU language, same larger image | No semantic result by 240-second timeout; TERM followed by KILL after five seconds; exit 137 | Timed out; no correctness conclusion |
| Official GUI-Owl phone tool prompt, same larger image | Valid `mobile_use` click at `[933,719]`; actual blue rectangle is approximately x 109-891, y 169-319 in 1000-based coordinates | Failed; output was not executed |
| Separate complete GenieX v0.9.3 package | FastRPC v79 session error `0x80000406`, VLM create `-100201`, before generation | Initialization failed; no semantic result |
| Fresh v0.10 text run after the timeout/old-version test | Correct 42 with EOS | Recovery smoke passed, not a production cancellation receipt |

The official-prompt case took 8.38 seconds with 1632 prompt tokens and 48 generated tokens. SDK return codes were zero and the stop reason was EOS; these facts do not turn incorrect coordinates into a pass. See `evidence/official-protocol-vision-failed-r1.json` and `evidence/cpu-vision-control-timeout-r2.json`.

The official phone prompt is from MobileAgent commit `c4cd0a8f9ddedad24dd8a3daf3a56ca69343849f`, `Mobile-Agent-v3.5/cookbook/end2end_usage_mobile.ipynb`. Its text-then-image order matches the tested worker. A template-order defect has not been established.

Potential numerical, conversion, or visual-embedding issues remain unresolved. The community model hashes establish file identity, not conversion correctness. The CPU-vision control used four batch threads and timed out; it is not a completed reference result.

## Offline isolation

Inference ran in a new Android network namespace. Each model script checked that its namespace differed from the parent and that the route table was empty before generation. These checks fail closed. Local model files and phone accelerator libraries were used; no host model service was counted as phone-local inference. Global phone Wi-Fi settings were not changed.

An early `--help` probe revealed a shell-quoting mistake that kept commands in the parent network namespace. It ran no inference, was retained as failed setup evidence, and was replaced by a complete phone script launched through one properly quoted remote command. All inference claims above use the corrected namespace checks.

Timeouts are enforced on the phone, not only on the host ADB client. A host ADB timeout alone would not establish worker termination.

## Single-request worker and production boundary

`worker.c` is a fixed-ABI, one-request candidate. The independently reproduced host suite passed 22/22 tests, including real host TERM/waitpid, hard-kill absence of a final result, cancellation races, negative SDK return codes, invalid UTF-8, output truncation, and private input/output checks. These host tests do not substitute for phone or app acceptance tests.

The actual Android binary is 28,200 bytes, SHA256 `67d4e368da136f74a7ab1022013cf1def64f75ebb32d91962772e28a2363864f`. `ANDROID-BUILD-R2.json` records its compiler and build evidence. It has exercised real create, template, generate, destroy and deinit calls in the phone tests.

The worker preserves original output bytes and SDK statuses, and marks generation completeness separately from action authorization. Its metadata explicitly does not claim a production receipt or an externally observed process exit. Existing Hepta CPU safe-point, cancellation, owner and token-ID receipts are not emulated or weakened.

The installed Hepta native supervisor uses a different UID/SELinux execution context from the root benchmark and imposes a 60-second hard cap. Actual access to DSP device nodes and a new, backend-specific receipt path must be validated before production use. The candidate profile must fit that cap; the old 8192-token profile cannot be asserted for the QAIRT package compiled only through 4096 tokens.

## Verification checklist and remaining tests

1. Completed: fixed-version Qwen3-VL-4B archive verification. The 3,029,730,149-byte archive has locally computed SHA256 `9053855d9b45d2dc1c41b8cc5d7d792887dd1549b8ebf3a7f3dfb0ef5b762599`. All 26 ZIP entries match the earlier fixed-version central-directory inventory and pass CRC checks; 24 regular files were safely extracted, totaling 4,356,290,162 bytes. This is a locally computed digest, not a claimed publisher-supplied SHA. The final 606,561,670 bytes were fetched on AI MAX and reverified after transfer; all 41 source pieces were rehashed during new-directory assembly. No partially downloaded archive was used for phone inference.
2. Completed for the stated synthetic cases: actual QAIRT loading, text and image correctness, plus revised complete-JSON decisions. The original malformed-JSON failure and subsequent grammar abort remain unchanged. The original v1 profile keeps grammar disabled; the separate R2/v2 constrained candidate below is not production-qualified. Realistic held-out screens remain pending.
3. Completed for two recorded image prompts: actual phone tokenizer/SDK context comparison. Full real-catalogue provider prompts and unseen multi-round admission remain separately tested; do not infer a larger context from the source checkpoint.
4. Real native-supervisor permissions, bounded cancellation and process termination evidence for the new backend.
5. Fresh natural-language requests from the Hepta APK through the local model to real reversible app actions on an unlocked phone, with postcondition checks.
6. The project's complete acceptance suite. Existing frozen qualification counters and unresolved historical claims remain unchanged by these new unit and inference tests.

Earlier read-only device checks confirmed that the screen was off and keyguard reported `showing=true` / `mIsShowing=true`; the owner emergency-stop remains present with SHA256 `ff6401f96ef8d2206e61e9fdf6d75d1dd11fe25f5696d7f6996b6647023fdb07`. The GNU root has no matching active mount. No unlock, stop removal or production bootstrap was performed by these inference tests.

**Later device-state update, approximately 11:41 UTC:** an additional read-only check found `showing=false`, `mIsShowing=false`, `inputRestricted=false`, `secure=false`, `SCREEN_STATE_ON` and `AWAKE`. No test runner performed a wake, unlock or UI action. The earlier locked-screen snapshot is historical and must not be presented as the current blocker. The owner-stop digest remains unchanged, bootstrap is stopped, and no model-worker process remained after the catalogue test. Production runtime/domain and App acceptance remain separate from the changed screen state.


## R2 constrained-output candidate and v2 integration

The fixed QAIRT source attached output grammar before seeding prompt history,
and accepted generated tokens again after the proc sampler had already
accepted them. The separately built R2 core validates a fresh output grammar,
seeds prompt history without grammar, then attaches the new output grammar.
It avoids double acceptance only for grammar-enabled requests. No new class
fields were introduced; the frozen worker, proc, model and QNN files remain
unchanged. This is an isolated candidate, not an overwrite of the original
phone runtime.

Core SHA256 is `06e65cbec4de0831e0010c02ff424e197a519f35b137344cb62ff92369abdb5d`.
The actual five-case report is `evidence/qairt-core-r2-smoke/RESULT.json`,
SHA256 `8f8592fff439a7c85512483339b9b2b28c540703bcc6e3337ede0ac2f83760e4`.

| Case | Observed outcome | Qualification |
| --- | --- | --- |
| Prompt A, grammar only B | Native `B`, EOS, all SDK return codes zero; 9.750 s | Positive passed |
| Invalid GBNF | Exit 134, no worker metadata or raw text; uncaught `std::runtime_error` | Graceful-error contract failed |
| Fresh no-grammar recovery | Native `42`, EOS, SDK success; 9.714 s | Positive passed |
| Constrained image 1 | Complete original JSON, coordinate `[500,250]`; 12.358 s | Positive passed |
| Constrained image 2 | Complete original JSON, coordinate `[499,728]`; 12.189 s | Positive passed |

Both image runs used 407 prompt and 38 generated tokens. SDK decode rates
were 16.649 and 16.607 tokens/s, with vision processing 142.8 and 146.0 ms.
SDK TTFT was 537.4 and 528.1 ms after model creation; it excludes the full
process/model-load time. These are short synthetic decision cases, not a
fixed-length steady-state benchmark. All processes ended and no model process
remained. The stop file and original core were unchanged; no UI action ran.

The official outer `geniex_vlm_generate` already contains a `std::exception`
catch; the observed abort cannot accurately be described as a missing outer
catch. A later CPU-only Android probe caught the invalid-grammar exception
both directly and through a C-only dlopen DSO against the unchanged proc.
It also constructed both full real-r9 action grammars successfully. That
probe loaded no QNN/model and is not evidence that the complete SDK exception
path works. Its original report is
`grammar-exception-probe-r1/evidence/phone-probe-r2/RESULT.json`, SHA256
`fb210546856e2eacf5fbf2694c6bf831541685bdfec5de2c6544e166198a9737`.

### Schema conversion and context

The v2 provider uses a separately reviewed standard-library Python converter,
pinned before import. The existing state bind stays `nosuid,nodev,noexec`.
Only the exact reviewed closed mobile/health schema subset is accepted;
unknown constructs fail closed. Conversion retains the original schema and
binds its exact bytes, canonical value, grammar bytes and converter source.
The grammar describes a conservative fixed-order serialization of allowed
JSON values, not every possible JSON spelling. All current App aliases and
full semantic history remain in the model prompt. GBNF is loaded outside the
model prompt, and the compiled 4096 / admitted 3584 budget is unchanged.

The Python converter passed 18/18 host tests, including 4515 integer boundary
cases and an independent C++ GBNF recognizer. A separate private test compared
1075 values against the two original real-r9 schemas and both grammar
implementations, with agreement throughout. The original schemas contain
53 App entries and 13/18 action branches; their generated grammars are
7667/9659 bytes. These comparisons establish the tested schema subset, not
phone task accuracy.

The full backend integration report
`broker/evidence/host-grammar-python-r2/HOST-VALIDATION.json` has SHA256
`f8c045dcc9354f7aecc020963e63e4ecd0d8670d431e21aae55ee447a714ad8e`.
Its 27/27 backend tests exercise the real host r6 supervisor and frozen worker
with an explicit SDK fixture, plus six selector/parser outcomes for each
public/private v1/v2 combination. The private original regression suite
passed 38/38, and source-pin import passed. The host SDK stub does not enforce
GBNF; no phone or model was involved in these host suites.

### Startup boundary

Static installation into new directories verified 78 model/runtime/worker/
counter files totaling 4,630,850,230 bytes plus private sources/configuration.
It did not select or start the backend. The old provider is started in the
Magisk domain, while the existing r6 execute path requires the bootstrap
caller domain. The original bootstrap's fixed two-child supervisor does not
provide a provider-entry hook. A separate init-owned entry and staging policy
are being prepared, with actual identity/capability/mount checks; neither is
activated. The active init_boot_a was backed up read-only as an 8,388,608-byte
image with SHA256
`ff159c91e06c34b0611ed5b071575dded3955e62f263fb5fec7d96b42c19436f`.
No boot partition was written and no reboot occurred in this phase. Actual
phone-worker NPU access and all original fixed19 App/component cases remain
pending. Historical UNKNOWN and retained claims are not cleared or replayed.


## Full 53-entry catalogue constrained positives

The two fresh constrained model requests passed on the actual phone NPU,
using the original 53-entry App catalogue, original owner bytes, original
strict action schema and unchanged typed mapper. This is **two model samples
with the full catalogue**, not 53 tested App workflows. The second input uses
a synthetic blue-target image and a host-constructed three-action history.
No action from either model output was dispatched.

| Case | Counter / actual SDK prompt tokens | Generated tokens | Full process time | Result |
| --- | ---: | ---: | ---: | --- |
| First-round open | 964 / 964 | 37 | 13.445 s | Complete 150-byte JSON; correct alias; strict parser and semantics pass |
| Click after three prior actions | 1991 / 1991 | 62 | 17.098 s | Complete 181-byte JSON; correct target region; strict parser and semantics pass |

Both counters admitted the exact inputs below 3584 before any model ran.
Grammar sizes were 7667 and 9659 bytes; no owner text, allowed alias or semantic
history was removed to fit. All SDK stages returned zero and both results
stopped at EOS. No output repair occurred. SDK decode was 12.056 and 11.146
tokens/s for these short, constrained decisions; these figures must not be
replaced by the smaller image-only 16.6 tokens/s measurement. Counter processes
took 1.063 and 1.045 s separately from the model durations above.

The original and candidate runtime libraries, all 24 model files, owner stop
and retained claims were unchanged after both tests. Every recorded counter
and worker PID was absent, and the terminal process check found no model
process. The test context was root/Magisk in a no-route network namespace,
with phone timeout 60 s plus 5 s kill grace, not an r6 production receipt.
The earlier R2 malformed-grammar abort remains failed; overall runtime and
App qualification remain false.

Original report: `evidence/qairt-catalogue-grammar-r1/PUBLIC-SUMMARY.json`,
SHA256 `9afc4efddaef47d97317ddecaedd1308f9dd72075f96bda467fd641eeb24ce91`.
The terminal job, exact runner/source/runtime bindings and publication scope
are recorded in the adjacent `RUN-BINDINGS.json` and evidence manifest.

## R3 VLM failure handling and explicit profile

The malformed-grammar failure was isolated across the actual SDK C ABI with a
CPU-only backend probe. A local backend catch returned the existing SDK error
normally; the original path let the exception reach the caller despite its
outer catch. This establishes the containment boundary. It does not establish
the exact low-level RTTI or unwind cause. The patch changes VLM generation
error handling only for explicitly requested grammar, uses the existing error
result, and does not change headers, vtables, worker, tokenizer or model.

The built R3 `libgeniex_vlm.so` is 361,152 bytes, SHA-256
`773e23de3f892d2cd9c468e7b0af32e6c254af341d4ed0e7ef0eda95f6ee1d73`.
It uses the already reviewed R2 core. ABI inspection checked all 12 symbols
required by the actual consuming plugin; additional standard C++ dependencies
resolve from the retained original processor library. The independent host
error-path test passed 16/16, while the original method failed the four added
grammar-error cases as expected.

The real phone five-case gate then passed in a new isolated runtime directory:

| Case | Process exit | Full process time | Actual result |
| --- | ---: | ---: | --- |
| Malformed grammar | 70 | 8.926 s | SDK generate=-201201, other seven stages zero; complete failure metadata, zero text bytes, normal cleanup |
| New no-grammar recovery request | 0 | 9.750 s | `42`, complete output |
| A prompt constrained to B | 0 | 9.672 s | `B`, complete output |
| Synthetic image 1 | 0 | 12.653 s | Complete click JSON, [500,250] inside the blue target |
| Synthetic image 2 | 0 | 12.360 s | Complete click JSON, [499,728] inside the blue target |

The failed generation's existing SDK profile still displays `eos`; its nonzero
SDK code, `generation_complete=false`, worker error and exit 70 are decisive.
No output from that request can be accepted. Recovery uses a new request ID;
the failed request is never replayed. The two image cases each counted 407
prompt and 38 generated tokens, at 16.311 and 16.228 decode tokens/s. These
short samples are not a sustained or thermal benchmark.

All 52 original, 52 R2 and 52 R3 runtime files and 24 model files were checked.
The original owner stop and retained claims were unchanged, and no model
process remained. Root/Magisk and a no-route network namespace were used, with
55-second worker and 60+5-second outer limits. Zero UI actions ran. This is not
the production r6/UID2000/phone_worker permission or App qualification.

`evidence/qairt-vlm-r3-smoke/RESULT.json` retains the original 33,849-byte report,
SHA-256 `8af9108bdbbe67d81f4c2b2efcde8ebe0d40f80a1e7e5047ec732aa0b171cfad`,
with all 145 original evidence files. Earlier R2 failures remain untouched.

The new provider profile `qairt-output-grammar-core-r2-vlm-r3-v1` explicitly
binds the repaired VLM path and hash in configuration, intent and receipt. A
changed VLM is rejected before counter/model creation. The full pocket4 host
suite passed 31/31 backend tests, 38/38 original private regressions and pinned
imports. Public/private v1, R2 and R3 each exercised the same six selector
outcomes; those subcases are not added again to the 31-test total. The original
fixed19 acceptance is separate. Host report SHA-256:
`f8271799169d811c5310e9ad66c9a18bd2725c845efb55001e9cc0e9ed74b708`.

The newer full-53-entry fixtures were generated from this exact source with
fresh IDs and the explicit R3 profile, preserving the owner and all aliases.
Their manifest SHA-256 is
`9cb73dfc1008c4e27a2474464fa81a67b7a47bae389e7ea325b9e163119fce98`.
Their phone recheck was submitted using one stable job key; a connector error
prevented launch acknowledgement at this checkpoint. Its state is unconfirmed,
not passed, failed or automatically retried under a new identity.


## Actual Android library layout correction (r4)

Deployment cross-review found a real configuration admission mismatch: the tested
official runtime keeps core/VLM/proc in `lib/qairt`, whereas the initial R3
validator required core/VLM at the plugin root. The flat host SDK fixture did not
exercise this production layout. No runtime libraries were moved or copied to
make a misleading flat configuration.

The r4 candidate preserves the measured six-directory loader order and validates
the QAIRT core/VLM/proc/HTP paths. It rejects earlier same-name core/VLM entries
(including dangling symlinks) before artifact hashing, counting or model launch.
Local contracts pass 15/15, including eight actual shell shadow cases, all exit
65 before later programs. The full 34-test suite, 19 native integration cases
and exact private-source regressions have not run for this revision because the
device connector fails even on host inventory. The earlier 31/38 report applies
only to its original source. See `broker/evidence/runtime-layout-r4/`.

A further startup-health candidate is being prepared separately so that a single
init-owned `serve` instance verifies a fixed model-only health operation through
the production r6 path before opening the provider listener. Its startup identity
must remain distinct from a user request. This work does not qualify the live
UID2000/SELinux path or any App, and cannot inherit either earlier test result.


## Larger native-v79 MoE research update

The current-source investigation identifies MobiInfer Android with
MiniCPM-V-4.7-35B-A3B as a concrete native Hexagon v79 route, not merely
CPU-only expert paging. Its publisher reports OnePlus 13 measurements and
limited image samples. The fixed source keeps original routed-expert
selection by default, uses external tiled expert storage and target-verified
DSpark. This is a different engine from the configured QAIRT bundle.

The author's six-case App record restarts the process for each case and
explicitly retains a prior third-consecutive-request failure/DSP queue issue.
Visual UPSCALE can run on local CPU; greedy equivalence and broad GUI quality
are not established. Source defaults have drifted from older deployment text.
The declared 19,315,173,512-byte bundle and its independently requestable
SHA256SUMS were identified in source, but the manifest was not retrieved and
no MoE weights or APK were downloaded. No result from this project is counted
as a razr test or Hepta action. See `evidence/mobiinfer-v79-moe-research-r1.json`.


## Same-process startup model health gate (health-r5)

The candidate now runs one fixed model-only health request in the same
init-owned `serve` process, before the daily provider can listen. It binds the
real kernel process identity and boot to the original entry intent, post-exec
proof, launch plan and selected backend configuration. It creates no accepted
owner turn or claim, and uses separate startup intent/receipt schemas. The
health schema permits arbitrary bounded summary text; only the original full
output that answers 6 times 7 with `42` passes the later semantic check.

The ordinary request body and receipt were checked for complete AST recovery
after removing only startup-specific branches and restoring owner binding.
Both entry points use the same lock, prior-UNKNOWN scan, counter, worker, r6
dispatch/inspect, waitpid, process-group, budget and SDK completeness checks.
No automatic retry, output repair or App dispatch is introduced.

Review found a post-model signal window in the first draft. The fixed version
restores the original terminating signal handlers before its last sticky
cancellation/deadline check. It rejects ignored/custom inherited handlers.
Six actual child-process signal/handler scenarios, grouped into three tests,
cover cancellation during result validation and termination after restoration
or function return. The model boundary is explicitly stubbed in those signal
tests; no Android inference is claimed. Successful evidence states
`listener_ready=false` and only authorizes the next same-process handoff.

The frozen source manifest is
`broker/evidence/startup-health-r5/SOURCE-MANIFEST.json`, SHA-256
`716e2e5a71955b31494258796de1f0f021cea2ede342446239f2254896283619`.
The local scoped report is `broker/evidence/startup-health-r5/VALIDATION.json`,
SHA-256 `4cd325399460779771792106fdbfae2d976e54d7167031fbc44dcc4817326beb`:
12 health contracts, 15 existing backend contracts, 16 entry contracts and
12 bundle contracts pass. These are separate local suites, not a global App
acceptance score. Two new actual-r6 startup cases are defined but unexecuted.
The exact private overlay closure, full native suites, private 38 regressions,
live stage bindings, init/UID2000 NPU health and actual App acceptance remain
pending. The original fixed19 qualified count stays zero.


Final independent reviews for health-r5 are retained beside the source manifest.
`INDEPENDENT-BACKEND-REVIEW.json` checks all eight changed source/test files and
the ordinary-branch AST, fixed schema and receipt separation.
`INDEPENDENT-ENTRY-REVIEW-r1.json` independently repeats only the three relevant
signal tests (six child-process scenarios) and finds the original swallowed
shutdown window closed. These repetitions are not new acceptance cases.
