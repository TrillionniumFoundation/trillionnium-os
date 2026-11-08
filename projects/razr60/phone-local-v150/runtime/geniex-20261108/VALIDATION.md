# Snapdragon 8 Elite local inference validation

Evidence date: 2026-11-08. This is a candidate runtime validation record, not a production Hepta qualification certificate. Subsequent QAIRT results must be appended with their actual inputs and outcomes.

## Current outcome

Actual disconnected Android execution has established Hexagon v79 inference on the target Snapdragon 8 Elite. The hardware-targeted **Qwen3-VL-4B W4A16 QAIRT candidate has passed a text smoke, two image-position cases, and two revised strict-JSON click-decision cases**. An earlier action-prompt case failed JSON syntax and remains recorded as failed. No generated decision was executed on the phone. The full Hepta APK-to-model-to-action path remains unqualified.

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

The QAIRT sampler has a grammar implementation in fixed source, but the actual discriminator failed at runtime. Passing a grammar flag is not proof that constraints work. The candidate integration therefore keeps QAIRT grammar disabled and checks complete native output against JSON syntax, the original strict action schema and the current observation after generation. Malformed output is rejected without repair or action execution. Grammar evidence is `evidence/qairt-grammar-r3/PROTOCOL-CHECK.json` (SHA256 `18368bade247c7f85b3eac5815c0af61a4ec08ef2e533339402027153c6c3be5`); recovery is `evidence/qairt-recovery-r4/RECOVERY.json` (SHA256 `f6d4ef5b595bcf7a64279e6b104d650eff3ea8c30fad1743d85098bd5a6cc4ab`). Recovery does not convert the original failed grammar case into a pass.

The requested QAIRT power mode is sustained performance (enum 6). Fixed source shows that it overrides the bundle's burst default. Successful QAIRT power votes are not logged by the compiled INFO/WARN macros, so source/config and absence of power errors do not establish actual frequency, utilization or watts.

### SDK tokenizer and context admission

The frozen Android token-count helper uses the same official `libgeniex-proc.so` tokenizer C ABI as the model runtime. It preserves the model tokenizer's NFC normalization and ByteLevel handling; it does not replace real tokenization with UTF-8 byte counts. The helper loads only the tokenizer library and data, without creating a model or opening the NPU. Its Android binary is 19,416 bytes, SHA256 `09c2c8fb4b0c0095ffe612be82bc1b2124d47f9351c53fd0a77384c74395589c`.

Two distinct real-phone counts were compared to the already-recorded SDK runs of the revised image prompts. Both counted 148 text tokens across the exact two QAIRT formatter segments, plus 256 image pads, two image boundary tokens and a one-token BOS upper allowance, yielding **407**. Both original SDK runs also reported **407** prompt tokens. Counter process times were approximately 1.260 and 1.074 seconds. Source input, tokenizer/library, segment and formatted-prompt hashes were checked. The accepted general contract is SDK prompt tokens in `[counter_upper - 1, counter_upper]`; these two cases had delta zero. This is a conservative bound with at most one optional BOS token, not a claim that every unseen prompt has been measured.

The first comparison harness incorrectly required delta one. Its original failure record remains byte-identical; the supplemental assessment applies the actual zero-or-one contract to the original evidence without rerunning that first case. The second counter run and supplemental assessment are in `broker/evidence/token-counter-r1/phone-count-r2/PHONE-COUNT-COMPARISON.json`, SHA256 `028c9b0ae03ce702f3a62506cf9724e71e2230db3e0629653d363022792536f5`. These are root, network-isolated tokenizer checks, not production-domain or real App actions.

The candidate admission budget is 3584 prompt tokens, 256 output tokens and 256 reserved tokens within the compiled 4096 context. Its broker runs the counter before the worker in the same supervised process group, and then requires both matching formatted-prompt identity and a matching actual SDK token range before accepting output. Full real-catalogue prompt and production-domain qualification remain separate gates.

### Grammar failure source analysis

`QAIRT-GRAMMAR-FAILURE.json` records a source-level explanation for the actual discriminator abort: the fixed QAIRT model prepares a grammar-aware sampler and initializes it with input prompt tokens; the processor's acceptance path feeds those tokens into the attached output grammar. This is consistent with the observed EOG constraint exception. No patched SDK or per-token exception trace was tested. The runtime remains unpatched and grammar remains disabled in the candidate.

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
2. Completed for the stated synthetic cases: actual QAIRT loading, text and image correctness, plus revised complete-JSON decisions. The original malformed-JSON failure and subsequent grammar abort remain unchanged. QAIRT grammar is disabled in the candidate integration; realistic held-out screens remain pending.
3. Completed for two recorded image prompts: actual phone tokenizer/SDK context comparison. Full real-catalogue provider prompts and unseen multi-round admission remain separately tested; do not infer a larger context from the source checkpoint.
4. Real native-supervisor permissions, bounded cancellation and process termination evidence for the new backend.
5. Fresh natural-language requests from the Hepta APK through the local model to real reversible app actions on an unlocked phone, with postcondition checks.
6. The project's complete acceptance suite. Existing frozen qualification counters and unresolved historical claims remain unchanged by these new unit and inference tests.

Earlier read-only device checks confirmed that the screen was off and keyguard reported `showing=true` / `mIsShowing=true`; the owner emergency-stop remains present with SHA256 `ff6401f96ef8d2206e61e9fdf6d75d1dd11fe25f5696d7f6996b6647023fdb07`. The GNU root has no matching active mount. No unlock, stop removal or production bootstrap was performed by these inference tests.

**Later device-state update, approximately 11:41 UTC:** an additional read-only check found `showing=false`, `mIsShowing=false`, `inputRestricted=false`, `secure=false`, `SCREEN_STATE_ON` and `AWAKE`. No test runner performed a wake, unlock or UI action. The earlier locked-screen snapshot is historical and must not be presented as the current blocker. The owner-stop digest remains unchanged, bootstrap is stopped, and no model-worker process remained after the catalogue test. Production runtime/domain and App acceptance remain separate from the changed screen state.
