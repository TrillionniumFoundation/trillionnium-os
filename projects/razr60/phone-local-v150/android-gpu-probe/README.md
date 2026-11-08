# Hepta GPU diagnostic source — work in progress

**This is an unqualified diagnostic candidate. No Android APK build has been confirmed, it has not been installed or tested on a phone, and it does not operate phone apps.** Only host C syntax checks and the explicitly mocked budget-contract checks below have passed. This source checkpoint is not a release or a statement that GPU inference works on a particular phone.

The independent package is `org.trillionnium.hepta.gpuprobe`, labelled **Hepta GPU 验证**. It leaves the separate `org.trillionnium.hepta.localprobe` QAIRT application and its model data untouched. Its manifest declares no Android permissions, including no Internet permission, and no Accessibility service, provider, or receiver. The sole exported Activity offers diagnostic text/image inference and a Stop button. Explicit test Intents can request diagnostic inference; they cannot execute generated phone actions.

## Purpose and qualification boundary

This candidate compares a cached, mobile-agent-specialized GUI-Owl 1.5 2B model using the GenieX 0.10.0 `llama_cpp` OpenCL backend. The closed profiles request an Adreno/OpenCL language model with either CPU or OpenCL vision. Text-only requests use LLM mode and do not initialize the vision encoder. The selected vision profile is material only for image requests.

Model output is retained in its native `Action:` plus `mobile_use` tool-call format. It is never dispatched. Successful process exit and valid receipts establish only that the diagnostic pipeline completed. Backend execution must be supported by real device logs; image interpretation and GUI decisions require independent fixture checks. A plausible tool call or a model-reported completion does not prove the intended screen was understood.

The CPU-vision path has an unresolved practical concern: the unmodified SDK can perform a fixed vision warmup during model creation. Reducing the input image does not prove that initialization becomes fast or memory-efficient. Neither vision path is qualified by this source publication.

## What the source enforces

The engine keeps one process-wide request and an application-owned engine across Activity recreation. The runner is an installed PIE in `nativeLibraryDir`, executes under the application's ordinary UID, reads app-private input files, and publishes complete raw text and structured receipts. Cancellation controls only the Java Process owned by this application. A process whose exit has not been observed keeps the request gate occupied. The gate is per application; a test operator must also ensure that a separate model application is not running another large model.

The generation context is explicitly 8192 tokens. Images retain their original bytes and are resized without cropping to at most 262144 pixels, with the exact width/height and coordinate scales recorded. This pixel ceiling is **not** treated as a token-count estimate.

After the actual GenieX chat formatter, an independently loaded vocabulary-only text model and the exact MTMD placeholder API count every text and image chunk. The counter uses the same GGUF vocabulary and projector as generation. It reproduces the image min/max defaults and the SDK's specific OpenCL allocation-limit override, disables only the counter's encoding warmup, and never encodes a placeholder bitmap. Admission requires:

```text
exact input tokens + requested output tokens + 64 reserved tokens <= 8192
```

After generation, `profile.prompt_tokens` must equal that pre-count exactly. An over-budget input, missing native symbol, token-count mismatch, SDK device coercion, known vision retry/fallback log, missing vision-load log, receipt binding failure, timeout, cancellation, or unknown process exit cannot become a completed diagnostic result. The real tokenizer, ABI loading, and device behavior still need to pass the first phone test; host mocks do not establish these facts.

## Pinned source and dependencies

| Component | Pinned identity |
|---|---|
| GenieX | 0.10.0, commit `071f609995470bdb0e0769ab964754adfaab7e47` |
| llama.cpp and MTMD | `19cce6919992fdffd92e0ac152caaf1e2b8f254e`, verified GenieX submodule revision |
| Native SDK libraries | Individual SHA256 checks in `assemble_pocket4.py`; no binaries in this source tree |
| GUI-Owl mobile SYSTEM | X-PLUG/MobileAgent `c4cd0a8f9ddedad24dd8a3daf3a56ca69343849f`, exact 3825-byte asset |
| Android build | compile SDK34, target SDK35, min SDK30, Java8 bytecode, NDK28.2.13676358 |

The exact GenieX header, BSD license and upstream NOTICE are retained under `native/vendor`. The exact llama.cpp/MTMD header closure, MIT license, source URLs and Git blob hashes are under `native/vendor/llama`. The GUI-Owl SYSTEM prompt has its own pinned source record and the exact upstream MobileAgent MIT license under `assets`. The broader SDK notice does not add network or cloud-model dependencies to this application. Native SDK binaries and model weights must be obtained separately under their applicable terms.

The runtime Java/native sources, manifest and exact SYSTEM asset are byte-identical to the frozen private candidate; `SOURCE-PROVENANCE.json` lists their hashes. Public changes parameterize build locations, add attribution, documentation, and host tests. The public build scripts have had Python syntax checks only; their Android build is not claimed complete.

## Cached model pair used for the candidate

These are **third-party mradermacher GGUF conversions**, based on the official mPLUG GUI-Owl model; they are not official Qualcomm-compiled assets or official mPLUG GGUF releases. Existing acquisition records pin quantized revision `a0592aa615540e507a918bc6281fdbfc1b441361` of `mradermacher/GUI-Owl-1.5-2B-Instruct-GGUF`, and official base revision `528ceaec795bbfbe6103bd79e03db849feadfb24`.

| App-private filename | Bytes | SHA256 |
|---|---:|---|
| `files/model-llama/model.gguf` | 1107410432 | `5fd2c77781a14a91128928b5bd313252aab076b44682396af4bb2c99667f5ef5` |
| `files/model-llama/mmproj.gguf` | 445053216 | `16748786911f630d0c14869ac28999f77715053a62b2a00d2327021bd6d2afb7` |

Local file hashes and sizes matched the existing acquisition records and LFS pointers. Model/projector metadata agreed on Qwen3-VL, a 2048-dimensional projection, patch16/merge2, and the expected tokenizer family. This does not prove semantic accuracy or establish that the conversion is lossless. The app neither downloads nor includes model weights.

## Build with locally installed tools

`build_mac.py` uses the same environment contract as the sibling local Android application:

- `ANDROID_SDK_ROOT` (or `ANDROID_HOME`): installed Android SDK with platform34 and build-tools34.0.0.
- `JAVA_HOME`: JDK17 directory.
- `ANDROID_NDK_ROOT`: optional NDK root, defaulting to SDK `ndk/28.2.13676358`.
- `GENIEX_ANDROID_LIB_DIR`: the pinned GenieX Android arm64 distribution's `lib` directory, including `libgeniex.so` and `llama_cpp/`.

Run `python3 build_mac.py` on a Mac with the NDK Darwin toolchain. To assemble with the cached SDK libraries, run `python3 assemble_pocket4.py` in the same source tree with `GENIEX_ANDROID_LIB_DIR` set. Assembly tools are resolved from `APKSIGNER`, `AAPT2`, `READELF`, and optional `KEYTOOL`, or their corresponding commands on PATH. No script installs dependencies, downloads models, connects to a phone, or executes ADB.

A new debug signing key is generated locally under ignored `keys/` when none exists. Keys, APKs, native binaries, generated build logs and device data are excluded. The proposed output name is `out/hepta-gpu-probe-0.1.0.apk`; no such successful APK is claimed by this checkpoint. Signing and package verification must complete before installation.

## Run the bounded host contract checks

```sh
python3 tests/run_budget_contract.py --out /tmp/hepta-gpu-budget-check
```

The output directory must be new. The committed summary records **16 boundary scenarios and 288 assertions passed** against the exact candidate counter with mocked ABI functions. Checks cover text preservation, special-token flags, vocabulary-only loading, the 8192 admission boundary, missing symbols, overflow, image bounds, the precise 1GiB OpenCL branch, CPU defaults, chunk-token totals, resource cleanup, and exact post-generation profile matching. No real model, tokenizer, GPU, Android process, or phone is exercised by these tests.

`GPU-PROBE.md` documents diagnostic Intents, unique case IDs, receipt paths, and the official prompt option. Full native/app receipts, stdout/stderr, original and processed images, and prompts belong in the application's private test records; they are not part of this public source checkpoint.
