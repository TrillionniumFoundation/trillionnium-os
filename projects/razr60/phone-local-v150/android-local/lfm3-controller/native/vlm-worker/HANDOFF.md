# Native VLM r4 handoff

The direct llama/mtmd worker is implemented, genuinely compiled for Android, and integrated as a separate APK member. Native code is frozen at r4. It has not been executed on the phone by this agent.

## Final artifact

* APK member: `libhepta_local_vlm_runner.so`
* Bytes: **147424**
* SHA-256: **33aea41ab348adad9b08ed6ae6f16ffd1fd06a12435d33847549dad276c8bd3e**
* Local runtime directory: `/workspace/scratch/22402a688123/r21_work/vlm-worker/runtime-r4`
* Mac runtime directory: `/Users/qianqi/Documents/Codex/2026-11-15/hepta-r21-vlm-22402/worker-build-r4`
* Build receipt SHA-256: `ee6b209b474f6027962b180d0c02023fa1f4d69616f50ee323e9162280a973a5`
* Frozen source manifest SHA-256: `212221cd0fd29f50ce3aa15a4e3504b648c12cc59847b12e54370fe1c2636a00`

Both source paths in the actual Mac reproducibility test produced these identical worker bytes. The linker uses the existing pinned SDK C++ symbols with `-nostdlib++`; it adds no second C++ runtime. This is Android 30 AArch64 PIE, `/system/bin/linker64`, 16 KiB load alignment, and exactly `$ORIGIN` RUNPATH.

The direct dependencies are libllama-common, libmtmd, libllama, libggml, libggml-base, libdl, libm, and libc. SDK/C++ strong symbol closure was checked against the real pinned SDK libraries and NDK API-30 platform stubs. The OpenCL backend's **35 versioned OpenCL APIs** and `libOpenCL.so` remain an explicit device vendor boundary; no host result is presented as proof of App-namespace visibility.

## What the worker does

It requires an exact App UID, direct package process parent, original parent start ticks/boot ID, parent-death signal, private task-generation directory, and all six existing scope environment fields. The original 678-line owned-generation implementation is unchanged and provides the existing cleanup entry point.

Every request binds task/generation/request ID, scope token, original task-owner SHA, display and window identity, observation/capture identity, original PNG SHA/geometry, and the exact current controller grammar SHA. It reads immutable private files and retains open descriptors. Both model files are fully hashed on every invocation; the SDK loads those held FDs via `/proc/self/fd`.

The two explicit profiles are UI-Venus-2-9B Q4_0 with its F16 projector, and GUI-Owl-1.5-4B-Instruct i1 Q4_0 with its F16 projector. Their complete weights, architecture, tokenizer pre, and embedded template hashes are fixed. GUI-Owl has separately verified tokenizer model `gpt2`; UI-Venus tokenizer model is recorded at runtime and should not be assumed without its metadata evidence.

Main compute selection is fixed to `HTP0`; the visual encoder is fixed to `GPUOpenCL`. Missing devices or model/vision initialization failure terminate the request. CPU host scheduling and unsupported kernels within the selected backends remain possible; zero CPU operations is not claimed. There is no worker-selected CPU model retry, remote API, model substitution, or alternate device retry.

The GGUF chat template is used with the original controller system/prompt, one original image, no native tools argument, and thinking disabled. Common-chat input segments retain their input/special-token distinction. The actual image-containing mtmd chunks are created once; their complete token and M-RoPE position budgets are checked against context 8192 minus maximum output and 16 guard tokens. The exact retained chunks are then evaluated. No truncate, second tokenize, KV shift, or hidden context growth exists.

The image source remains unchanged, but mtmd performs its normal internal preprocessing with `image_max_tokens=1024` and warmup disabled. This is not a claim that the encoder processes the original full resolution. The real wall clock used by template formatting is recorded separately from the original capture clock and monotonic deadline.

Sampling is the exact current-frame GBNF followed by greedy selection. Output is the unmodified sampled text. Only an observed EOG and successful native exit qualify as complete generation. The worker has no phone-action dispatcher and never grants business completion or task authority.

## Integration changes

The shared integration source is `/workspace/scratch/22402a688123/r21_work/vlm-integration/candidate`.

New paths:

* `native/vlm-worker/`: complete frozen source, matching llama/mtmd/common headers and license, build script, protocol, source manifest, provenance, and C guard test.
* `native/local-vlm-runtime-pins.json`: final artifact, SDK closure, model profiles, and OpenCL vendor boundary.
* `tools/build_vlm_worker.py`: rebuilds the fixed source with the supplied existing NDK/SDK and refuses a rebuilt artifact whose complete identity differs.
* `tools/verify_vlm_runtime.py`: binds real Java pins, frozen source, generation cleanup core, build receipt, SDK pins, final worker, and exact ELF imports.
* `tests/test_vlm_runtime.py`: packaging acceptance and refusal tests using the real Android ELF.

Modified paths:

* `tools/build_identity.py` includes both new build/verification tools in compiler input binding.
* `assemble_pocket4.py` requires `LOCAL_VLM_ANDROID_RUNTIME_DIR`, adds the new unique library member, validates its actual ELF and packaged bytes, and records separate static acceptance without device claims.

The original three compiler output checks remain unchanged. `build_mac.py` is byte-for-byte unchanged. All **51 existing native files** compared with the original candidate remain byte-for-byte unchanged. Existing GenieX, MobiMind, UI-Venus pins and their packaging gates remain in place. This agent did not edit Java, manifest, signing material, or the default model configuration.

## Build and assembly inputs

From the integration candidate:

```sh
python3 tools/build_vlm_worker.py \
  --ndk "$ANDROID_NDK_ROOT" \
  --sdk-libs "$GENIEX_ANDROID_LIB_DIR" \
  --output /absolute/new-vlm-build-directory
```

Use a new output directory. The SDK argument is the `lib` directory that contains `llama_cpp/`. The required actual NDK revision is 28.1.13356709 (r28b), although the configured Mac folder is named 28.2.13676358. No download or signing occurs in this command.

Set `LOCAL_VLM_ANDROID_RUNTIME_DIR` to either the verified r4 runtime directory or a matching fresh rebuild directory when the root agent performs normal assembly. Keep all existing runtime environment variables and gates.

## Validation completed

1. Actual library export discovery and public C/C++ API link probe against the packaged SDK.
2. Actual full Android C/C++ worker compile, PIE/dependency/runpath inspection, SDK/C++ strong symbol closure, and HWCAP-contained SHA2 instruction audit.
3. Independent rebuild from a different source directory, producing exactly the same 147424 bytes and SHA-256.
4. **43** executed C host checks: separate token/position capacity, overflow/negative/boundary refusals, UTF-8, private permissions, alias/refile changes, full hashes, atomic no-overwrite output, missing task scope, and parent refusal.
5. **11** executed packaging tests: actual ELF accepted; byte mutation, stale source, Java pin drift, cleanup-core change, SDK hash change, added C++ runtime, false phone qualification, false vendor closure, and altered runpaths/imports refused.
6. Production packaging verifier executed against the real shared candidate's `VlmPins.java` and the final r4 ELF; passed.

These are native/build/contract checks. Full APK assembly, App-namespace driver loading, model inference, instruction quality, thermal/memory/latency, cancellation inside accelerator calls, and ordinary controller tool execution still require the root agent's authorized phone tests. The current first-phone plan is a normal Start run in observe mode, stopping before model action dispatch.

## Parent acceptance requirements

The Java adapter must hold the model slot for the entire task, give each one-shot process a fresh generation, retain its exact `Process`, enforce the original deadline, verify receipt/raw/sidecar bindings, and finish the unchanged `OwnedGenerationScope` before callback or another request. The native receipt intentionally contains `process_exit_observed=false`, `cleanup_known=false`, `action_authorized=false`, `actions_dispatched=false`, and `business_completion_verified=false`.

Only after parent exit/cleanup/ownership validation may the ordinary controller parse the raw decision and apply its existing action-domain, virtual-display, payment, and completion-evidence rules. No native result should bypass those rules.
