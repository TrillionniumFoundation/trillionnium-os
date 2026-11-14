# UI-Venus ordinary-App model-only candidate

This candidate adds an explicit, one-shot private image diagnostic to the existing application. It does not connect UI-Venus output to `LocalInference`, `LocalTaskController`, the action parser, or the accessibility dispatcher. The default text model catalogue, existing private text configuration, task assertions, existing permissions, and original GenieX/MNN native members stay unchanged.

## Independent identities

The added installed PIE is `libhepta_ui_venus_runner.so`, 58,144 bytes, SHA-256 `5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551`. It is a separately compiled App-parent wrapper around the UI-Venus first-frame VLM core. The older shell worker is a different artifact and cannot satisfy the Java or packaging pin.

The complete independent build receipt is preserved at `provenance/ui-venus-app-r1/NATIVE-BUILD-RECEIPT.json`, SHA-256 `3dac4c0e91bd9c088e7330394953f6df74596feff04c7e815672ee8d3392e705`. The original private build used `native-worker/DRAFT-MANIFEST.json`, SHA-256 `d2b91f0e6425c896f3249b8eb156884c08cc31524dd76cd664e3c4455bd3e748`. The current public source derivative uses the same manifest filename with SHA-256 `87842f36e1ff9577235c3855a3e04be139af4c942eb3e1b452f966a8db923776`, after replacing only the cleartext identity guard in a preserved historical validator with fixed-length SHA-256 substring checks. The original historical manifest and native build receipt remain unchanged. This public source identity differs from retained device-build source `883821726a8ed90ea8f8d928017a371942ed238dff3796bce89ab0dfa712f310`; all compiled Java and native C/header/include inputs remain byte-for-byte unchanged. The actual compiler reports NDK revision **28.1.13356709**; the preexisting directory happens to be named `28.2.13676358`. No compiler metadata is rewritten.

The two model files live in the canonical private `files/ui-venus-model` directory:

| File | Bytes | SHA-256 |
|---|---:|---|
| UI-Venus-2-9B-Q4_0.gguf | 5,482,832,672 | 2e881d6e74899b47b1f0c9052abeeb0a7ff55913dfb18d942a3de3cadb3d1adb |
| mmproj-UI-Venus-2-9B-f16.gguf | 918,165,664 | 6ef77c3bf87391664be7cd71c595352e7281dabe52f24e961e2deace550f3af2 |

They come from creator `bartowski/UI-Venus-2-9B-GGUF` at fixed revision `3d2022e8bbe1fb95f12ca530a9d6ef063807d593`. The creator card labels Apache-2.0, while the upstream model's license information was pending/conflicting when reviewed. This candidate does not resolve that discrepancy. Weights are not embedded in the APK. Complete host download SHA checks and complete private-file verification are required before testing; prefix/header qualification alone is insufficient.

## Private request interface

The only trigger is an explicit `MainActivity` intent with `auto_ui_venus_probe=true` and `ui_venus_nonce` containing 64 lowercase hexadecimal characters. Combining it with `auto_mobi_probe`, `auto_task`, or `auto_run` is rejected. All trigger selectors are consumed before checking the request, so Activity recreation does not replay the intent.

The intent supplies no image, model path, prompt, or action authority. The App reads a single private `files/ui-venus-probe-request.json` with exactly these fields:

```json
{
  "schema": "hepta.private-ui-venus-probe.v1",
  "nonce": "<64 lowercase hex>",
  "request_id": "<32 lowercase hex>",
  "fixture_sha256": "<complete FIXTURE.json SHA-256>",
  "created_wall_ms": 1,
  "expires_wall_ms": 2,
  "deadline_ms": 300000,
  "max_tokens": 1024
}
```

The timestamps shown are placeholders, not a usable request. Expiry must follow creation by at most ten minutes, creation cannot be more than 30 seconds in the future, and the request must still be fresh after input verification. A durable exclusive file in `ui-venus-probe-consumed/<nonce-sha>.json` is created before the request is removed. Any failed acknowledgement leaves that claim intact. There is no automatic retry, deletion of the claim, or reuse of its nonce.

The exact input directory is `files/ui-venus-probe-inputs/<request_id>/`. It contains `FIXTURE.json`, `owner.txt`, `system.txt`, `prompt.txt`, `screen.png`, and `official-system-template.txt`. The fixture uses the original `hepta.ui-venus.mobile-first-frame-fixture.v1` schema. Java checks all four input files' complete byte counts and SHA-256 values against the fixture. The official SYSTEM template SHA is `627c1f85167d72994d7d3c9da686456d1e9fd0eb3c8438605a1a8596f6e5efa3`; its only final `{user_task}` placeholder is replaced with the unchanged UTF-8 OWNER. The user prompt is exactly `Current Screenshot:\n`. There is one complete original PNG and explicit initial-frame empty history. This does not authorize dropping an existing conversation's history or calling the experiment a replay of that conversation.

The original PNG is not resized by Java or the worker. The App checks the signature, IHDR fields/CRC, whole-file hash, RGB/RGBA encoding, and the fixed 4096-by-4096/8 MiB input envelope. Actual image decoding and model preprocessing remain runtime gates; synthetic host headers do not prove either.

## Execution and recovery

The new engine uses the existing `LocalModelEngine.ExternalRunLease`. Every request reserves the same process-wide slot as text inference, controller tasks, and MobiMind. The existing visible Stop button cancels that shared lease and its attached child.

At Application startup, the original control session, MobiMind session, and UI-Venus session are all inspected synchronously. Each keeps its own strict clean-terminal policy, side-file checks, and durable interruption latch. No old task or nonce is replayed. Once all inspections finish, any blocked session causes exactly one Application-owned recovery lease to be retained. The MobiMind constructor no longer reserves its own recovery lease. Multiple dirty journals therefore cannot compete for multiple leases or accidentally expose a free model slot.

UI-Venus has its own `ui-venus-probe-session.json`, `.bak`/`.new` interruption checks, `ui-venus-probe-interrupted.json`, trigger receipt, and `ui-venus-runs/<request_id>/` evidence directory. New requests are blocked after unknown process exit or failed durable terminal publication. The lease is released only after an observed child exit (or known no launch) and successful terminal publication. An inference error with an independently observed exit can be cleanly recorded without calling the inference successful.

Native arguments begin with the actual App PID, actual App UID, and canonical App files directory. The wrapper verifies real/effective UID, direct parent PID/UID/package, exact package name followed only by NUL padding in the parent's cmdline, canonical owned private directories, and parent-death SIGKILL. It repeats parent and scope checks after the VLM core. A failed post-check returns 78; failed binding publication returns 74. Java requires the actual owned exit code, the core return code, and the wrapper return code all to be zero for complete inference. A completed core receipt cannot override a wrapper failure.

The separate `app-process-binding.json` explicitly does not claim SELinux-domain qualification or actual runtime maps. Its parent-status hashes can differ as the App runs; the cmdline hashes are each verified against their own exact byte length and allowed package-plus-NUL representation.

## Fixed inference and supervision budgets

The native request is `llama_cpp` VLM, text compute NPU/HTP0, vision device `GPUOpenCL`, context 8192, maximum output 1024, four threads, thinking enabled, and timeout 300000 ms. Only the four main-model identity/profile literals in the VLM runtime include change. The sampler, template handling, complete per-request model SHA checks, and FD bindings remain unchanged. The two models are read through held descriptors and are never loaded into Java byte arrays.

The Java preflight has a separate 30000 ms bound. Native 300000 ms begins inside the core after wrapper identity checks and plugin bootstrap; it includes input reads and full model hashing. The App supervisor starts at successful process launch and allows 325000 ms. On cancellation, log overflow, or supervisor expiry, it sends TERM, escalates after two seconds if necessary, and waits within a 12-second termination-confirmation window. These distinct clocks are recorded; they are not presented as identical native and App deadlines or as a real-time scheduling guarantee.

An 8 GiB available-physical-memory threshold is an engineering admission only, not a measured peak or proof that loading will succeed. CPU assistance, actual tensor/offload behavior, vendor OpenCL mapping, memory use, and thermal behavior require the real phone diagnostic.

## Output and qualification limits

The App retains original raw output, core and App-process receipts, exact formatted prompt, embedded chat template, generation prefix, and diagnostic text-only token IDs. It checks complete EOS, native phase success, two whole-file hashes, exact input/owner hashes, sidecar hashes, requested devices, and supporting SDK token counts. It never parses the raw output into a phone action.

Diagnostic text-only token IDs exclude image expansion and are not passed as VLM inputs. A post-run token total fitting 8192 is supporting evidence only. The receipts keep `full_multimodal_input_qualified=false` and `no_context_shift_proven=false`; they do not silently promote those facts to a full multimodal context guarantee. Requested GPU/NPU selection does not prove every operator ran there.

Host contract passes and Android compilation are separate from ordinary-App runtime qualification, which in turn is separate from semantic GUI accuracy and any future closed-loop task acceptance. The shell candidate remains a distinct test artifact. No model-only success authorizes dispatching output or switching the default text model.

## Build handoff

Build from the final reviewed merged source, with the original GenieX and MobiMind runtime directories. Set `UI_VENUS_ANDROID_RUNTIME_DIR` to the separately built directory containing the new PIE and exact `BUILD-RECEIPT.json`. The assembler verifies the complete new worker pin, preserved source/build provenance, actual ELF dependencies and non-transitive `$ORIGIN` RUNPATH, and signed APK member bytes. It adds one new native member and refuses to replace any of the original sixteen. Existing signer matching and no-INTERNET verification remain required. This handoff does not install or launch the APK.

## Q4_0 identity and measured-evidence boundary

The explicit profile is `ui-venus2-9b-q4_0-f16-mmproj`. The real independent Android build changes exactly four identity literals in `native/venus-runtime.inc`; 18 of the 19 original native C/include members remain byte-for-byte unchanged. The build receipt deliberately records `original_core_byte_unchanged=false` and `only_model_identity_literals_changed=true`. Packaging verifies the original and new native manifests, the exact four substitutions, the actual new worker/build receipt, and the matching Java model pair. It does not reuse the previous worker's unchanged-core claim.

The creator's Q4_0 file is mixed: its complete tensor directory contains 181 Q4_0, 4 Q4_1, 5 Q6_K, 12 Q8_0 and 225 F32 tensors. The Q6_K output matrix alone has 834,355,200 serialized bytes. These header-derived figures describe GGUF storage, not backend placement, converted buffers, physical RAM, or all-HTP execution. The first receipted 16 MiB contains the complete metadata/tensor directory and the same 7740-byte official template, but prefix qualification does not replace the full-file SHA or ordinary-App runtime qualification. No better quality, speed, or measured peak memory is claimed for this candidate.
