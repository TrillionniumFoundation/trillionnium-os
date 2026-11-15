# Hepta one-turn native VLM protocol, v1

Status: the r5 Android native worker compiled from the frozen SOURCE.json is 147544 bytes, SHA-256 27aa467faa1be26dc97e3290178eb208b3705bfb13df8e034d9b04bd5eace781. The original build receipt and executed 23-check linked-backend host receipt are preserved as provenance/ANDROID-BUILD-R5.json and provenance/LINKED-BACKENDS-HOST-R5.json. This records native compilation only; full APK compilation and r5 ordinary-App GPU/HTP inference remain separate pending acceptance gates. Historical r4 provenance and the actual 45e pre-model backend-load failure remain retained. The unchanged runtime still requires vendor OpenCL APIs and phone acceptance; no business success is claimed.

## Launch and lifetime

The adapter owns the ordinary task's global model slot. Allocate a fresh 32-lowercase-hex **generation** for each native process, retain the same task ID, and allocate a separate 32-hex request ID. Use the existing `OwnedGenerationScope(files, runner, generation, taskId, token)` unchanged and call its `initialEnvironment` before launch. Its six environment fields are mandatory; the legacy unscoped fixture exception is rejected.

```
runner --expected-parent-pid PID --expected-app-uid UID --app-files-dir FILES --generation G --task-id T --request-id R --model-profile PROFILE
```

Exactly this argument order is required. UID must match both real/effective UID and be >=10000. Parent must be the direct process, exact `org.trillionnium.hepta.local` command line, same UID, same `/proc` start ticks and boot ID as the scope environment. Parent death SIGKILL is armed. The worker includes the exact existing generation entry/cleanup implementation and accepts the existing `--hepta-owned-generation-cleanup-v1` invocation. The worker does not release the global model slot or assert process exit/cleanup for itself.

Create all request directories with 0700:

`FILES/runs/G/vlm/R`

Every input below must be a canonical, unlinked regular file owned by the App with 0600 permissions. No overwrite is permitted. Inputs are held open, hashed, and checked for replacement/modification at native stage boundaries.

Set `HEPTA_LOCAL_NATIVE_LIB_DIR` to the canonical installed directory containing the runner and all pinned libraries. Set `LD_LIBRARY_PATH` to the same directory plus `/vendor/lib64` as the existing adapter does. The worker accepts no separate runtime directory and never loads an external model service.

## Inputs

`request.json` is a compact JSON object, optionally followed by one LF, with exactly these 14 fields. Strings contain plain IDs and lowercase SHA-256; numbers are decimal integers. No duplicate or additional fields, alternate escaping, or insignificant whitespace is accepted. Property order is preserved by the pinned JSON implementation; Java's compact JSONObject output is appropriate for these simple values.

```json
{"schema":"hepta.vlm.request.v1","profile":"gui-owl-1.5-4b-instruct-i1-q4_0","request_id":"R32hex","generation":"G32hex","task_id":"T32hex","owner_sha256":"sha64","prompt_sha256":"sha64","system_sha256":"sha64","image_sha256":"sha64","grammar_sha256":"sha64","max_tokens":256,"deadline_monotonic_ns":123456789,"image_width":1080,"image_height":1920}
```

`deadline_monotonic_ns` is the original `System.nanoTime()` deadline, still in the future and no more than 300 seconds away. It is never renewed. `max_tokens` is 1..256. Image width/height must match the original PNG, at most 8192 per side and 24 million pixels. Parent must independently kill and wait on its exact Process at the deadline; NPU/GPU kernels are not assumed promptly interruptible by the SDK's CPU-only abort callback.

The other input files are `owner.json`, `prompt.txt`, `system.txt`, `screen.png`, and `decision.gbnf`. Their complete bytes must match the manifest digests. Use the unmodified original PhoneObservation screenshot; do not resize it in the adapter. The worker decodes those same bytes once. The vision encoder's own bounded dynamic-resolution preprocessing remains enabled with image_max_tokens=1024.

`owner.json` is a snapshot exported by the controller/adapter, not model output. It has these mandatory fields and may retain additional original evidence:

| Field | Required value |
|---|---|
| schema | `hepta.vlm.current-frame.v1` |
| task_id, generation, request_id | Same T/G/R as launch |
| scope_token | Same exact token as OwnedGenerationScope environment |
| observation_id | Original PhoneObservation ID, nonempty, <=128 bytes |
| background_generation | Original background ownership generation, <=128 bytes |
| task_owner_sha256 | SHA-256 of the actual original task/display owner evidence |
| image_sha256, grammar_sha256 | Same current-frame input hashes as request.json |
| image_width, image_height | Original screenshot dimensions |
| package_name | Actual current observed package, <=256 bytes |
| display_id | Actual non-main display ID >0 |
| window_id | Actual observed window ID >=0 |
| rotation | Original rotation 0..3 |
| captured_elapsed_ms | Original observation capture time; never refreshed |

Native verification proves binding and immutable inputs, not freshness or current registry ownership. Before accepting the result and before dispatch, Java must revalidate its active task token, original owner evidence, display generation, observation/grammar identity, cancellation, and all existing prompt/action-domain restrictions. Keep the existing business evidence and purchase boundaries.

`decision.gbnf` must be the **exact current controller DecisionGrammar**, with rule `root`. The worker does not generate, widen, translate, or substitute an action grammar. It does not parse or dispatch tools. It renders the model's own GGUF template with system + image + original prompt, enable_thinking=false and force_pure_content=true, then uses GBNF followed by greedy sampling. Extra media markers supplied in prompt/system are rejected. Native tools arguments are omitted.

## Profiles and model files

Explicit profiles only:

* `ui-venus-2-9b-q4_0`: `FILES/ui-venus-model/UI-Venus-2-9B-Q4_0.gguf` and `mmproj-UI-Venus-2-9B-f16.gguf`.
* `gui-owl-1.5-4b-instruct-i1-q4_0`: `FILES/gui-owl-model/GUI-Owl-1.5-4B-Instruct.i1-Q4_0.gguf` and `GUI-Owl-1.5-4B-Instruct.mmproj-f16.gguf`.

Complete sizes/SHA-256 are compiled into `native/vlm-worker.cpp`. Every invocation fully hashes both files and retains their FDs; llama/mtmd open `/proc/self/fd/FD`, not an unbound path. Both profiles also independently pin embedded architecture, tokenizer pre, and template hash. GUI-Owl's verified template is 5292 UTF-8 bytes, SHA-256 `3636d0f0bd6bef02654cdffdc447b79cb2cef8ab02cc75267345946291a489e4`, tokenizer pre `qwen2`.

Devices are fixed to main `HTP0` and vision `GPUOpenCL`. Device absence, loading failure, or missing vision capability ends the request. There is no alternate model/device retry. The CPU backend is registered for host scheduling and unsupported kernels required by llama; **zero CPU operations is not claimed**. Graph placement/performance and actual phone support still need device evidence.

The pinned GenieX build sets `GGML_BACKEND_DL=OFF`: libggml.so links CPU, Hexagon and OpenCL, and its registry constructor registers those backends. Their shared objects do not export the dynamic-plugin entry `ggml_backend_init`. r5 makes no ggml_backend_load/load_all call and does not manually re-register CPU. Before llama_backend_init it requires exact registered names and ownership: CPU registry/device of type CPU, HTP registry/HTP0 device of API type GPU, and OpenCL registry/GPUOpenCL device of API type GPU. The pinned Hexagon API's GPU enum does not relabel the physical NPU. Missing or mismatched registration fails closed before model loading; CPU is never returned as the model/vision selection. The unchanged receipt still does not prove zero CPU operations or instantaneous accelerator utilization.

The r5 builder runs the production helper against a linked host registry without a generic plugin-init symbol, then checks actual SDK DT_NEEDED/import/export facts and forbids worker imports for plugin scanning, manual registration and automatic best-device fallback. These checks do not execute Android backends. The native result schema and its 88 successful fields remain unchanged.

Context is 8192, batch 256, ubatch 128, threads 4, one sequence. The actual image-containing chunk collection is tokenized once, both its token count and position count are admitted against `8192 - max_tokens - 16`, and the same retained chunks are evaluated once. No KV shift/truncate path exists.

## Outputs and acceptance

Create-only outputs: `gguf-chat-template.jinja`, `formatted-prompt.txt`, `chunks.json`, `raw.txt`, `native-result.json`. Some sidecars may exist on failure; missing final receipt is failure, never success. Raw text is the unmodified sampled token text, with no action translator or postprocessing. EOS is not emitted as text.

`native-result.json` has schema `hepta.vlm.result.v1`, all T/G/R/scope/profile bindings, all input SHA-256, the generation identity SHA, model/projector pins, original `current_frame` object, actual template/tokenizer identity, formatted prompt SHA, chunks SHA and actual token/position counts, prefill rc and returned positions, raw byte length/SHA, generated token count, eog status, native rc/error, monotonic timestamps, parent/scope final checks, and explicit non-authority fields.

Explicit process identity fields are `app_uid`, `app_pid`, `worker_pid`, `expected_app_uid`, `expected_parent_pid`, `app_start_ticks`, `boot_id`, `parent_death_signal` (9), `parent_verified_before`, `private_scope_verified_before`, and `observed_parent_pid_before`/`observed_parent_pid_after`. They bind the already verified scope environment and `/proc` lifetime, not caller-supplied process claims.

Successful inference requires exact held Process **exit 0**, receipt `native_return_code=0`, `generation_completed=true`, `eog_observed=true`, `full_multimodal_admission_passed=true`, `same_chunks_counted_and_evaluated=true`, `parent_verified_after=true`, `scope_unchanged_after=true`, all request/raw/sidecar bindings, and the unchanged `OwnedGenerationScope.finish()` proof. Then still pass raw text through the existing controller ActionDecision + DecisionGrammar + dispatch authorization. A receipt's `process_exit_observed=false`, `cleanup_known=false`, `action_authorized=false`, `actions_dispatched=false`, and `business_completion_verified=false` are intentional: native inference cannot supply those app-level proofs.

Exit codes: 0 completed EOG; 65 output token limit; 74 native/inference/publication failure; 78 boundary refusal; 124 cooperative deadline; 130 cooperative cancellation. Parent-observed forced/signal termination stays explicit. The new runner must use a new APK artifact name; neither the historical diagnostic runner nor its receipts are overwritten.


## Final receipt additions

The final r4 receipt also includes model_filename, model_bytes, projector_filename, projector_bytes, tokenizer_model, model_files_full_sha_verified, and runtime_files_full_sha_verified. The verified flags become true only after the actual full-file SHA pass. template_now_unix_ms is the real template-rendering wall clock (the default common-chat system clock), not a substituted date. The original observation capture clock and monotonic inference deadline remain unchanged.
