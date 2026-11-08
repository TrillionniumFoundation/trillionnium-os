# Hepta GPU diagnostic candidate

Independent Android package `org.trillionnium.hepta.gpuprobe`, label `Hepta GPU 验证`. No Internet permission, Accessibility service, provider, receiver, or phone action execution. Its installed PIE worker runs under this app UID. This candidate is not a qualified phone agent. The separate QAIRT app is unchanged.

Uses the already cached GenieX 0.10.0, exact source 071f609995470bdb0e0769ab964754adfaab7e47 and llama.cpp 19cce6919992fdffd92e0ac152caaf1e2b8f254e. SDK binaries are hash-pinned in assemble_pocket4.py and excluded from source control.

## Models

Import cached third-party mradermacher GGUF conversions, based on official mPLUG GUI-Owl-1.5-2B-Instruct, into app-private `files/model-llama/model.gguf` and `mmproj.gguf`. No model is bundled or downloaded by the app. Existing acquisition metadata pins quantized revision a0592aa615540e507a918bc6281fdbfc1b441361 and official base revision 528ceaec795bbfbe6103bd79e03db849feadfb24; local hashes match its LFS pointers.

| File | Bytes | SHA256 |
|---|---:|---|
| model.gguf | 1107410432 | 5fd2c77781a14a91128928b5bd313252aab076b44682396af4bb2c99667f5ef5 |
| mmproj.gguf | 445053216 | 16748786911f630d0c14869ac28999f77715053a62b2a00d2327021bd6d2afb7 |

## Diagnostic entry

Activity `.MainActivity` has normal text/image buttons and Stop. Explicit test Intent extras: `auto_run=true`, unique `case_id` (ASCII letters/numbers/dash/underscore, 1..96), `mode=text|image`, `profile=llama_gpu_cpu_vision|llama_gpu_gpu_vision`, `system_mode=simple|official`, `prompt`, `max_tokens` (1..1024), `timeout_ms` (1000..300000). With `prompt_file=true`, full UTF-8 prompt comes from private `files/probe-prompt.txt`. Image is fixed to private `files/probe-image.png`. Duplicate case IDs refuse replay.

The official 3825-byte mobile SYSTEM asset is pinned by SHA28235cbaf0bd969239f5cdd3f1fa67a59edf8de4a39c49e96011feac2fbf62fe from X-PLUG/MobileAgent commit c4cd0a8f9ddedad24dd8a3daf3a56ca69343849f. Its raw Action plus mobile_use tool-call output is retained without being executed.

`files/triggers/<case_id>.json` binds prompt/system hashes and runtime to `run_id`. `files/runs/<run_id>/` contains full app/native receipts, stdout/stderr, raw text, original image, processed PNG, and exact source prompt/system. A successful exit or syntactically plausible tool call alone does not establish a correct GUI decision; independently verify the fixture target.

## Budget and backend gates

Context is explicitly8192. Text uses LLM mode, without ViT initialization. Images retain original bytes and are explicitly scaled without cropping to at most262144 pixels; transform geometry is recorded. That pixel ceiling is not used as a token-count estimate.

After the actual GenieX chat formatter, a separately loaded vocab-only model and the exact MTMD placeholder API count every text/image chunk. The counter reproduces metadata min/max or the exact OpenCL <=1GiB allocation override to max1024 image tokens. It does not encode a placeholder. Admission requires input+generation+64 <=8192. The actual generation profile must report exactly the counted prompt tokens, otherwise result is failed with raw evidence retained. SDK backend coercion, known vision retry/fallback logs, missing vision-load logs, receipt mismatch, unknown process exit, timeout, or cancellation also fail completion. Ordinary-app-UID OpenCL execution must still be established by real-device logs and fixtures.

The CPU-vision profile may still spend significant time in the unmodified SDK's fixed initialization warmup. No CPU-vision reliability claim is made. Stop only controls the Java Process owned by this application; one process-wide request is admitted at a time.
