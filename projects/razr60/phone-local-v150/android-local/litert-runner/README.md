# Hepta LiteRT-LM one-shot runner candidate

This is a **host-tested, text-only integration candidate**, separate from the
installed Hepta application. It calls the real LiteRT-LM C API, and never
executes model tool calls or phone actions. No model, Android execution, GPU
dispatch, NPU dispatch, or business-task success is implied by its build or
host fixtures.

## Pinned inputs and provenance

The runtime is Google LiteRT-LM **v0.19.1**, released 2026-11-05, C API **1.0.0**.
Official release asset:

https://github.com/google-ai-edge/LiteRT-LM/releases/download/v0.19.1/litert_lm_c_api-1.0.0.zip

The complete archive was downloaded and verified on pocket4:

- Size: 123,469,788 bytes.
- SHA-256: `1d430d80eaf536f696a4922270ba55eb3d112189ac198c3066d487a45e3b4d4c`.
- Android member: `lib/android_arm64/liblitert-lm.so`.
- Android member size: 22,758,512 bytes.
- Android member SHA-256: `d000b46697a43bfae6181f280240ddeff08ef25049902f42d54b35c519ec7764`.

Actual ELF inspection found AArch64 ELF64, 16 KiB LOAD alignment, an Android
API 24/NDK r29 build note, and versioned `LITERT_LM_C_API_1.0` symbols. These are
static facts, not device-loading or accelerator-execution evidence.

`vendor/litert/c` contains the unmodified official v0.19.1 tag headers, fetched
with GitHub's file API. `provenance.json` records the repository, ref, and Git
blob SHA for every fetched source. The SDK's packaged flat headers differ in
include paths and lint comments; the inspected API declarations match. The
runtime's `litert_lm_get_api_version` is checked before other SDK functions.
This verifies the reported API version, not the complete loaded library hash;
the packager must verify the pinned library hash, as `build_android.py` does.

`vendor/yyjson` is the official **0.13.0** release, dated 2026-09-08, under its
included MIT license. Parsing uses flags zero, nonstandard JSON disabled,
strict UTF-8, and compiled reader/writer depth limits. Duplicate object keys,
decoded NUL, excessive containers and unknown request fields are also rejected.
`runner.c`, build and fixture files are original work for this task.

## Request contract

Run the executable with **no arguments**, send exactly one UTF-8 JSON object on
stdin, then close stdin. There is a 1 MiB input cap and a 10-second input budget.

```json
{
  "schema": "hepta.litert-once.request.v1",
  "request_id": "comparison-001",
  "model_path": "/absolute/canonical/app-private/model.litertlm",
  "cache_dir": "/absolute/canonical/app-private/cache/litert",
  "system_prompt": "Return the one permitted decision for the current observation.",
  "prompt": "Current observation and user task supplied by the controller.",
  "backend": "gpu",
  "max_context_tokens": 8192,
  "max_output_tokens": 256,
  "speculation": "off",
  "deadline_ms": 60000,
  "constraint": {
    "type": "json_schema",
    "value": {
      "type": "object",
      "additionalProperties": false,
      "required": ["action"],
      "properties": {"action": {"const": "wait"}}
    }
  }
}
```

Required fields are `schema`, `request_id`, `model_path`, `prompt`,
`deadline_ms`, and `constraint`. Unknown fields fail closed. Defaults: GPU,
context 8192, output 256, speculation off. This version accepts only GPU and
never requests an automatic backend fallback. Runtime internals and real GPU
dispatch still require device qualification.

Bounds:

- Request ID: 1–64 ASCII letters, digits, underscore or hyphen.
- Prompt: 1–262,144 UTF-8 bytes. System prompt: 0–65,536 bytes.
- Context: integer 512–32768; output: integer 1–2048 and below context capacity.
- Deadline: integer 1000–300000 milliseconds, counted from main entry.
- Constraint: exactly `type` and `value`. Type is `json_schema` (object, at most
  262,144 serialized bytes) or `regex` (1–65,536 UTF-8 bytes). External `$ref`
  and `$dynamicRef` are rejected. GBNF is unsupported by the pinned C API.
- `speculation`: `off`, `on`, or `adaptive`. The pinned API has no `lenience`
  parameter. MTP requires compatible model assets; setting a flag does not
  prove that speculation executed or improved performance.

Model paths must be absolute, contain no symlink components, name an existing
caller-owned regular `.litertlm` file, and pass the size bound (1 byte–64 GiB).
Component-wise `openat` with `O_NOFOLLOW` and `O_NONBLOCK` rejects special files
without blocking on a FIFO. The opened model FD is transferred to the official
raw-file-descriptor API according to its ownership contract. A duplicate FD
checks metadata, including nanoseconds, after inference. This is not a model
content SHA-256 verification: the app must verify its model pin before calling.
The app should supply canonical paths; platform aliases implemented as symlinks
are rejected just like other symlink components.

An optional cache directory must already exist, be absolute, owned by the
caller and pass the same component checks. Its pathname is passed to the SDK;
this is a **preflight check**, not a guarantee against another same-UID process
renaming that directory concurrently. The caller must keep its cache directory
stable for the run.

## Response and lifetime contract

The runner attempts at most one final JSON record, capped at 1 MiB. It keeps a
private response FD and redirects ordinary stdout to stderr before calling the
SDK. The supervisor must capture stdout and stderr as separate streams; merging
them defeats this separation. The native
SDK response must be a strict JSON object of at most 256 KiB. It is preserved
both as structured `response` and exact `raw_response_json`; no tool call is
executed, converted into an action, or treated as business completion.

The normal status is `response_received`, **not task success**. The result
always includes `tools_executed=false`, `business_success_verified=false`,
`controller_validation_required=true`, and `process_exit_observed=false`.
The caller must validate the current observation, permitted targets, user
authorization, model decision schema and actual post-action state separately.

All SDK calls and deletes use one main thread. The watchdog does not call the
SDK or touch an SDK handle. Signal cancellation uses a compile-time verified
lock-free atomic. SIGTERM/SIGINT or the monotonic deadline cause a bounded
terminal attempt marked `cleanup=incomplete`, then `_Exit`. This deliberately
does not claim SDK cancellation or graceful thread shutdown. A canceled native
conversation is never reused. Normal publication happens only after all SDK
deletes have returned; this is recorded as `cleanup=sdk_delete_returned`.

The watchdog remains able to force exit after another thread claims the final
record. A losing terminal contender gives the publisher at most 500 ms before
exiting. A nonconsuming stdout reader can still cause a partial record or no
record. **The controller must require complete JSON, EOF and the observed
process exit code; a printed receipt cannot prove its own exit.** It must use an
external supervisor that starts before exec and covers dynamic loading,
constructors, scheduling, and the entire child lifetime. The internal clock
covers main entry through input, configuration, load, inference, deletes,
serialization and publication; it cannot cover work before main entry.

Exit codes: 0 response received; 64 invalid request; 70 SDK/response/internal
failure; 74 output delivery failure; 124 deadline; 128+signal for cancellation.
After normal publication the runner uses `_Exit` to avoid unbounded unrelated
shared-library exit hooks. Parent-observed exit remains mandatory.

## Building and checking

Host process-boundary tests use the **explicit fake SDK** only:

```sh
python3 tests/host_boundaries.py
```

They compile the real runner against the real header declarations and a test
double, then exercise raw-response preservation, duplicate/invalid/oversized
input, input that never reaches EOF, model-load/generation/cleanup stalls,
SIGTERM, malformed SDK output, and stdout backpressure. They test the process
contract; they do not test model quality, GPU, NPU, constrained decoding or MTP.

An independent, reproducible regression suite adds strict-input and forced
terminal-publication schedules, including the main-tail CAS race:

```sh
python3 -B tests/review_boundaries.py
```

This suite requires Linux and a GNU-compatible linker with `--wrap`. Its one
Python file embeds the complete scheduling shim and derives an explicitly fake
SDK from `tests/fake_sdk.c`. It does not modify `runner.c`. Its default output
directory must not already exist; a later run can pass `--out /absolute/new/dir`.
The reviewed runner SHA is pinned in the test. On the recorded source, the
original suite passed 12 cases and this independent suite passed 28 cases.
These results qualify process boundaries only.

The Android build is offline and refuses an unpinned runtime:

```sh
python3 build_android.py \
  --ndk-root /path/to/cached/android-ndk \
  --runtime /path/to/verified/liblitert-lm.so \
  --out /new/output/directory
```

Products are an Android ARM64/API30 PIE executable, the identical executable
named `libhepta_litert_runner.so` for extraction into an app's native library
directory, and the verified `liblitert-lm.so`. Both must stay together for the
`$ORIGIN` runpath. No APK, installed Hepta source, native ABI, model profile or
phone state is changed by this build.

The observed build used NDK **28.1.13356709 (r28b)** according to the actual
`source.properties`, despite a cached directory label of `28.2.13676358`.
`VALIDATION.json` records the actual revision and the directory label separately.

## Integration work still required

Current Hepta runtime configuration, model verifier, native result schemas and
warm-task ownership remain tied to GenieX/llama.cpp. An adapter must retain the
existing cleanup/ownership semantics and bind request identity, source/model
hashes and the external process-exit observation. Current observation-derived
GBNF needs a JSON Schema projection preserving each observation ID, authorized
action and node-label/ID or app-label/package pair. Generic JSON validity is
insufficient.

The existing GGUF cannot be loaded by LiteRT-LM. A pinned official `.litertlm`
bundle must be separately acquired and admitted against real device memory.
Actual razr GPU dispatch, cold and warm latency, thermal/memory behavior,
MTP OFF/ON correctness and end-to-end app tasks remain untested here.
This one-shot candidate initializes an engine for every request. It does not
provide a persistent warm engine or history/KV reuse across controller steps.

This first candidate is intentionally text-only: `image_path` is rejected as
an unknown field. The pinned official Message.kt does prove the future image
format `{"type":"image","path":absolutePath}`, and v0.19.1 exposes a vision
backend argument. Bounded image admission, vision-backend configuration and
model-specific image ordering still require a separate, tested addition.

Official image-format source:
https://github.com/google-ai-edge/LiteRT-LM/blob/v0.19.1/kotlin/java/com/google/ai/edge/litertlm/Message.kt
