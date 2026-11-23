# MobiMind 1.5 2B Android OpenCL model-only probe

This is an independent experiment. It does not install an app, call accessibility,
run ADB, execute generated actions, or modify the frozen Hepta code5 application.
The parent operator supplies one private PNG screenshot and one exact rendered
prompt. The worker produces raw model text and evidence only.

## Fixed inputs

- Runtime source: `https://github.com/doulujiyao12/mobiinfer`, commit
  `bce7456ce60b5e51b4d3b357f303515860353d8c`, Apache 2.0.
- Model: ModelScope `fengerhu1/MobiMind-1.5-2B-W8A8-0717`, revision
  `f02848b6b7796988ea95df8f78a7b38bd71e2a90`, Apache 2.0 model card.
- The full official package is 3,398,455,629 bytes. Eleven runtime/provenance files
  are independently pinned by complete SHA256 and size in `native/model_pins.hpp`.
  Unused graph-debug JSON files are not loaded by the worker.
- The original package config requests CPU; its exporter says activation 16-bit
  and `generate_for_npu=false`. The repository name is not proof of QNN W8A8.
  The original files remain unchanged. `runtime-config.json` records the separate
  OpenCL configuration, greedy sampler, 4096-token cap, and disabled template/KV reuse.

## Source compatibility already checked

The exact `llm.hpp` declares `Llm::response(const MultimodalPrompt&, ostream*,
const char*, int)`. The pinned `Omni` recognizes qwen3_vl, handles the fifth visual
`idx_tensor` input, constructs MRoPE position IDs, retains the visual model's
second DeepStack output, and adds its three text-side placeholder/embedding
streams. The pinned model config declares `is_mrope`, `has_deepstack`,
`num_grid_per_side=48`, and 2048 hidden size. This is source-level compatibility;
successful loading and correct GUI decisions still require the real device probe.

The screenshot is decoded once as BGR. A unique `<img>screen</img>` placeholder
is resolved from the in-memory image map, so no media URL or alternate file path
is interpreted. Qwen3VL preprocessing receives explicit aspect-preserving,
32-aligned dimensions (1224 x 2992 -> 416 x 1024 by default). The original image
SHA and original/resized dimensions are recorded. No screenshot is committed here.

## Build on the existing Mac NDK installation

Use the already-authorized independent checkout. Do not patch another checkout.
Run `python3 patch_runtime.py /absolute/pinned/mnn/source` and archive its JSON.
It checks three complete upstream source hashes before writing anything. The
patch is idempotent and rejects unrelated changes. It adds only observer hooks:

1. Requested/selected backend at `RuntimeManager` creation.
2. Selected execution backend and return status after each Pipeline execution.
3. Exact multimodal input IDs after vision/tokenization and before language prefill.

Configure MNN at its own source root with the existing Android NDK toolchain:

```sh
cmake -S "$MNN_SOURCE" -B "$MNN_BUILD" -G "Unix Makefiles" \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
  -DANDROID_STL=c++_shared -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_STANDARD=17 -DCMAKE_POLICY_VERSION_MINIMUM=3.5 \
  -DMNN_BUILD_SHARED_LIBS=ON -DMNN_SEP_BUILD=OFF \
  -DMNN_BUILD_FOR_ANDROID_COMMAND=ON -DMNN_OPENCL=ON \
  -DMNN_BUILD_LLM=ON -DMNN_BUILD_LLM_OMNI=ON \
  -DMNN_BUILD_OPENCV=ON -DMNN_IMGCODECS=ON \
  -DMNN_BUILD_TOOLS=OFF -DMNN_BUILD_DEMO=OFF -DMNN_LLM_BUILD_DEMO=OFF \
  -DLLM_SUPPORT_HTTP_RESOURCE=OFF -DBUILD_MLS=OFF \
  -DMNN_QNN=OFF -DMNN_HIAI=OFF -DMNN_SME2=OFF
cmake --build "$MNN_BUILD" --target MNN --parallel 6
cmake -S "$PROBE_SOURCE" -B "$PROBE_BUILD" -G "Unix Makefiles" \
  -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
  -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 \
  -DANDROID_STL=c++_shared -DCMAKE_BUILD_TYPE=Release \
  -DMNN_SOURCE="$MNN_SOURCE" -DMNN_LIBRARY="$MNN_BUILD/libMNN.so"
cmake --build "$PROBE_BUILD" --parallel 2
```

Use the real full CMake path on the Mac, `/opt/homebrew/Cellar/cmake/4.3.2/bin/cmake`.
The shared runtime closure is the worker, built `libMNN.so`, and the same NDK's
arm64 `libc++_shared.so`. Record complete SHA256, build config, ELF architecture,
DT_NEEDED, exported observer symbols, and HTTP-disabled CMake cache. No QNN SDK
or separately licensed prebuilt library is required. Do not claim the build
passed until the real NDK compile/link and ELF checks finish.

## Private one-shot invocation (operator only; not executed by this project)

All model/input files must be regular, owned by the worker UID, and not group/world
writable. The output path must not exist. The parent shell must stay alive until
the worker exits; do not `exec` the worker and do not drop the final `rc` statement.

```sh
LD_LIBRARY_PATH="$RUNTIME_DIR" "$RUNTIME_DIR/hepta-mobimind-probe" \
  --expected-parent-pid "$$" \
  --request-id "$REQUEST_NONCE_32_HEX" \
  --model-dir "$PRIVATE_MODEL_DIR" \
  --prompt-file "$PRIVATE_RENDERED_PROMPT" \
  --image-file "$PRIVATE_SCREENSHOT_PNG" \
  --expected-prompt-sha256 "$PROMPT_SHA256" \
  --expected-image-sha256 "$SCREENSHOT_SHA256" \
  --output-dir "$NEW_PRIVATE_OUTPUT_DIR" \
  --deadline-ms 120000 --max-tokens 256 --image-long-edge 1024
rc=$?
exit "$rc"
```

`make_prompt.py` renders caller-supplied system/task text using the pinned ChatML
shape. It is not a claim to reproduce the official MobiMind system prompt. Use
an independently reviewed model-specific GUI instruction/action schema for the
first semantic test; do not force the old text model's node-ID protocol. Raw
generation is never parsed into, or executed as, a phone action by this worker.

## What constitutes a valid result

Read the real process exit code and both `terminal.json` and `receipt.json`.
Exit zero requires normal EOS, valid nonempty UTF-8, exact model/input binding,
one input-token observation, at least two OpenCL runtime selections, observed
OpenCL execution calls, and no observed execution error. Exit 3 means the token
limit was reached and is not a complete answer. A timeout/cancel leaves an
explicit incomplete terminal receipt and already-written raw bytes; SIGKILL or
parent death may leave no terminal receipt and must be reported as interrupted.

`raw.txt` is the full unfiltered model output, separate from the parent-captured
stdout/stderr. Input IDs are hashed as uint32 little-endian and counted exactly.
Input + maximum output must fit 4096 before language prefill. Full model hashes
are retained; this probe intentionally adds no hashing shortcut.

The worker rejects global OpenCL-to-CPU runtime fallback. CPU helper or fallback
operators are reported by operation type/name and phase. Counts are selected
Pipeline execution calls, not GPU hardware counters, percentage of FLOPs, or
proof that every tensor stayed on GPU. Disk embeddings, tokenization, sampling,
and preprocessing can use CPU outside these counts. `all_gpu_claim` is always
false. Evaluate whether any heavy language/vision operator falls back to CPU
using the actual operation rows and stderr before qualifying performance.

File binding uses full hashes followed by retained file descriptors and matching
path device/inode/size/UID/mode/mtime/ctime checks. MNN still opens the pinned
model files by their private paths; this is not a claim of descriptor-only loading.
Run under the already network-denied app UID for the offline application test.
The worker itself does not install a network policy; HTTP resource support and
the model downloader/server are excluded at build time.

## Host checks

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
g++ -std=c++17 -Wall -Wextra -Werror -O2 -I native tests/util_contract.cpp -o /tmp/hepta-mobi-util-contract
/tmp/hepta-mobi-util-contract
```

These checks cover pin rejection/idempotence, SHA256 published vectors, UTF-8
edge cases, exact token hashing, external/extra media rejection, image dimensions,
input replacement/modification, symlinks, and output overwrite refusal. They do
not replace real Android compilation or device inference.

## Revision r2

The first Android build stopped before patching: the GitHub text response had
appended one newline to `express/Executor.cpp`. Revision r2 pins the exact Git
blob (24,833 bytes, SHA256 79fd37b7111e91201efcbca12aa61f287d6ffe7d05a95cc7e9b215a6990cda05).
The checkout and `git show HEAD:express/Executor.cpp` matched exactly; the other
two source files were already byte-identical. The validation remains strict and
worker behavior is unchanged. The failed first build is preserved separately.

## Revision r3

The pinned official ClawMate Harmony local caller uses a manually rendered GUI
prompt ending in `<|im_start|>assistant` with no final newline, and sets
`use_template=false`. The worker now accepts this exact suffix as well as the
existing ChatML suffix with one newline. It does not add, remove, or normalize
any prompt byte. Other suffixes remain rejected. The MNN library and observer
hooks are identical to the successfully built r2 runtime.

The local GUI protocol uses `reasoning`, `action`, and `parameters`, with bbox
coordinates for click actions. Its built-in prompt is obtained from fixed source
`doulujiyao12/mobiinfra-oh` commit
`c64ee5134ae3fb5358decb47b31c2ece3039937b`,
`entry/src/main/ets/utils/AgentPromptTemplates.ets`;
`AgentLoopRunner.ets` and `entry/src/main/cpp/napi_init.cpp` establish the local
prefill/step path and disabled template wrapping. Model-directory prompt files
can override these built-ins and must be checked before selecting the fixture.
No full third-party app prompt or private screenshot is redistributed here.

## Revision r4: complete SHA-256 with runtime ARM SHA2 dispatch

This revision changes the worker's SHA implementation and adds hash-execution
evidence. It keeps all eleven complete model-file hashes, held descriptors,
pre/post metadata checks, exact input bytes, prompt validation, MNN configuration,
and raw-only output behavior. It introduces no digest cache or verification skip.
The existing MNN and libc++ libraries are reused by exact hash; only the worker
PIE is rebuilt.

`native/sha256-dispatch.hpp` is a C++17 port of the previously qualified Hepta
code9 header, pinned at SHA256
`b614c97accb36faeda582918cbbbd7acd378285197e2def1557e4e3839379b1a`.
The ARM compression routine, Linux `HWCAP_SHA2` check, errno preservation,
block batching, padding, and portable compression are unchanged. The only port
changes are the header guard, C++ aggregate initialization, and the void-pointer
cast. The portable compression also matches the original r3 worker exactly.
The original UTF-8 validator is byte-identical.

The ARM function alone has `target("sha2")`; the translation unit does not enable
SHA2 globally. Runtime capability determines the branch before instructions run.
Platforms outside the compiled Android/Linux AArch64-Clang path use portable
compression. A missing capability also selects portable compression.

`receipt.json.sha256_dispatch` records compiled support, the runtime HWCAP result,
the backend actually observed in completed model hashes, verified model-file
count/bytes, and hardware/portable block totals. Prompt, image, and loaded-library
hashes have separate execution records. `model-binding.json` retains every
official size/SHA and adds per-file `hash_execution`. Counts include SHA padding
blocks and never claim that an incomplete or failed file hash was verified.

Run `python3 tests/run_host_checks.py --out /new/host-evidence-directory` for the
real C++17 utility and SHA tests. They cover 316 digest comparisons, published
vectors, unaligned/chunked inputs, 24 file reads compared to Python hashlib,
five seeded random vectors, and the 536,870,913-byte length boundary. The source
comparison enforces that only the declared C++ changes separate the transplanted
header from code9. Hash failure clears an output evidence object; repeated calls
still perform a full hash and report their own work.

The local x86 host executed the portable branch. Android NDK compilation and
disassembly establish that the gated ARM instructions are present, not that they
ran. A subsequent real Android request must verify all eleven pins, exact prompt
and image bindings, the actual block counters, and timing before claiming the
new worker's acceleration or overall performance. No phone command is run by
this source package or its host checks.
