# Independent GenieX / Hexagon MoE runtime probe

This directory contains a small, local-file C API probe. It does not modify Hepta,
install an APK, start an activity, inject input, create a display, download a model,
or call a cloud inference API. Compilation and host tests are not phone inference
qualification.

## Fixed experiment

- GenieX 0.10.0, source commit 071f609995470bdb0e0769ab964754adfaab7e47.
- Its llama.cpp gitlink is 19cce6919992fdffd92e0ac152caaf1e2b8f254e.
- Context 2048; logical batch 128; physical microbatch 128; one sequence.
- Four CPU helper threads, HTP0, all-layer request (-1), power mode 6
  (sustained high performance), speculative decoding disabled.
- Exactly 128 deterministic synthetic input IDs (seed 42, reported vocabulary,
  appropriate BOS) and 64 generated tokens. This deliberately tests runtime
  loading/compute, not Chinese instructions or tool-call correctness.
- The requested settings are compared with actual model/context parameter logs
  emitted by the pinned SDK. Missing or different logs are a failure.
- Selecting HTP0 does not prove that every node or expert ran on the NPU.
  Every receipt retains all_expert_op_placement_proven=false.

## Provenance and compatibility

provenance.json records the official Android release archive digest, all 16
runtime member digests, the exact public C ABI header digest, the upstream
gitlink, and the 24B candidate's official LFS size/SHA256. vendor/geniex.h is
byte-for-byte the public header at the pinned GenieX commit. vendor/LICENSE
contains its upstream license.

This runtime contains upstream Q2_K/Q4_K/Q8_0 and MUL_MAT_ID paths, subject to
tensor type, layout, shape, and VTCM restrictions. It does **not** contain
llama.cpp #32144 (9daa0aa22b8aa0143344d7549dee1f0e32f048bb, 2026-11-13).
GenieX's two Hexagon patches at this release cover session lifecycle and power
mode, not that IOVA change. A patched runtime requires a separate manifest/build
and paired host/DSP libraries; this probe refuses different release bytes.

Official source:
- https://github.com/qualcomm/GenieX/releases/tag/v0.10.0
- https://github.com/qualcomm/GenieX/tree/071f609995470bdb0e0769ab964754adfaab7e47
- https://github.com/qualcomm/GenieX/blob/071f609995470bdb0e0769ab964754adfaab7e47/sdk/include/geniex.h
- https://github.com/qualcomm/GenieX/blob/071f609995470bdb0e0769ab964754adfaab7e47/sdk/plugins/llama_cpp/src/params.cpp
- https://github.com/qualcomm/GenieX/blob/071f609995470bdb0e0769ab964754adfaab7e47/sdk/src/registry.cpp
- https://github.com/ggml-org/llama.cpp/pull/32144
- https://huggingface.co/LiquidAI/LFM2.5-24B-A2B-GGUF

## Research selection evidence

The research_audit section of provenance.json records the source-pinned
MobiInfer v0.4.5 portability review, its coordinated expert bundle metadata,
the EStream v1 / BigMoMo v2 hardware and workload boundaries, and a proposed
minimum headless integration contract. It also records device acceptance
criteria for comparing LFM3 with the existing 8B compact-grammar candidate.
These are source-based findings and proposed gates, not completed phone tests.
This probe still targets only the exact GenieX release above; it cannot execute
MobiInfer's separate expert-streaming ABI.

## Resource admission and termination

The limits are fixed, with no CLI to disable or reduce them:

1. The model must be a regular non-symlink local file matching caller-supplied
   exact bytes and SHA256. A held descriptor is passed to the SDK through
   /proc/self/fd, so loading uses the file that was hashed.
2. MemAvailable must cover model file bytes + 1536 MiB estimated runtime overhead
   + an untouched 3072 MiB reserve before hashing and again before SDK loading.
   This is conservative admission, not a proof of the runtime's memory needs.
   The pinned 24B candidate requires **14,367,293,600 bytes (~13.38 GiB) of
   MemAvailable**. A 16 GB-class device may fail this admission while other apps
   are present. Record that failure; do not evict apps or weaken the guard.
3. A supervisor samples child RSS+swap and global MemAvailable every 100 ms.
   It kills only its own child group if the reserve is breached, the child
   exceeds model bytes + 1536 MiB (minimum 2 GiB), or output grows too large.
   This is sampled protection, not an atomic kernel memory reservation.
4. The child has an address-space cap of estimated resident budget + 2 GiB
   (minimum 4 GiB), CPU limit 180 s, no core dumps, file limit 16 MiB, 256 FDs,
   and reduced scheduling priority. An AS-limit failure is not proof that the
   model cannot fit in physical RAM.
5. The supervisor enforces a 240 s wall deadline across hashing, loading,
   generation, and cleanup. SIGKILL is followed by observation of child reaping.
   A child not reaped within 5 s is explicitly reported as unconfirmed; no
   successful termination is fabricated. Parent death triggers child SIGKILL.
6. The child cannot use stdin for input. No other app/process is stopped.
   Inherited Hexagon tuning variables are removed; a single Hexagon session
   and verbose level 1 are set only for this child.

The standard SDK release's Android default microbatch is 1024. The public
geniex_ModelConfig supports explicit n_batch/n_ubatch; stock geniex-bench
0.10 has no corresponding CLI flags. This source uses the public fields directly.

## Build and validate

Use an existing NDK and the verified existing release runtime; this script
downloads nothing:

    python3 test_host.py
    python3 build_android.py \
      --ndk /absolute/path/to/ndk \
      --runtime-lib-dir /absolute/path/to/verified/runtime/lib

build_android.py reads the NDK's **source.properties Pkg.Revision and
Pkg.ReleaseName**. It does not infer the installed version from its directory
name. It verifies the public header and release core digest, verifies the
required public C symbols, records the actual compiler version, and checks the
AArch64 PIE ELF. The binary links libc/libdl only, and loads GenieX after checks.

Host validation covers known SHA256 vectors, missing/wrong model identity,
missing runtime, exclusive output, rejection of guard-disabling arguments,
strict watchdog reaping, and actual SDK log parameter mismatch. It loads no
GenieX library and contacts no phone. A separate test-only build contains a
watchdog sleep fixture; the Android build does not contain that mode.

Generated bin/, BUILD-RECEIPT.json, HOST-VALIDATION.json, and result directories
are ignored by Git. Keep the host build receipt with the compiled runner; it
contains absolute host paths.

## Future isolated device invocation

These commands are a handoff recipe, not evidence of execution. Use the existing
verified lib layout (libgeniex.so plus only the llama_cpp plugin directory), a
local model already available, and a new result directory. No transfer or install
command is part of this harness.

Preflight only (default):

    sh run-probe.sh /absolute/runtime/lib \
      --model /absolute/LFM2.5-24B-A2B-QAD-Q2_K_L.gguf \
      --model-bytes 9535455392 \
      --model-sha256 7c8e0365ca9cc40df48fd5b7cbc60476cc08e13c48750859751cb45880a2b4ca \
      --model-source https://huggingface.co/LiquidAI/LFM2.5-24B-A2B-GGUF \
      --output /absolute/new-preflight-result

After an independently accepted preflight, adding --run requests exactly one
synthetic inference. There is no automatic retry, fallback, sweep, or app action.
The wrapper sets only its own process library search path. It clears preload
variables and invokes the separately built binary.

## Results

- events.jsonl: requested provenance, admission, full hashes, SDK logs, stage
  transitions/errors, observed parameters, exact input ID digest, performance
  values, stop reason, cleanup.
- sdk.log: raw stdout/stderr from the isolated worker, including Hexagon output.
- raw-output.txt: bounded synthetic generated text; not a quality assessment.
- supervisor.json: observed exit/signal/reaping, guard reason, elapsed time,
  sampled memory, and explicit limitations.

Typical nonzero exits: 64 arguments; 65 identity/layout; 66 model preflight;
70 SDK/environment/parameter proof; 73 exclusive output; 75 memory;
124 deadline; 128+signal for a signalled child. Exit 0 without --run means
preflight_ready_not_executed. An inference_completed result still does not
qualify Hepta UI behavior, all-expert NPU placement, long-session thermals, or
tool calling.
