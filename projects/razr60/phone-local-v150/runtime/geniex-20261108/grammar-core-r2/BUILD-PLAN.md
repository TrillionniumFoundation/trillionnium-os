# Core-only grammar candidate R2

This is a proposed source repair of the observed output-grammar initialization
failure. No Android binary has been built or deployed. Existing model, QNN,
processor, VLM/plugin wrapper and C worker artifacts remain pinned and unchanged.

## Repair boundary

The inference changes are confined to the two existing methods
`qualcomm/geniex-qairt-plugin@ab24abb1f66cb3d8fe624cb8649ec23bd36da41c`
`LLMModel::prepareSampler` and `LLMModel::sampleNextToken`. The candidate validates a requested grammar before
changing prior sampler state, creates sampler chains without an attached grammar,
and performs `detach -> init(prompt history) -> attach fresh output grammar` for
each response. The original configuration remains the cache key, so prompt and
generated-token penalty history survive ordinary reuse. Invalid grammar, missing
tokenizer, or requested grammar with sampling disabled throws explicitly.

The pinned processor `Sampler::sample` already accepts its chosen token. The
core now skips its extra `accept` only when a validated grammar configuration is
active. No-grammar sampling deliberately retains the upstream double-history
acceptance behavior, and the greedy no-sampler path is unchanged. The processor
binary and its implementation are not changed. Exception-to-C-ABI mapping is also unchanged: a malformed requested
grammar must be treated as a failed worker process if the wrapper does not catch
the exception. This candidate does not promise a new SDK error-code contract.

`prepare_sampler.inc` and `sample_next_token.inc` are the exact replacement
methods used by both the patch generator and host harness. The retained comment
in `prepare_sampler.inc` about generated-token acceptance describes that method
only; R2 deliberately changes the extra acceptance in `sampleNextToken` as
explained above. The reviewed method bytes remain frozen.
`review-r2/PATCH-MANIFEST.json` binds
the upstream Git blobs, upstream SHA256 values, patch bytes and candidate method.

## Minimal build inputs

- The fixed QAIRT source directories `core/`, `qnn-api/`, `models/` and root
  `CMakeLists.txt`. QNN headers are already vendored in `qnn-api/include`.
- Public headers from `geniex-proc@6b68dd0de5b9a84c316cc3babfe9f2477d9c6079`,
  including its vendored public xtensor/xtl dependency headers as required.
- The unchanged official Android `libgeniex-proc.so`, SHA256
  `7a1a80346ddd7d1e775a00435b87303d7794c08d3c75251bcfc5d911fa82227d`.
- The already installed Mac NDK r28b/Clang19, CMake and make. The local directory
  called `28.2.13676358` actually reports NDK `28.1.13356709`; provenance must retain
  that distinction. Do not silently fetch another NDK.

The optional CMake patch imports the existing processor target instead of
building its Rust tokenizer. It is explicitly restricted to an Android core-only
build. It also permits skipping HTP runtime copying; it neither downloads nor
changes those runtime files. The default upstream CMake path is preserved.

## Build after source review

First verify all input hashes, record the complete sparse-source manifest and
apply both reviewed patches to a fresh isolated checkout. A representative CMake
argument vector is:

```text
cmake -S <patched-qairt-source> -B <new-build>
  -DCMAKE_TOOLCHAIN_FILE=<existing-ndk>/build/cmake/android.toolchain.cmake
  -DANDROID_ABI=arm64-v8a
  -DANDROID_PLATFORM=android-31
  -DCMAKE_BUILD_TYPE=Release
  -DGENIEX_BUILD_VLM=OFF
  -DGENIEX_BUILD_AUDIO=OFF
  -DGENIEX_BUILD_OCR=OFF
  -DGENIEX_BUILD_EXAMPLES=OFF
  -DGENIEX_BUILD_TESTS=OFF
  -DGENIEX_SKIP_HTP_RUNTIME_COPY=ON
  -DGENIEX_PROC_PREBUILT_LIBRARY=<pinned-libgeniex-proc.so>
  -DGENIEX_PROC_PREBUILT_INCLUDE_DIR=<pinned-proc-source>/include
  -DGENIEX_PROC_PUBLIC_DEPENDENCY_INCLUDE_DIRS=<pinned-public-header-dirs>
cmake --build <new-build> --target geniex_core --parallel 4
```

Use `nice 10` and no more than four compilation jobs. Do not build or install the
whole GenieX SDK, its model manager, the tokenizer Rust library, QNN runtime,
firmware or model binaries. The full SDK's Android CMake also hard-codes a Linux
NDK host directory, so it is not the intended native-Mac route.

Before choosing final compiler/STL flags, compare the original core/processor ELF
dependencies and the pinned SDK Android toolchain flags. The official toolchain
uses API31 and `-march=armv8.7a+fp16+dotprod+i8mm`, vectorization, fast FP with
`-fno-finite-math-only`, LTO and `_GNU_SOURCE`; do not introduce an unrecorded
runtime C++ dependency. A successfully linked library is only a build candidate.

## Required gates before phone inference

1. Host regression: the pinned old methods reproduce prompt-to-grammar failure.
   The retained R1 setup-only candidate reproduces duplicate generated-token
   acceptance failure. R2 must preserve prompt history; accept the first, later
   and EOG tokens exactly once with grammar; reset on repeated/empty-prompt turns;
   reject invalid grammar and missing tokenizer; and retain no-grammar history
   and greedy behavior. The fake processor sample method accepts internally, as
   the pinned real processor does. These are control-flow regressions, not NPU
   or tokenizer numerical validation.
2. Compare original/candidate ELF machine, SONAME, all undefined dependencies,
   required public exports and C++ ABI-relevant symbols. Preserve a complete
   diff; a build that loses required exports is rejected.
3. Produce a new candidate manifest for a complete isolated runtime, changing
   only `libgeniex_core.so`; hash every unchanged processor/QNN/plugin/worker
   artifact. Never replace the existing tested runtime in place.
4. Obtain root/mobile source review before Android compilation and explicit
   approval of the resulting ABI comparison before using this SDK on the phone.
   Future phone checks must begin with the B-only discriminator against a natural
   prompt asking for A, then multi-token structured output and no-grammar
   recovery. Only after those gates can actual constrained action semantics be
   tested. The broker must retain grammar disabled until these real checks pass.
   None have run yet.

## Fixed primary sources

- [QAIRT core model](https://github.com/qualcomm/geniex-qairt-plugin/blob/ab24abb1f66cb3d8fe624cb8649ec23bd36da41c/core/src/llm/llm_model.cpp)
- [QAIRT sampler creation](https://github.com/qualcomm/geniex-qairt-plugin/blob/ab24abb1f66cb3d8fe624cb8649ec23bd36da41c/core/include/llm/sampler_utils.h)
- [Processor sampler implementation](https://github.com/qualcomm/geniex-proc/blob/6b68dd0de5b9a84c316cc3babfe9f2477d9c6079/src/sampler/sampler.cpp)
- [QAIRT CMake](https://github.com/qualcomm/geniex-qairt-plugin/blob/ab24abb1f66cb3d8fe624cb8649ec23bd36da41c/CMakeLists.txt)
- [Official Android flags](https://github.com/qualcomm/GenieX/blob/071f609995470bdb0e0769ab964754adfaab7e47/sdk/cmake/arm64-android-llvm.cmake)

## R1 review history

The R1 host harness manually accepted output tokens and did not model the real
processor sample method accepting internally. Independent review found that the
core accepted each sampled token a second time. R1 files and its insufficient
passing host record remain unchanged in `../grammar-core-r1/`; R1 is not an
approved runtime repair. R2 tests demonstrate both the original and R1 failures
with the actual two core methods and the correct external acceptance semantics.
