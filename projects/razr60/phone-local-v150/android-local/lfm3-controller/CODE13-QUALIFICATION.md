# Code13: Gemma 4 text profiles and isolated MNN library search

Version 13 / `0.13.0-local-gemma4` is an independent qualification candidate based
on frozen code11. It preserves the code10 text planner, action grammar, visible
label/node binding, freshness checks, persistent-destructive-action rejection,
single native request slot and task cleanup rules. The visual12 action controller
is not included. Installation does not rewrite the existing runtime config,
model files or task evidence. The source default remains the original LFM3
profile; a persisted Spark selection remains selected.

## Explicit Google Gemma 4 profiles

| Profile | Official file | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `gemma4-e4b-qat-q4_0` | `gemma-4-E4B_q4_0-it.gguf` | 5,154,941,280 | `676c35070db6dbe52f93e9c864ee0fba4eddea94b9c875d9cb10daff453fbaee` |
| `gemma4-e2b-qat-q4_0` | `gemma-4-E2B_q4_0-it.gguf` | 3,349,516,256 | `fa401b55b07ee70a54c6dae3903c783a6e65064312529ea57175cb5f8dec6634` |

E4B is pinned to official repository
[`google/gemma-4-E4B-it-qat-q4_0-gguf`](https://huggingface.co/google/gemma-4-E4B-it-qat-q4_0-gguf/tree/4b4a2c1d584be7264f87aac328a1bc739ce81b6c),
revision `4b4a2c1d584be7264f87aac328a1bc739ce81b6c`. E2B is pinned to
[`google/gemma-4-E2B-it-qat-q4_0-gguf`](https://huggingface.co/google/gemma-4-E2B-it-qat-q4_0-gguf/tree/675cff42a74c774d6cb76f76d8eacb49b48c9b93),
revision `675cff42a74c774d6cb76f76d8eacb49b48c9b93`. The fixed public repositories
identify these distributions as Apache-2.0. Download manifests must retain the
official model card and license, then verify the complete file hash before import.

Java, native and host-validation profile tables carry the same complete file
identity. E4B's size exceeds 32-bit unsigned range: Java uses `long` and native
uses `uint64_t`/`UINT64_C`, including whole-file count and receipt comparisons.
The full held-file-descriptor SHA-256 check remains mandatory for every native
invocation. There is no hash-check bypass for larger models.

Both profiles require architecture `gemma4`, the fixed llama source commit
`19cce6919992fdffd92e0ac152caaf1e2b8f254e`, exact native input-token IDs and the
same-input budget receipt. The existing private formatted-prompt and input-ID
sidecars are retained. Generation and tool protocols are unchanged. Native
function-call formatting, MTP and Gemma image input are not enabled by a profile.

The E4B admission threshold is 7 GiB of available physical memory; E2B is 5 GiB.
These conservative engineering thresholds are not measured peak usage and do
not establish that a context/device combination will load successfully. Device
qualification must independently record memory, actual accelerator selection,
successful loading, complete generation and cleanup. No automatic CPU fallback
is allowed.

An explicit configuration, written only after the corresponding complete private
model file has been verified, has this existing v2 shape:

```json
{"schema":"hepta.local-runtime.v2","model_profile":"gemma4-e4b-qat-q4_0","compute":"npu","context_tokens":4096,"threads":4}
```

For a controlled GPU comparison, change only `compute` to `gpu`. E2B uses its
separate profile ID. APK preparation provides candidate files and frozen plans;
their existence does not mean they have been executed or passed.

The optional official projectors are separately identified for future visual
work, but are not part of this text runtime's accepted input:

| Projector | Bytes | SHA-256 |
| --- | ---: | --- |
| `gemma-4-E4B-it-mmproj.gguf` | 991,552,256 | `7498a37cb619e55f2fcf87eb931f56e99389ed6d432e4c5c66110694c0d65578` |
| `gemma-4-E2B-it-mmproj.gguf` | 986,833,664 | `021059cce659fe7f9170d5599761d7bbaf644b798dab9503aca30dc43e6beb14` |

## MobiMind model-only child library search

Code11 set `LD_LIBRARY_PATH` to the installed native directory followed by
`/vendor/lib64`. On the actual installed worker, that environment failed before
`main` with an unresolved fmt v11 symbol referenced by the system `libinput.so`.
A retained same-worker, same-App-UID diagnostic reproduced that failure and
entered `main` when the environment variable was removed. The latter check used
no model arguments and did not establish GPU inference qualification. The exact
provider of the incompatible symbol was not identified; no standalone system
or vendor `libfmt.so` was inferred from its name.

Code13 removes `LD_LIBRARY_PATH` only from this MNN child. The unchanged pinned
r4 PIE has one non-transitive `DT_RUNPATH=$ORIGIN` and directly needs both
`libMNN.so` and `libc++_shared.so`. The assembler verifies those properties against
the actual ELF, its complete hash and its original build's dependency list.
System dependencies use the platform's default resolution. The fixed MNN
OpenCL loader already tries Android library names and explicit Qualcomm library
paths, including `/system/vendor/lib64/libOpenCL.so`, using local `dlopen` scope.
The optional `libOpenCL.so` manifest declaration remains present.

All three MNN payload hashes, the installed executable location, full model
hashes, private request nonce, parent/UID binding, deadline, shared request slot,
no-INTERNET manifest and no-action-dispatch model-only scope are unchanged. The
GenieX text child keeps its separately configured environment. No executable is
copied to writable App storage, no platform library is repackaged, and no SELinux
or permission change is part of this fix.

The App receipt records the configured linker policy. This field is not a claim
that `/proc/maps` or every actual dependency resolution was observed. A fresh
ordinary-App GPU model-only run is still necessary after installation.

## Validation boundary

Host checks exercise real profile parsing, exact model identity, greater-than-
4-GiB sizes, budget binding, native profile selection and loader-policy rejection.
Real Android compilation, DEX generation, installed-PIE packaging, original
signer match and actual ELF dependency checks are recorded in separate build
receipts. Neither host nor build receipts prove phone functionality.

Final phone acceptance must use the exact installed APK and candidate identity,
actual model raw output, dispatched tool receipts, fresh final UI and known
cleanup. The prior text controller has known incomplete goals; this candidate
must not be described as production-ready or as passing the complete suite.
