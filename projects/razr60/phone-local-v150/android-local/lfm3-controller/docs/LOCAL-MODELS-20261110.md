# Razr local-model deployment review, 2026-11-10

This is a deployment decision record, not a phone-acceptance certificate.
Published performance, retained older phone runs, and new candidate tests are
different evidence sets. A registered model profile does not establish that the
model completed an ordinary phone task.

## Device and existing execution path

A fresh read-only Pocket4/ADB observation identifies the phone as Motorola
XT2551-3, Android 16, SM8750. `/proc/meminfo` reported 15,540,960 KiB total and
8,465,044 KiB available in that observation. Available memory is a point-in-time
value and changes with foreground applications, model caches, and Android.

The existing application uses pinned GenieX 0.10.0 and its llama.cpp plugin,
including the Hexagon v79 and OpenCL libraries. The pinned llama.cpp commit is
`19cce6919992fdffd92e0ac152caaf1e2b8f254e`. New upstream backend features must not
be attributed to this frozen runtime without checking its actual source and
executing the resulting binary. The APK build rejects INTERNET permission and
automatic CPU/external-model fallback; target apps may still access the network
to retrieve current products or flights.

## Hexagon execution and usable capacity

Snapdragon 8 Elite exposes the v79 Hexagon target in the upstream mobile backend;
the phone's GPU is Adreno 830. Qualcomm's platform material describes a 45%
generation-over-generation improvement in AI performance and performance per
watt. It does not establish a single measured, usable LLM TOPS value for this
phone. Numbers from other Snapdragon product families must not be substituted.

Transformer decoding is affected by weight traffic, quantization support,
attention state, CPU-side scheduling and the accelerator's supported operators.
GPU and NPU peak figures therefore cannot simply be added to predict tokens/s.
The existing runtime selects one compute backend and retains explicit helper
threads. Helper work is distinct from silently falling back to CPU inference.
This integration does not claim simultaneous GPU/NPU partitioned execution.

The pinned GenieX NPU path requests sustained high performance. A newer upstream
maximum-burst mode is not automatically preferable for a background assistant:
clock and thermal behavior must be measured while the owner uses the main
display. Keep the current 8,192-token setting until exact-token admission and
actual task prompts establish that a smaller context preserves the whole task.

## Model decision

Retain `lfm3-1.7b-qad-q4_0` as the small-model qualification candidate. Its actual
registered GGUF is 1,049,615,680 bytes, SHA-256
`43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452`.
The existing selected profile is NPU, 8,192 context tokens, and four CPU helper
threads. The integration does not silently select a different profile.

LFM3 was released on October 27, 2026. Its official model card describes a
1.73B text model supporting Chinese and structured tool calls. The publisher
also cautions against complex multistep reasoning. Qualcomm's preview lists
the same Q4_0 model family on Galaxy S25 NPU at a 4,096-token context, with
2,315 prefill tokens/s and 36 decode tokens/s. These are vendor reference
measurements, not this Razr's results and not an 8,192-context guarantee.

Use Orvena-4B as the next tool-quality comparison. It was released on November
5, 2026, is based on Qwen3.5-4B, defaults to thinking off, and supports images
and multilingual tools. Its publisher reports 440/547 on its own simulated
phone-task benchmark. That benchmark is not Android GUI acceptance. The
existing registered GGUF is 2,783,447,904 bytes; the publisher's 3.1 GB MLX
download is a different artifact and must not be used as its byte identity.

Nanbeige4.2-3B remains a quality comparison with an existing NPU integration.
The model name excludes embeddings: total parameters are about 4B. Default
reasoning and looped layers affect execution cost. GUI-Owl-1.5-4B-Instruct is
a separate visual-agent candidate; a text-only controller cannot inherit its
GUI benchmark results merely by selecting its language-model weights.

No model is declared the best on this phone before matched tests compare task
success, false completion, latency, memory, thermal behavior and main-screen
coexistence. In particular, the currently retained Gemma4 E4B Notes failure
does not establish that LFM3 or Orvena will succeed.

## Retained phone timing evidence

The retained v45 Gemma4 E4B failed Notes task has 17 complete native receipts.
Their median request time is 28.379 s, median time to first token 13.706 s,
median prompt length 4,741 tokens, and median decode rate 9.435 tokens/s.
The native records retain one model creation for the task generation and
subsequent resets. They do not support blaming repeated cold model loading for
every step. These are older failed-task measurements, not new v47 execution.

## Larger MoE

LFM2.5-8B-A1B is a practical bounded comparison: the official model card lists
8.3B total and approximately 1.5B active parameters; official Q4_0 weights are
4.84 GB and Q4_K_M weights 5.16 GB. The existing Hepta registry already pins a
4,844,678,368-byte Q4_0 artifact. Registration alone does not qualify its memory
use, operator coverage, or business-task performance.

Current upstream llama.cpp documents approximately 3.5 GB virtual address space
per HTP session, dynamic weight mapping, and layer splits across several virtual
sessions on one physical NPU. Its GPT-OSS-20B example uses four sessions and
about 10.97 GiB of model buffers. This does not create extra physical RAM. At
4 bits, a 30B model already needs about 15 GB for raw weights before metadata,
KV state, runtime workspaces, Android and concurrently used apps. Expert
offloading and lower-bit quantization trade memory for latency, energy, or
quality. Large MoE should therefore remain an explicit experiment rather than
the default persistent background controller.

## Runtime and background follow-through

MNN 3.6.2 adds relevant Hexagon fused decoding, Qwen3.5 gated-delta and LFM2
convolution work. LiteRT-LM and Qualcomm's compiled QNN/GenieX packages are
additional backend candidates. Their model formats, supported SoCs and native
libraries are not interchangeable with the frozen GGUF runtime. Compare them
under the same task and evidence contract before adoption.

For arbitrary third-party apps, the current route remains a permissioned
trusted virtual display plus exact-display accessibility nodes. A normal APK
does not obtain trusted/own-focus privileges just by creating a VirtualDisplay.
Background coordinate gestures remain unsupported because Android's
`dispatchGesture` can cancel another ongoing gesture, including the user's.
The current observer repair does not broaden those action permissions.

Android 16 AppFunctions can expose local structured tools without opening UI,
but requires a permitted caller and participating target apps. It is a useful
future integration path, not automatic access to all installed applications.

## Acceptance that remains necessary

Use the same final signed APK and model artifact for these independent checks:

| Check | Required evidence |
| --- | --- |
| Build | Complete source identity, strict Java 8 host results, actual Android compilation and original signing certificate |
| Local inference | Selected model and runtime hashes, accelerator receipt, prompt tokens, first-token and decode timings; no external-model path |
| New note | Unique task marker, model-selected create, body readback, list transition, same-item reopen and final body |
| Calculator | Fresh model actions, current expression/result fields, no historical/pre-existing result, terminal identity and cleanup |
| Flights/products | Actual requested query and observable result details; browsing or cart preparation is not a completed order |
| Background | Separate trusted display, exact display/window/generation actions, main-screen activity and input preserved, display cleanup |
| Interruption | Stop, timeout, screen lock and service/process interruption do not dispatch late work or falsely report completion |
| Sustained use | Repeated-task latency, memory pressure, thermal behavior and main-screen responsiveness |

Publisher benchmarks, synthetic host cases and retained older phone receipts
cannot fill an unexecuted row. Account login, biometrics, secure windows and
target-app display restrictions may require visible owner interaction; universal
invisible operation across all apps is not an established Android capability.

## Primary sources

- [Qualcomm Snapdragon 8 Elite platform](https://www.qualcomm.com/smartphones/products/8-series/snapdragon-8-elite-mobile-platform)
- [LFM3 release](https://www.liquid.ai/blog/lfm3)
- [LFM3 model card](https://huggingface.co/LiquidAI/LFM3-1.7B)
- [Qualcomm LFM3 preview](https://aihub.qualcomm.com/mobile/models/lfm3_1_7b)
- [Orvena release and benchmark](https://orvena.app/blog/orvena-4b-on-device-model/)
- [Nanbeige model card](https://huggingface.co/Nanbeige/Nanbeige4.2-3B)
- [GUI-Owl model card](https://huggingface.co/mPLUG/GUI-Owl-1.5-4B-Instruct)
- [LFM2.5 MoE model card](https://huggingface.co/LiquidAI/LFM2.5-8B-A1B)
- [Official LFM2.5 GGUF files](https://huggingface.co/LiquidAI/LFM2.5-8B-A1B-GGUF/tree/main)
- [llama.cpp Snapdragon backend](https://github.com/ggml-org/llama.cpp/blob/master/docs/backend/snapdragon/README.md)
- [MNN releases](https://github.com/alibaba/MNN/releases)
- [LiteRT-LM](https://github.com/google-ai-edge/LiteRT-LM)
- [Android AccessibilityService](https://developer.android.com/reference/android/accessibilityservice/AccessibilityService)
- [Android AppFunctions](https://developer.android.com/ai/appfunctions)
