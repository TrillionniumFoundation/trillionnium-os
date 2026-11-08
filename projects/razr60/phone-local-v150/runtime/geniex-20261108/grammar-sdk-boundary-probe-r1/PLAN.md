# SDK exception boundary probe — R1

This is a CPU-only diagnostic with the unchanged official SDK and processor. It creates a tokenizer and a fake implementation of the fixed official IVlm interface. No model creation, geniex_init, plugin initialization, QNN call, UI operation, production service, or owner-stop change occurs.

## Question and controls

The previous direct executable and C-only loader tests caught the official proc Grammar exception with std::exception and catch(...). The full model test nevertheless aborted. The SDK C ABI source already has a std::exception catch. The SDK binary has internal exception support while the processor exports the RTTI and exception runtime used by QAIRT libraries. This motivates testing the real SDK boundary; it does not yet establish an ABI defect.

Use the fixed geniex_vlm_generate with the fake backend, both with a callback and without one. The backend either constructs a valid B grammar, propagates the original invalid-grammar exception, or catches that exception locally and returns the existing GENIEX_ERROR_VLM_GENERATION_FAILED. An outer diagnostic catch records whether an exception escapes the original C ABI. The backend produces no text or token callbacks; return values are diagnostic outcomes, never model qualification.

Expected records:
- Direct invalid construction: caller catches std::exception (10).
- SDK valid grammar: original SDK returns success without any model/text (0).
- SDK invalid grammar: SDK returns GENIEX_ERROR_COMMON_UNKNOWN (23), or caller records escaped std exception (30) / catch-all (31), or an actual abort is retained.
- Locally contained invalid grammar: existing SDK error -201201 crosses the C ABI normally (22).

Each invocation uses the existing frozen tokenizer, official libgeniex.so and libgeniex-proc.so, and a new phone directory. Build with the same NDK Clang 19/API 31 flags as the previous probe, retaining a C-only dlopen driver variant. Every artifact and input hash is recorded; use a no-route network namespace, phone timeout18s/alarm15s, core dumps disabled, and verify no residual probe afterward. These calls must wait for the current mobile_models queue to release phone IO.

## Minimal repair boundary under consideration

LLMModel::prepareSampler returns void and LLMModel::generate returns only token IDs; neither exposes a nonthrow error Result. Returning empty token IDs would incorrectly resemble EOS. The next existing nonthrow error boundary is QAIRT VLMPipeline::generate (libgeniex_vlm.so), whose GenerateResult.stop_reason="error" is already mapped by QairtVlm::generate to GENIEX_ERROR_VLM_GENERATION_FAILED. A prospective repair can catch exceptions from requested-grammar generation there, before crossing the SDK DSO, without changing layouts or disabling grammar. R2 core remains unchanged. No repair is implemented or qualified by this probe.
