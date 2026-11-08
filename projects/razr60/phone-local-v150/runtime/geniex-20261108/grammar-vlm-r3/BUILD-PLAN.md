# R3: requested-grammar failures return the existing QAIRT error result

## Fixed scope

The R2 core repair remains byte-identical (06e65cbec4de0831e0010c02ff424e197a519f35b137344cb62ff92369abdb5d). The sole additional runtime change is lib/qairt/libgeniex_vlm.so, built from qualcomm/geniex-qairt-plugin commit ab24abb1f66cb3d8fe624cb8649ec23bd36da41c. Only core/src/pipeline/vlm_pipeline.cpp changes. The public classes, headers, vtables, field layouts, and function signatures do not change.

The complete original SDK source already catches std::exception in geniex_vlm_generate. The R2 phone request with malformed grammar nevertheless aborted, while a CPU-only original-proc constructor probe caught the same std::runtime_error normally. The SDK has local RTTI/exception-runtime symbols and the QAIRT DSOs import the processor's exported ones. A separate CPU-only SDK-boundary probe is being used to determine that boundary's behavior; those facts alone are not a proven low-level cause.

## Result semantics

LLMModel::prepareSampler returns void and LLMModel::generate returns a token vector. Neither offers an error Result; returning an empty vector there would look like EOS. The next existing nonthrow boundary is VLMPipeline::generate. Its GenerateResult with stop_reason="error" is already translated by QairtVlm::generate to GENIEX_ERROR_VLM_GENERATION_FAILED (-201201).

The patch adds standard and unknown exception handlers after the existing prompt-too-long/context-length handlers. Only a nonempty requested grammar activates the new error handling. The handlers log the failure and use the unchanged finalizer to return error. They do not retry, remove grammar, manufacture tokens, or accept incomplete output. No-grammar exceptions still propagate. Partial text, if a later error follows a callback, remains diagnostic text paired with the nonzero SDK failure; the frozen worker and provider must reject it. The one-request worker subsequently destroys the model and deinitializes the SDK. Reusable-model cleanup beyond the existing interface is not claimed by the host tests.

## Host evidence

run_host_tests.py compiles the exact extracted upstream and patched generate method, the unchanged upstream finalizer, and the unchanged GenerateResult definition against small processor/model fakes. The original method has four expected grammar-error failures; the candidate passes all sixteen checks, including pre-token/partial-token standard exceptions, unknown exceptions, normal EOS/length/user stop, existing typed-length errors, no-grammar propagation, processor failure, and a following valid request. These tests do not qualify numerical model execution or exception behavior between Android DSOs.

Final patch SHA: 5d6e35d07c872124e7e160eee7831f4cbdb0fe0b832c25c0cc6b7ea5b6be9821.
Final candidate source SHA: cfee2c080b42b59e4edcf7e8313b5e52297539ed70c38aa405fd948042d74866.
Final host report: host-validation-r2/HOST-TESTS.json, SHA 605f43545d5ccbd6aedb6a0a3d3da39346f591218c76c8f3b634590b7108619d.
The earlier wording/test iteration is retained in history-r1 and host-validation-r1.

## Isolated Android build plan

Reuse the already verified source/header closure from the R2 build (INPUTS-MANIFEST SHA45c6f4e58ed9d14e1c687ca05b687571ed00059530927f6125e9590b7ee34779). Its fixed source already contains the ten .cpp files selected by upstream's geniex_vlm target: five core/src/vlm files, vlm_pipeline.cpp, and the Qwen2.5-VL/Qwen3-VL/InternVL/Gemma4 implementations. Their direct includes use existing core/proc/xtensor headers; no OpenCV source build is needed when importing the unchanged official processor-vision DSO.

Create a new Mac build directory. Import the unchanged R2 core, original proc, and original proc-vision libraries; verify all three SHAs before linking. Proc-vision SHA5517a4ca8e754e6df46859f914ce779dd30831e5a33bc457d40bec744d699be9. Original VLM reference SHA8afccd775a6a6a2cef0521d30aa30df824a85d3617d913fc3cf49fe32795cb87. Use API31, the existing r28b/Clang19 toolchain, static libc++, the original QAIRT compile definitions and architecture flags, SONAME libgeniex_vlm.so and RUNPATH $ORIGIN. Link only imported geniex_core, geniex-proc-vision, their proc dependency, and the existing Android system libraries. No SDK, Rust, QNN, firmware, model, or processor rebuild occurs. Four compile jobs at nice10 maximum.

Retain the unstripped and stripped result, compiler commands, complete source/header and input-library hashes, and original/new ELF evidence. Compare SONAME, DT_NEEDED, RUNPATH, exported business symbols, all actual consumer symbol requirements, and new undefined symbols against the unchanged closure. Inspect any new logging dependencies explicitly. No phone deployment or production activation is implied by a successful build.

## Later on-phone gate

After source and ABI review, use a new runtime copy containing the exact R2 core plus this one VLM change. Preserve all earlier runtime directories and failed records. Verify malformed grammar produces a normal nonzero SDK return and complete frozen-worker failure metadata, then run no-grammar recovery and the positive grammar/model cases authorized by the parent. Use the established no-route network namespace and 55s worker/60s native timeout. Root-only inference does not qualify the production SELinux domain or any UI action.
