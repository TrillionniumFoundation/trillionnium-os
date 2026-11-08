# Explicit R3 VLM profile candidate

This source candidate adds `qairt-output-grammar-core-r2-vlm-r3-v1`. It selects the already built R2 core (`06e65cbe…`) with the separately built R3 VLM exception-boundary library (`773e23de…`, 361152 bytes). The file SHA is an artifact pin; this directory does not claim that the new Android runtime has passed its phone gates, been installed, or been activated.

## Admission and compatibility

- R3 requires explicit `vlm_android` and `vlm_sha256`. The file must be named `libgeniex_vlm.so` and share the first loader directory with the core and QAIRT plugin. Production admits only the pinned R3 VLM SHA.
- R2 configurations written before these two fields existed remain readable. They select `libgeniex_vlm.so` beside the core and the original official VLM SHA `8afccd775a6a6a2cef0521d30aa30df824a85d3617d913fc3cf49fe32795cb87`. Production R2 cannot silently select the R3 VLM.
- The VLM check for R2 is a **tightening in this new source version**. Previous R2 reports describe their original source SHA and are not retroactively described as having this check.
- Original v1 configurations remain grammar disabled. They cannot specify grammar-only artifacts. JSON configuration cannot select the host fixture policy.
- Every grammar-enabled native command verifies the selected VLM SHA before running the tokenizer counter. A failed hash check exits 65 before either the counter or model is invoked. Intent and terminal receipt bind the selected VLM path and expected SHA; success still requires the original validated native and worker evidence.
- Adding configuration fields changes the configuration digest. A new source/configuration closure and fresh deployment evidence are required. Retained old claims and receipts are preserved; they are not rewritten or reused as new readiness evidence.

The actual profile name remains identical across configuration, budget, intent and receipt. All numerical limits remain 4096 context, 3584 prompt admission, 256 generation, 256 reserve, 55-second worker and 60-second supervisor. No worker, counter, native supervisor, phone parser, cancellation, UNKNOWN gate or timeout classification was changed.

## Verification status

The local `--unit-only` run passed all 13 contract tests. It includes real JSON-file parsing of synthetic old v1 and R2 configuration shapes, production profile/path/pin rejection, and an overlay AST check preserving the old CPU completion branch. The compatibility test deliberately stops at the artifact-reading boundary and does not claim to load an Android library. Execution of the original CPU selector gate remains part of the pending full host probe.

The full suite now contains 31 tests. Its 18 native integration tests require a host that permits AF_UNIX. The added R3 mutation test uses the real r6 supervisor, frozen C worker and explicitly labelled host SDK fixture: a changed VLM pin must yield a joined native exit 65 with no counter result, worker result or generated output. A separate fresh request is then allowed only after cleanup is proven.

The selector probe retains v1 and R2 and adds explicit R3 runs, for both the public overlay and the actual private r9 source when supplied. Each profile exercises the same six scenarios: normal typed mapping, malformed JSON rejection, task deadline, native timeout, owner cancellation and worker deadline. These are host lifecycle/parser fixtures; the SDK fixture does not enforce grammar and they are not phone GUI tests.

`SOURCE-MANIFEST.json` contains before/after source hashes and the exact unchanged AST checks. `profile-vlm-r3.patch` is relative to the saved R2 baseline. The full pocket4 suite and actual private r9 regression results are pending and must be recorded separately.

The catalogue fixture builder is unchanged and still defaults to R2. Only the host selector probe gains `--grammar-profile qairt-output-grammar-core-r2-vlm-r3-v1`; its original `--schema-grammar` flag continues to mean R2.
