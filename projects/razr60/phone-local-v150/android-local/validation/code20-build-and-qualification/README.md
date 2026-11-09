# Code20 source and build qualification

This candidate brings the already reviewed text-controller changes and the isolated UI-Venus Q4_0 App probe into the external `fdb7eca8` history. The original external commits remain ancestors. Historical MNN v7 and fixed SDK transport v1 files remain unchanged.

## Application changes relative to the external Code19 parent

- `LocalTaskController`, `CompactTaskHistory` and `PromptActionDomain` preserve every recorded history scalar and the complete eligible action domain from the observed tree. A dictionary/row encoding preserves order, repetitions, missing fields, explicit null, false, zero and empty text. Optional screen text and app catalogue entries may shrink; required observed click, editable and actual scroll-capability nodes cannot be removed to fit the budget. An oversized mandatory prompt is rejected before inference. This is complete within the observed bounded tree, not a claim about unobserved nodes.
- The external `open_allowed_packages` field remains tied to the identical package set used by the grammar and policy. No target or answer is inserted into the task. Existing editable-field facts and owner method constraints are retained.
- The external ten-second observation stability cap is preserved within the original caller deadline. The 200 ms comparison interval, full observed graph key, cancellation, late-callback checks, screenshot revalidation and pre-dispatch freshness gates remain.
- `UiVenusModelEngine`, its typed private request, input/process/result contracts and session contract add an ordinary-App model-only entry. `LocalProbeApplication`, `DiagnosticStartupGate` and the shared engine lease aggregate all three session recoveries before admitting work. UI-Venus is not connected to an action dispatcher. Unknown exit or unconfirmed publication keeps the recovery barrier; a known failed process can terminate cleanly without becoming a successful model result.
- The UI-Venus profile is explicitly `ui-venus2-9b-q4_0-f16-mmproj`. Its separately compiled worker is pinned by whole-file SHA256. The old Q4_K_M worker is not substituted, the 16 existing native payloads are unchanged, and no model weights are included in the APK. A filename does not prove all tensors use one quantization or that the runtime is qualified.
- The pinned SDK fetch helper opens the same fixed URL at most three times, with 2/4-second delays only for HTTP 500/502/503/504 returned before a body is read. TLS, 4xx, body, size and digest errors do not retry. Archive/core hashes and bounded extraction checks remain. Historical transport v1 is preserved as prior work; this workflow selects the newer application helper explicitly.

The absent-config fallback remains the external LFM3/NPU/8192 setting. This source update does not mutate a device's persisted model configuration. The E4B 8192 test selection belongs to a separate private transaction.

## Evidence available before phone qualification

The frozen candidate passed 56 host checks and a real Java/DEX/arm64 build with the original signing certificate. `BUILD-SUMMARY.json` pins the exact APK, DEX, source and original receipts, and records all 17 native payloads. The original three MNN runtime files and UI-Venus runtime are independent pinned builds; this APK pipeline did not rebuild them again.

The prior 64-frame packing replay applies by byte identity of its production packing inputs. It admitted 54 frames at 4096 and refused ten; at 8192 it admitted all 64. It is not a phone quality test or native tokenizer proof. The source still requires native exact-token admission and does not silently truncate or retry an oversized mandatory prompt.

## Public source identity

The public source manifest differs from the private device-build manifest. One archived scanner now detects generic mixed uppercase/digit identifiers instead of containing a real device serial literal. Its nested manifest, runtime source-manifest pin and explanatory document change with it. `SOURCE-EQUIVALENCE.json` lists all four changes and the top-level manifest cascade.

All 49 production Java files and the source/resource/native compilation text are byte-identical to the frozen candidate. The broader suffix-based audit covers 148 files, including archived and host-test source. The actual `build_identity.source_inputs` list has 141 entries; three metadata/scanner inputs differ. Therefore the complete build receipt inputs are not claimed identical, and a fresh public-source build is required. The only PNG in the source is a 33-byte synthetic IHDR header with no pixels; it is not a phone screenshot or a decodable runtime image.

## Required CI for the eventual exact PR head

CI must freshly rebuild and match all three MNN files on macOS, and freshly compile the Q4_0 UI-Venus worker. New-build receipts remain separate from the preserved original receipts. The consumer on Linux verifies the exact payloads, compiler identity, source head, run ID and attempt before exposing either runtime to the assembler. Linux then rebuilds Java, DEX and the original runner, and assembles with an ephemeral development signer. The device signing key is not part of CI. Historical MNN v7 remains; v8 binds this public source. UI-Venus v2 binds the new profile and the exact 19-file / 18-unchanged / four-literal native-source boundary.

No fresh public CI result or current phone success is asserted by this preparation. `PHONE-EVIDENCE-PENDING.json` is deliberately empty of verdicts. Actual installation, full-nine, offline restoration, Stop/restart and ordinary-user evidence must be added only after independent evaluation of that exact candidate. Existing failures remain failures. UI-Venus requires a separate ordinary-App model-only qualification before any future controller integration.
