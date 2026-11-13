# Main57: bounded Flight observation stability

This snapshot contains the five reviewed source changes in aggregate `517e61599073eb264c5e52871570d49e7af2d798`. All four current host stages have complete original receipts and passed. The source inventory contains 595 files with SHA-256 `22d32f2de9ecd5690e1dfe7de8fa682b3a0469584ade1ec83ac69bf6558d10b6`. There are 217 Android compiler inputs and 115 Java sources. The production base is Main56 source commit `9f4168616546233033edd4b254b4236ae987ea7e`; the compare-and-swap parent is the evidence head `c28266b18703bbb6287d2a3d7809384921214d01`.

## Scope of the change

Main56 stopped during the native observation bracket, before its action-time stability exception could participate. Main57 adds a separate read-only observation-bracket proof. It compares complete bounded native snapshots and retained observations, independently replays geometry, requires all four bound DOM strings to be identical, and limits tolerated native variation to the observed homepage advertising subtree. It preserves owner, selection, window, epoch, IME, target, ancestor, geometry and completeness checks. The proof does not grant an action permit or replace the original native node reference. Truncated or unknown evidence remains a rejection.

The added local proof is written to the task's web-frame evidence. It is not added to the model prompt. The Flight results provider remains unavailable; no result-page selector or inferred result contract is introduced.

| Source path | Change |
| --- | --- |
| src/org/trillionnium/hepta/local/HeptaAccessibilityService.java | Complete bounded native observation snapshots, private read-only handle and cleanup |
| src/org/trillionnium/hepta/local/WebFlightSession.java | Use and retire the read-only bracket proof while preserving existing action fences |
| src/org/trillionnium/hepta/local/WebFlightNativeStability.java | Strict observation-bracket comparison using current native and bound DOM evidence |
| tests/web-flight/run_query_host_tests.py | Integrate the previously explicit count-only repair: 46 paths / 44 production inputs |
| AndroidManifest.xml | Version 57 / 0.57.0-flight-observation-stability |

The remaining 590 source files are byte-identical to Main56. The source path set and 40 overlay entries are unchanged. No production class was added. The 17 native payloads are reused byte-for-byte from the verified signed54 inputs; no NDK, clang, or native generator execution is claimed.

## Actual host results

| Stage | Actual result | Original receipt |
| --- | --- | --- |
| Core | 101 groups, 419 host inputs; 18 completion stages are included within those 101 | [core57-RESULT.json](core57-RESULT.json) |
| Web | 80 cases / 92 assertions; 79 / 215; 13 / 1001; four normal child exits | [web57-RESULT.json](web57-RESULT.json) |
| Focused | 20 cases / 60 assertions plus 19 / 98; 51 Java files, 44 pure sources, 15 exact method projections | [focused57-RESULT.json](focused57-RESULT.json) |
| Android | Eight normal tool exits; 217 inputs, 115 Java sources, 425 compiled classes | [android57-RESULT.json](android57-RESULT.json) |
| Query | The original 40 cases / 187 assertions ran using the corrected repository runner; 50 Java files | Nested original query report in the Android receipt |

The unsigned APK is `hepta-local-0.57.0-unsigned.apk`, 21027622 bytes, SHA-256 `0b5d20941940d12bca1a9a0e30a6d1b20ff010326285e772e8f01a0956d0bb51`. All current stage receipts bind aggregate517e and the same 595-file inventory. Original inputs, generated sources and the distinct prior success and failure trees were checked unchanged by the stages. The complete original JSON bytes are preserved; their timestamps were not parsed and reserialized for publication.

## External Web fixture boundary

The observation tests retain the original four Android FD/AX records and all four original DOM strings. The complete 89-node traversal used by the positive fixture is explicitly synthetic; it is not presented as an archived complete Android traversal. The recorded Android observations contain 49 retained nodes.

Desktop JSON-java20240303 omits Java-null map entries, while the original Android binding includes an explicit `find_query:null`. The corrected host fixture first recompiles and verifies the complete original authorization. It then derives a host copy by deleting only that null entry; restoring the entry must reproduce the entire original capture. Missing or non-null values are rejected. The unmodified production binding verifier is run on the derived copy. The original binding hash is `427b3e7743e044dc06643468e976ba0fd47c27b28b21203473fd31738937dc53`; the explicit host-derived binding hash is `b56264d8894c3c3946437e9aab857c3ccf8453170396acfbff5e556411da1e69`.

This adds four assertions inside an existing case. The old 70 cases and the nine observation cases keep their exact order; no production file or original capture was changed for this compatibility repair. [The fixture change](web57-null-fixture-change.json) and [independent review](web57-null-fixture-review.json) preserve that boundary.

## Preserved failed attempts

- [Web transport failure](web57-transport-failure.txt): the loader length assertion failed before source publication. Its exact correction is separate in [web57-transport-fix.json](web57-transport-fix.json).
- [Web initial gate failure](web57-initial-failed-RESULT.json): compilation and evidence80 passed; the new observation fixture rejected the desktop/Android null representation. The original failure and [stderr](web57-initial-failed-stderr.txt) remain unchanged.
- [Focused preclaim parse failure](focused57-preclaim-failure.txt): the prior successful receipt's elapsed float was rejected before output creation or JVM execution. The [single receipt-parser correction](focused57-preclaim-fix.json) preserves the strict current input parser and all original assertions.
- The unused Core request before its filename correction was never submitted and is not recorded as an executed failure.

## Publication and phone boundary

The source/evidence tree preserves every existing repository entry outside the five declared source replacements and the new evidence directory. Main56's original Notes collector false values and exit2 remain unchanged. Its independent normal, cancellation and recovery scopes remain [Main56 evidence](../v56-flight-stability-20261112/CANCEL-RECOVERY56-REPORT.md), not Main57 phone results. The former PUBLICATION and source-map records are preserved.

At this source publication, Main57 is not yet signed, installed or phone-tested. The Flight results provider remains false. Host synthetic tests and Android compilation do not establish a completed flight query, price result, native Binder behavior, or any shopping order or payment. The original failed Flight55 and Flight56 tasks remain failed. All requested business scenarios are not yet complete.
