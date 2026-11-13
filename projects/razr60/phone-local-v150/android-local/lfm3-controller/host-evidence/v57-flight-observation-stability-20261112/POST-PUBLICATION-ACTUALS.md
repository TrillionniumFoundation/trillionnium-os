# Main57 signing, installation and actual Flight evidence

Main57 is installed and its Flight task ran. The task failed after five steps with `AX/DOM bracket changed; no current page capability published`. The original collector exited 0 after collecting evidence and releasing resources. Query dispatch, completion verification and business verification remain false. The result provider remains unavailable.

This evidence-only publication leaves the 595 source files from commit `313685edc580a750aea6301d8ff3cfd617d6fab6`, aggregate `517e61599073eb264c5e52871570d49e7af2d798`, and inventory SHA-256 `22d32f2de9ecd5690e1dfe7de8fa682b3a0469584ade1ec83ac69bf6558d10b6` unchanged. The earlier [source report](REPORT.md) and [source index](INDEX.json) remain historical snapshots. Their signing and phone-test status was accurate when that source commit was created; this report supplies the later observed facts without rewriting those originals. The original [PUBLICATION](PUBLICATION.json), [source blob map](GIT-SOURCE-BLOB-MAP.json) and [source-publication proof](SOURCE-PUBLICATION-PROOF.json) are retained as their original bytes.

## Signing and installation

The [signed receipt](main57-signed-RESULT.json) records six normally completed signing steps, the existing certificate and APK `hepta-local-0.57.0.apk`: 21,038,933 bytes, SHA-256 `c1e126031ff8728a3335a5ef1e6d546b3b089ca03ee73a8b3671b67b7e124ad4`.

The first installer stopped in a host prerequisite because the actual `omitted_screenshots` value was an empty array while the guard expected numeric zero. Its [original stderr](main57-installer-r1-preclaim-stderr.txt) and source remain recorded. It did not reach its output claim, ADB or an installation command. The successor changed only that comparison. Its [complete installation receipt](main57-installer-r2-RESULT.json) confirms code57, UID10481, the full signed APK hash, preservation of models, configuration, cache, preferences and history, preservation of the 50 Helper records then present, and restoration of formal accessibility. Owner24 PID3386576 observed installer child3459758 exit0. No automatic model task was started by installation.

## Actual Flight57 outcome

The [original RESULT](web57-flight-original-RESULT.json), [execution receipt](web57-flight-actual-execution.json), [COLLECTION](web57-flight-COLLECTION.json), and [CAPTURE index](web57-flight-CAPTURE-RAW-INDEX.json) remain unchanged.

Task `495b2b1e79a449e99c2fc604da1f452d` ran five steps. It did not dispatch the bound query and did not verify flight results. The original `qualified=false`, `business_verified=false`, `completion_verified=false` and `sdk_teardown_verified=false` are not replaced by the collector's exit status. The task records ordinary Helper close, cleanup known, VD28 release, absence of the recorded active-resource markers and release of the operation lock after 804 continuity checks. This run was `background_only`; it contains no main-screen coexistence action.

Preparation, the Root's whole-frame visual review, Owner24's normal close, the final RUN wrapper and the unique execution request are included. One read-only PTY poll timeout is recorded separately; it did not cause another RUN submission.

The collection indexes 150 task files, 49 model/session files and 66 Helper files. Fourteen CAPTURE raw FD records are indexed. A data collector or capture index is not a business-result verifier.

## Local-model requests and normal parent cleanup

The [12 original app/native receipts](FLIGHT57-NATIVE-APP-RECEIPT-ORIGINALS.json) contain five request pairs and one parent-session pair. Every embedded raw file was independently checked against its complete SHA-256. All five requests are bound to the same task and worker generation `218e649e1e7c472ba641d21909a908ba`, native PID4726. They report request status0, SDK generate0, deviceHTP0 and no automatic CPU fallback. Individual request receipts retain `process_exit_observed=false`: they describe requests made within a retained worker, not five separately exited processes.

| Request sequence | Prompt tokens | Generated tokens | TTFT seconds | Decode tokens/second |
| --- | --- | --- | --- | --- |
| 1 | 2968 | 121 | 2.969870 | 31.645669 |
| 2 | 3319 | 132 | 3.386504 | 30.323928 |
| 3 | 3557 | 111 | 3.632854 | 31.282225 |
| 4 | 3687 | 124 | 3.727411 | 31.613161 |
| 5 | 3815 | 126 | 3.886069 | 30.760637 |

These are five different prompts in one actual task-session. They are not a cross-model controlled benchmark.

The app parent receipt observed process exit0, no force, known cleanup and `normal_close_with_observed_sdk_cleanup`. The native parent receipt records five requests received/completed, five model resets, five control-DONE writes delivered without a write error, SDK destroy0 and deinit0. The native parent's own `process_exit_observed=false` remains unchanged; the app parent supplies the independent exit observation. These complete parent records establish this bounded cleanup fact independently of the original outer collector's still-false SDK field. They do not turn the failed flight task into a successful query.

The [original binary SDK stderr](FLIGHT57-PARENT-SDK-STDERR-ORIGINAL.json) contains 53,429 bytes with SHA-256 `7cc1578012c2b2a143706dda53646b97249008018135ec000d0f685e729a1d70`. Its canonical base64 and full raw hash were checked. The selected backend session reports Hexagon v79, HTP0, threads6, HVX6, HMX1 and VTCM8MB. These are device/backend reports, not six physical NPU cores or a whole-chip core count; ndev2 is not two physical NPUs. The line about 25/25 layers “to GPU” uses the runtime's generic offload wording; the selected device in the same log is HTP0, not Adreno. There is no independent hardware-counter, all-operator, power, thermal or peak-RSS conclusion.

## Original archive and read limits

The [complete compressed archive manifest](FLIGHT57-COMPLETE-GZIP-ARCHIVE.json) makes all 36 original base64 chunks reachable under `flight57-original-text-archive/`. Each Git blob, canonical base64 representation, decoded chunk size/SHA and contiguous offset was checked. The reassembled compressed stream is 1,726,746 bytes, SHA-256 `dafce5150fc43b19790ec8340a5d7902baa14a403773e3270632334ef5bd93cf`.

The host pack records 218 selected originals, 201 transmitted files and 17 omitted PNG bodies, with their original pins retained. It records complete original-file hashing and gzip CRC verification. Root's attempted large local decompression did not complete. This publication verifies the complete compressed stream and does not claim that the 35,244,429-byte text envelope was decompressed here. It does not replace omitted PNG bodies with descriptions or synthesized pixels.

The [15 step/model/progress originals](FLIGHT57-STEP-MODEL-PROGRESS-ORIGINALS.json), [three final native scopes](FLIGHT57-LAST-THREE-SCOPE-ORIGINALS.json), request/session receipts and SDK log were separately verified in full against the collection. Their smaller raw records remain available without inflating the full archive.

## Main58 candidate and current connection block

The `pending58/` directory preserves candidate material only. Aggregate `94ca147166c4e4c7faa5bd32085c5431eb36f4b1` changes only WebFlightSession and the Manifest to code58 / `0.58.0-flight-observation-settle`; the other 593 files are identical. It preserves the original stability and action guards, obtains fresh AX/DOM observations within the existing bounded wait, and does not replay the destination-city click. It does not add a results provider.

The [Root's original blocked checkpoint](pending58/ROOT-BLOCKED-CHECKPOINT.json) preserves a unique Core58 Start ACK (PID3934790) and the subsequent `tunnel_client_not_connected` response around 01:47 UTC on 2026-11-13. Core58's final result and exit are unknown. The recorded request must not be replayed to resolve that unknown. Focused58, Web58, Android58, signing58 and installation58 have not executed. Main57 remains the observed installed version.

The unsubmitted Focused58 candidate used `sha257` in two prior57 receipt-consumer lines. Its original request is retained and marked withdrawn. The corrected source changes those four field references to `sha256`; CONFIG was already correct and is byte-identical. The actual57 receipt was read and both fields matched the existing CONFIG. All 51 compile records, 15 projected methods and the original 39 case assertions are unchanged. The corrected unique request, full source hashes and gzip roundtrip are recorded, without an execution or pass claim.

[Pending status](pending58/STATUS.json) and [complete evidence index](POST-PUBLICATION-ACTUALS-INDEX.json) distinguish these candidates from actual57 results. The Main56 Notes creation/reopen, main-screen scroll, cancellation and recovery conclusions remain attached to Main56. Shopping remains limited to the AX3000T official public-price scope, with no phone pass and no checkout implementation.
