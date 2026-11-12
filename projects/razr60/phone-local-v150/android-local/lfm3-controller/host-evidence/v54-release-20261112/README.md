# Hepta v54 source and evidence snapshot

This directory makes the release's source, host, Android, signed artifact, and selected device records reachable from Git. The APK source commit is `42d3a0f447807659c0f78c8273edee01dd1b734f`; this evidence-only successor preserves all 589 source blobs. The original JSON and text bytes are preserved. Files here are outside the 589-file build inventory. [EVIDENCE-INDEX.json](EVIDENCE-INDEX.json) lists the exact size, SHA-256, Git blob, and scope of every retained item.

## What the records establish

| Area | Evidence and scope |
| --- | --- |
| Main source | Final 589-file closure from the actual v53 base `7dee83d838b2c76b3abe3a3e61d7837316f40853`: 29 existing files changed and 19 files added, represented by 48 overlays. |
| Complete host gate | The actual P4 r4 stage passed 101 checks over 413 inputs, with 18 nested completion stages. The original command, Java 8 API-release contract, source map, and unchanged-source checks are retained. |
| Android and native | Actual r6 built 109 Java files and 403 classes from 211 compiler inputs. The final source differs only in five Python host-fixture entry files; the preservation sidecar reverses each change to the compiled source bytes. Android was not rebuilt for those Python-only fixes. |
| Helper5 | The unsigned Android build contains 38 source files, 36 Java files, 7 generated files, 154 classes, and 372 compiled APK members. The new bounded capture-attempt gate passed 33 cases and 175 assertions. The prior four pure-contract groups are referenced by their original hashes, not represented as rerun. |
| Signed main54 | The actual signing and artifact closure passed for `0.54.0-natural-official-web`, APK SHA-256 `0729f54704a058049e12041c7f901b1b6650924500663cf9952a03d6a33a8b8a`. Its receipt binds source commit `42d3a0f447807659c0f78c8273edee01dd1b734f`. Its only declared permission is the helper evidence binding permission. The receipt retains phone, flight-query and flight-result verification as false. |
| Signed and installed helper5 | The actual signed `0.5.0-web-evidence-v3` APK is SHA-256 `b5e56ce0c2967489b55150c157f8289fdd82ad5b89caacc8b106013a7caeaf4f`. A separate original installation receipt confirms UID 10484 and preservation of all 33 prior diagnostics. That installation performed no site open, capture or model task, and reports no business verification. |
| Existing device evidence | v53 Notes, cancellation, and recovery originals retain their actual status fields. Independent reviews state their narrower conclusions without rewriting the original `qualified=false` or native receipt flags. |
| Manual helper4 evidence | Two Mi capture attempts failed to produce a successful DOM record. Normal retirement later produced one new close record after one ordinary Back. These records do not establish a formal task lease or a shopping result. |

## Preserved failures and limits

The r3 P4 failure and r3/r4 query-test failures remain separate original records. The final host fixes copy the same Java fixture bytes under their proper compiler basename and add the missing pure Goal dependencies; they do not relax Java warnings, change the production Java/native source, or remove assertions.

The helper5 change permits at most three read-only attempts under the same absolute deadline, only after a full-DOM mismatch. Successful capture still requires exact full-DOM equality and all four geometry observations. A retained instability pair carries no action or business authority. The candidate payload in this directory is a source delta plus test fixtures; the complete 38-source archive is separately pinned by the actual unsigned BUILD.

Main54 has a guarded single-query flight path, but its flight results provider remains incomplete until implemented against real result-page evidence. A query dispatch cannot establish a completed flight search. Shopping is limited to the recognized Xiaomi AX3000T public-price goal; it does not implement a cart, order, payment, or a general purchasing completion contract. Generic UI primitives do not by themselves prove a completed purchase.

Original full `HOST-CHECKS.json` and nested completion JSON are pinned by the verified P4 stage; their full bytes are not yet included in this snapshot. This limitation is explicit in the index. The signed main54 and helper5 receipts, helper5 installation receipt, and original source publication map and receipt are now included. Their original bytes and historical status fields are unchanged. Later device evidence may be appended separately; the APK remains bound to source commit `42d3a0f447807659c0f78c8273edee01dd1b734f`, even when the branch advances through evidence-only commits.

No screenshots or unrelated device dumps are published here. No phone action was performed by this publication.
