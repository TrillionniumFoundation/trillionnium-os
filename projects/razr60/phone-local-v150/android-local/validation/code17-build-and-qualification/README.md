# Code17 local build and qualification boundary

Code16 is preserved as commit `2e4cc3ac1d59637e2967aee82a06252fa1a906dd`.
The frozen Code17 observation changes and v5 CI binding are commit
`c726c48b7f9f9477957a138f5a9c826643d423da`.

The controller now exposes observed editable fields with their current values,
keeps other visible text neutrally labelled, and projects a bounded sequence of
already dispatched actions. These changes supply information for the local
model's next decision. They add no task-specific answer, app script, coordinate
shortcut, native tool protocol, or automatic replay. Action freshness, policy,
and the unchanged native inference runtime remain separate gates.

## Local preparation

`LOCAL-PREPARATION.json` binds the exact source, actual Mac Java/DEX/Android arm64
build, source archive, unsigned build, original signer, packaged APK, Bolt NPU
4096 candidate, and nine-case plan. The APK uses the existing certificate; no
replacement key was created. All 16 packaged native members match Code16
byte for byte, as recorded in `NATIVE-CLOSURE-COMPARISON.json`.

The cached NDK directory name was not used as version evidence. Its actual
`source.properties` reports r28b/28.1.13356709, and the compiler reports Android
clang 19.0.0. The build used the installed Temurin 17.0.7 toolchain, platform 34,
and build-tools 34.0.0.

## Local host results and remaining gates

`LOCAL-HOST-COVERAGE.json` preserves the real split result: 44 of 46 gate names
have a passing local execution, with no single-host full-suite pass. Mac Java
contracts, including the new editable-field and dispatched-sequence regressions,
passed. The unchanged Linux Python tools suite passed all 152 tests, and the
private MobiMind staging tests and native contract executions also passed.

Two native host gate names still lack a local pass. The macOS SDK lacks the
Linux worker header `linux/fs.h`; the Pocket4 Ubuntu 26/GCC15 host introduces
POSIX/XOPEN feature macro redefinitions that the original `-Werror` gate rejects.
These failures were retained. No test or compiler warning gate was removed or
relaxed. The actual Android NDK worker build succeeded and reproduced the
Code16 native runner bytes. The complete unmodified host suite subsequently
passed on the standard Ubuntu 24.04 / Temurin 17 CI runner for the exact frozen
Code17 source commit, as documented below.

The `HOST-CHECKS.json` embedded in the frozen source remains the historical
Code16 artifact. It is not evidence that the Code17 full host suite passed.
Current Code17 evidence lives in the separate records in this directory.

## Exact-head CI host qualification

[Run 42565206107](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42565206107)
used source commit `c726c48b7f9f9477957a138f5a9c826643d423da`.
Its original host suite completed with all 46 gates passing, including
`native-adapter-syntax` and `private-prompt-evidence`. The downloaded host
artifact SHA256 matches GitHub's artifact digest, and every one of the 118
recorded source inputs was independently matched to the frozen Code17 source.
`CI-HOST-QUALIFICATION.json` records the run, job, artifact, and check identities.

The macOS MNN producer also succeeded. The later Linux runtime-download step
received HTTP 504 from the pinned GenieX archive URL, so this workflow did not
reach CI Android compilation or complete successfully. The local signed APK
build is separate evidence. The failed run and original local platform
failures are retained.

The fresh full [workflow run 42569728212](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42569728212)
again passed its MNN producer and all 46 original host gates, then stopped
at the same official archive URL with HTTP 504. Producer and consumer shared
the new run and attempt; no pin, source member, test or warning requirement
was relaxed. The later Code18 workflow completed successfully after the
separate bounded transport change; it does not change either Code17 verdict.

## Retained phone regression results

Separate phone evidence now records two Code17 runs with the same original
four cases, core driver and verdict assertions. Gemma E4B QAT Q4_0 at NPU4096
passed 2 of 4; LFM3-1.7B QAD Q4_0 at NPU8192 passed 0 of 4. Both runs completed
with known cleanup and verified restoration of the temporary offline setup.
These are practical configurations with different context sizes and generated
actions, not a controlled identical-prompt speed benchmark.

The [Gemma summary](phone-regressions/GEMMA-SANITIZED-SUMMARY.json),
[LFM3 summary](phone-regressions/LFM3-SANITIZED-SUMMARY.json) and
[comparison](phone-regressions/COMPARISON.json) retain their exact plans and
receipt hashes. The [independent audit](phone-regressions/INDEPENDENT-AUDIT.json)
preserves the distinction between the confirmed long-history prompt-budget
defect, observed model action-selection errors, and the navigation observation
failure whose exact root cause remained undetermined.

These tests used the private debug entry. They do not establish ordinary
Start/Stop, lifecycle or background acceptance. Their failed verdicts are
retained and are not replaced by later source or model candidates.

## Qualification scope

The historical preparation and CI records do not stand in for phone
acceptance. The separate phone records above identify their actual candidate,
entry point, plan and results; they establish neither lifecycle acceptance nor
general release readiness. Any later workflow or candidate must identify its
own exact source head.
Device identifiers, private phone journals, signing keys, model weights, and
raw phone logs are not included here.
