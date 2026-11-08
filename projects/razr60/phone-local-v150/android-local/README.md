# Hepta 本地

**Work in progress — version 0.2.2 / code 5.** Compilation and the named host checks passed. Full phone-task qualification is pending; this source publication does not claim general app-operation success.

An Android phone assistant using the phone's own Qwen3-VL-4B QAIRT/Hexagon model and standard Accessibility APIs. It declares no INTERNET permission and never connects to an external model.

The integrated control candidate keeps package `org.trillionnium.hepta.localprobe`, preserving the private model imported during ordinary-UID qualification. Its Chinese UI supports owner task entry, Start, Stop, Accessibility setup, task progress/results and local inference diagnostics.

Read [LOCAL-CONTROL.md](LOCAL-CONTROL.md) for the lifecycle, private one-use debug trigger, strict action and observation gates, source/build contract, and acceptance limits. [PROBE-README.md](PROBE-README.md) preserves the initial inference-only qualification contract; 0.1.0 and 0.1.1 APKs remain separate from the integrated 0.2.2 candidate. [CONTROL-INTEGRATION.md](CONTROL-INTEGRATION.md) documents the independently prepared control layer.

Framework-only Java, exact pinned GenieX C ABI, build scripts, private-trigger generator and an atomic publication contract test are included. Models, native SDK binaries, signing keys, device traces and screenshots are excluded from source control. A build does not establish NPU access or goal completion: ordinary-UID device evidence, real process exit and visible UI postconditions are the acceptance gates.

[PUBLIC-BUILD.md](PUBLIC-BUILD.md) describes portable tool paths, host checks, and the source publication boundary.
