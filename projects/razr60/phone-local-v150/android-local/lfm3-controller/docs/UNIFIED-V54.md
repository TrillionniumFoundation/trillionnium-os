# v54 integration and acceptance scope

This standalone Android candidate is outside the active Cargo/G1 source graph.
The change affects Android observation lifecycle, completion cancellation and
launcher availability (D3/D5); it does not activate a registered G1 module.

## Frozen integration inputs

| Input | Exact source | Retained behavior |
| --- | --- | --- |
| Current v52 branch | `9414df636f5a20e3b5a5ee7582af9d81beb17aac` | v51 Notes single-use child grants, independent controller completion, v52 explicit background selection persistence |
| PR 143 | `5bc3b7c5a0bd80318438ee4303bda8a62b5bfd3a` | Process-wide observation worker, event fences, deadline/Stop checks, strict v6 fixed-intent acceptance verifier |

PR 143 was based on v50. Its alternative versionCode 51 must not replace the
newer Notes-workflow source. This candidate uses versionCode 54 and preserves
the current package identity. The imported PR receipts and proposed Qwen model
configuration remain historical evidence for their exact sources. They neither
select the current phone model nor establish v54 host, Android or phone success.

The final installed-package check can block after an earlier Stop check. The
integrated controller therefore clears both `modelSuccess` and
`controllerSuccess` when a Stop arrives during that IO. The host completion
fixture exercises the real controller and verifier with a completed Notes child
workflow, stops inside package-manager IO, and checks cancellation with known
cleanup and a retained block with unknown cleanup. A separate five-decision
model-done path reaches the same blocked verifier and must also cancel without
verified completion. The workflow path does not fabricate a model-issued `done`.

Invalid local runtime configuration is shown in the launcher with its actual
error. Start and text inference are disabled until it is fixed. Stop, cleanup,
permission navigation and existing background selection validation keep their
prior behavior. No default model configuration is substituted. The regression
fixture extracts the actual production refresh and runtime methods; Android
widgets, package IO and model execution remain explicit host fakes.

## Source, build and deployment gates

The source manifest lists every current source file and hash. Its old v30/v51
metadata and historical host results cannot be reused as qualification. Run
`tools/verify_source.py`, followed by `tools/run_host_checks.py --out` with a new
output directory and a complete JDK supporting `javac --release 8`. A
`-source 8 -target 8` supplemental run is not this API gate.

Use the exact source-bound Android and packaging receipts described in
`PUBLIC-BUILD.md`. Preserve the original installed signer, app-private weights,
runtime configuration and task journals. Installation requires the existing
cooperative owner handoff and known task/cleanup state. A busy or quiet host
process does not release its phone lock. Never uninstall to bypass signer or
version checks. A rollback needs a separately reviewed same-signer version
strategy and must preserve recovery evidence.

## Required physical-phone evidence

| Case | Evidence needed before reporting success |
| --- | --- |
| Ordinary launcher Start/Stop | One actual UI-started task, local model/tool receipts, Stop during inference and observation, explicit terminal status and known teardown |
| Notes regression | Exact authorized body, real model parent, single-use child receipts, saved list item and complete same-item readback, independent completion and native-session binding |
| Preference restoration | Cold launcher reopen restores explicit mode/range/initial app without starting a task; changed or absent package identity disables background Start |
| Background coexistence | Real model task on the owned virtual display while the user independently scrolls, types and switches main-screen apps; focus, IME, gestures and task migration recorded |
| Offline local inference | Exact active model hash/configuration and ordinary app UID, actual selected accelerator trace, original model outputs and native session receipts, no external model endpoint |
| Flight and shopping search | Actual query/route/date details and returned app results agree with the instruction; no booking, order or payment merely to test the controller |
| Recovery | Cancellation, blocked IO, service/process restart, screen-off and virtual-display loss retain evidence and do not automatically retry uncertain actions |

This candidate does not add a flight or shopping result completion provider.
The fixed-intent launch verifier alone cannot establish those goals. The current
calculator matcher also has no wired task-completion provider. Those boundaries
must remain visible in any acceptance report.

`tools/phone_acceptance.py` normal mode is a main-screen navigation driver that
accepts `model_reported_done`; it does not score the background Notes
`controller_verified_done` workflow. Its v6 support verifies fixed-effect
bindings, not that workflow's complete save/list/reopen proof. Background Notes
requires separate receipt replay and a dedicated case that verifies the actual
controller/tool-child, display-generation and native-cleanup evidence. Do not
broaden the normal-mode accepted terminal names to substitute for those checks.

Observation traversal, image copy and file IO leave the main looper. The
synchronous action-validation graph reads do not. Host scheduling tests therefore
cannot establish a worst-case Android response-time bound, thermal behavior or
uninterrupted main-screen use. New admission remains unavailable until an
uncancellable read actually exits; a timeout does not start another worker or
weaken the task/display/authorization fence.
