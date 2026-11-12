# v51 physical-phone acceptance scope

The pinned candidate runtime configuration is in
`provenance/v51-responsive-observation-20261111/runtime-qwen35-4b-npu8192.candidate.json`.
It selects Qwen3.5-4B Q4_0, NPU, 8192 context tokens and four threads. Its bytes
match the latest retained v50 configuration receipt. The file is a reviewable
candidate, not a new configuration write or a claim that this model won a
same-device comparison. No external model endpoint is introduced.

## Preconditions

Use the existing cooperative phone owner protocol. A host process being idle
does not release its lock. A later install must first prove the normal owner
handoff, the actual installed package identity, terminal task/cleanup state,
existing configuration, source-bound candidate APK and original signing identity.
Preserve model files, application data and task evidence. Do not uninstall or
replace the existing signing key to force an upgrade.

The v51 production build is frozen at
`b4ff6d2c0b09208d341cacf8fc1cac18489c9cfd`. Later acceptance-tool changes do not
alter its 182 Android build inputs. Source checks, Android compilation, signed
APK verification, installation and actual phone effects are separate gates.

## Acceptance matrix

| Case | Required observable outcome | Current verifier boundary |
| --- | --- | --- |
| Ordinary Hepta Start/Stop | A user-visible Start creates one task; Stop reaches a terminal result with known cleanup; no duplicate action or stale publication | Observation host fixtures cover scheduling, not Android response time |
| Local inference | Exact pinned model/hash and app UID, HTP v79 or deliberate GPU trace, original tool JSON and matching native request receipt; external model disabled | NPU selection alone is not proof of all-operator NPU execution |
| Background Notes | Model creates the requested note, complete body is saved, the unique created list item is clicked by this task, reopening proves the complete body, final observation and teardown agree | Use the existing supported literal Notes contract; an intent launch does not prove saving |
| Calculator | Model enters the authorized expression and the genuine result view shows its answer | Current v50/v51 has an input guard and a pure result matcher, but no wired task-completion provider; do not claim qualified task success |
| Flight search | Actual route, date and passenger/search constraints agree with the returned app results | No flight-result completion provider yet; do not book a ticket as a diagnostic |
| Shopping search | Actual query, item and relevant displayed details agree with the instruction | No shopping-result completion provider yet; no real order/payment in this diagnostic scope |
| Main-screen coexistence | While the model operates the virtual display, independent main-screen scrolling, typing and app switching remain correct; focus, IME, gestures and task migration are recorded | A static foreground app or focus-only sampling does not establish this |
| Recovery | Cancellation, blocked IO, app/process restart, screen off and virtual-display loss produce explicit outcomes and preserve recovery evidence | Never turn an unknown cleanup result into success or silently retry an action |

## Test entry points and limitations

`tools/phone_acceptance.py` can collect and verify original task/native artifacts.
Its diagnostic `run-task` entry uses a private nonce/Intent and is not evidence of
the ordinary UI background Start path. Production v6 fixed-intent receipts need
their own prompt-domain, app identity, payload, pre-dispatch journal and broker
binding checks; the new verifier retains the distinction between launch
acceptance and goal completion.

The historical `provenance/background-v36-bff66-20261110/phone-tests/r2` runner
pins older helper bytes, a fixed calculator task and a static main-screen
baseline. Preserve it as historical evidence. Do not remove its hash checks,
silently substitute current tools or present it as a full v51 coexistence test.

For the final model decision, repeat the same accepted task set with the same
observation input and context budget on Qwen3.5-4B NPU and GPU, followed by
selected smaller/larger candidates. Record task completion, tool validity,
first-token and decode timing, process/system memory, temperature and foreground
responsiveness. A model file being present or a generation benchmark completing
is not a passed phone-agent task.
