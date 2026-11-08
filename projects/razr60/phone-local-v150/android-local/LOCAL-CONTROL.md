# Hepta 本地: integrated local control candidate

Package remains `org.trillionnium.hepta.localprobe` so signed updates preserve the imported model. Control versionCode is 5, versionName `0.2.2-local-control`; the separate ordinary-UID inference qualification builds are 0.1.0/code1 and 0.1.1/code2. The APK declares no application permissions, including no INTERNET permission. Android's standard Accessibility binding permission guards the service; the user enables it normally in Settings.

## Owner interface and lifecycle

The launcher contains a Chinese task field, Start/Stop controls, Accessibility Settings entry, status/history/result views, and a local inference diagnostics panel. Model startup uses the configured Qwen3-VL-4B QAIRT/Hexagon backend. Its actual hardware qualification must be established by fresh ordinary-UID device logs and receipts.

The Application owns one LocalModelEngine and one LocalTaskSession. The engine has a process-wide admission lock as well as its own Process ownership. The Accessibility service lazily owns the sole controller; Activities bind to the Application session and can stop an existing task after reopening. `singleTask` prevents ordinary duplicate launcher instances but is not the only concurrency gate. New task epochs reject old callbacks; uncertain cleanup blocks new tasks. There is no automatic task restoration after app restart.

Before the first observation, the visible Activity normally moves its own task behind the foreground screen and waits 500 ms. Status/log views are excluded from the Accessibility tree so their own updates do not invalidate an observed Hepta window. UI/node/webpage text is untrusted observation data; the original owner instruction is preserved throughout planning and a bounded format correction.

The service observes a fresh screenshot and active-window nodes, associates a unique observation ID, and executes only a strict single JSON action. Supported actions are open, click, type, scroll, back, home, wait and done. The controller checks current window/tree identity before effects, optionally checks target pixels for coordinate clicks, and observes again after each accepted action. Only `open` uses window/package/rotation/geometry freshness without requiring an identical full tree; its target must still be an installed launcher entry. Node actions, coordinate actions and `done` retain the full-tree gate. Reopening the already foreground package dispatches no action and enters the bounded repair path. A `done` result is recorded as `model_reported_done` with `goal_independently_verified:false`; separate visible postconditions are required for acceptance. No raw SDK log is interpreted as an action.

## Private debug task trigger

An arbitrary launcher Intent cannot authorize phone control. Normal users press Start. Device tests may import a one-use JSON into this package's own `files/debug-task.json`, owned by its app UID, mode 0600, one link, at most 8192 bytes. Use `tools/create_debug_task.py` to prepare the file; it does not interact with a phone.

Exactly these fields are required: `schema="hepta.private-debug-task.v1"`, `nonce` (64 lowercase hex), `instruction` (unchanged owner text, at most 1600 UTF-8 bytes), `created_wall_ms`, and `expires_wall_ms` (no more than ten minutes after creation). The visible launcher is then opened with `auto_task=true` and `test_nonce=<nonce>`. No action names, target coordinates, model paths or executables are accepted in that Intent. The app verifies the private file and nonce, atomically consumes it into `files/debug-consumed/<nonce>.json`, and schedules one new task. A busy or unavailable service refuses before consumption. A request consumed before a later start failure is still recorded as consumed and is never replayed.

`files/debug-trigger-result.json` records accepted and consumed separately. `files/control-session.json` records the active task ID, nonce SHA, owner SHA, status, cleanup and evidence directory. Per-step screenshots, observed nodes, prompt budgets, exact model output, accepted/rejected action and final receipt live under `files/control-tasks/<task-id>/`. Native inference evidence remains under `files/runs/<request-id>/`. These private traces and test requests must not be committed or uploaded.

The diagnostic text trigger remains `auto_run=true`, with `prompt`, optional `system_prompt`, `mode=text|image`, `max_tokens`, and `timeout_ms`. It only performs inference and refuses while a phone task is active. It cannot execute an action.

## Android adaptation and publication contract

The fixed child environment searches the installed native library directory first, then the standard `/vendor/lib64`. This resolves the declared public FastRPC library dependency without changing permissions, copying private system libraries, or modifying SELinux. Namespace/access denials must be treated as failures requiring a proper app JNI design, not as success or permission bypass.

The frozen worker source remains byte-identical. `native/generate_adapter.py` verifies its SHA and generates only the Android publication changes. Output publication is `fsync(file)` then `renameat2(RENAME_NOREPLACE)` then `fsync(directory)`. It never falls back to overwriting rename. Each failure reports its phase and errno; process completion is still verified externally. The Linux contract test checks successful publication, existing-file and symlink collisions, empty output and failed fsync. It is not a substitute for app-domain device verification.

## Build and verification

`build_mac.py` compiles framework-only Java, Accessibility XML, D8 and the pinned native adapter with cached tools. `assemble_pocket4.py` packages cached libraries, signs with the same dedicated local debug key, and validates no INTERNET/application permission, ABI, vendor declarations, service guard, signature, resource alignment and artifact hashes. Model weights and keys stay outside source control. Original qualification APKs and static receipts are preserved.

The meaningful acceptance gates are: fresh app-UID text and image inference using HTP, offline operation, actual process termination after cancellation, single-task/reopen behavior, strict parser rejection cases, continuous tasks without stale callback contamination, and visible app-specific postconditions for the requested UI operations. A build or model's self-reported done is not itself end-to-end acceptance.

## Revision 5 grounding changes

The prompt includes the last action outcome and current foreground package. It asks the model to finish a satisfied open-only task rather than repeatedly reopen the same app. Visible child labels are folded only into their real interactive ancestor, and the folded text is included in the observation digest. Node identity also includes checkable, checked and selected state. Parsing accepts the exact Android system package `android`; unrelated single-segment package strings remain invalid. These changes retain strict JSON validation, original owner text, bounded repair, cancellation ownership and the unverified model-done status.
