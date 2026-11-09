# Standalone local Android controller contract

This subtree is a source-only candidate for `org.trillionnium.hepta.local`,
versionCode 13 / 0.13.0-local-gemma4. It is outside the active Cargo/G1 delivery graph.
It changes no owner-open protocol, protected package, ingress, claims, SELinux
policy or existing machine authority. Adoption requires independent review and
exact-build phone evidence; publication of this subtree does not grant adoption.

## Purpose and interfaces

The app accepts an exact user instruction through its visible Start/Stop UI.
An app-wide `LocalTaskSession` owns one `LocalModelEngine` and one service
controller. A private one-use debug trigger exists for observed tests; exported
Intent extras cannot choose a model, path, executable or arbitrary tool.

The Accessibility service observes the current foreground application's node
tree and a local screenshot. The pinned text model receives bounded node/readout
data and the unchanged instruction. Screenshots support freshness/effect checks;
they are not image input to this text model. The local inference adapter returns
one observation-bound action, parsed independently of its generation grammar.

Tools are `find_app`, `open`, `click`, `type`, `scroll`, `back`, `home`, `wait` and
`done`. `find_app` is an installed-launcher catalogue read. Other effects require
fresh package/window/node identity, an owned task lease and an unlocked device.
Text-model clicks require observed nodes. There is no arbitrary shell, URL,
installation, remote-model, network or fabricated app mapping tool.

The visible Activity may move to the background while the Accessibility service
acts on foreground apps. This does not promise invisible parallel app operation,
locked-screen operation, screen-off interaction, Android permission bypass, or
complete coverage of all installed apps.

## State, ownership and failure semantics

The session persists pending ownership before scheduling the controller.
Activity recreation reattaches listeners; it does not resubmit the instruction.
Known clean terminal records may allow new work after process recreation.
Unresolved/corrupt prior records block new tasks and preserve recovery evidence.
The native runner checks the expected parent and installs a parent-death signal
before explicitly initializing its SDK/plugin. See `SESSION-RECOVERY.md`.

One application process, one active model request and one service lease are
permitted. Stop cancels the owned inference handle and forbids subsequent effects.
An already dispatched effect cannot be undone. Unknown process/gesture cleanup
blocks new work. An uncertain action is not automatically retried or replayed.

The controller has 20 steps, an eight-minute task budget, a 55-second model-call
budget, at most one format repair per step and two per task, and bounded stale
observation replanning. Unsupported actions, stale nodes, locked/protected
screens, insufficient memory and malformed output fail explicitly.

## Model and resource bounds

Only a file from the explicit Java/native/host SHA-pinned profile allowlist in
the app's model directory is accepted. The original default remains LFM3 with
GenieX 0.10.0 / llama_cpp / HTP NPU, 4096 context, four support
threads. Explicit app-private configuration permits GPUOpenCL, context 8192 or
1..8 support threads. It is read once per app process and never falls back to CPU.

`TOKEN-BUDGET.md` documents the LFM3-specific conservative byte/token bound;
other profiles require the exact native token IDs, actual chat template and
profile-bound budget proof described in `MODEL-PROFILES.md` and
`CODE13-QUALIFICATION.md`. Image input is not admitted by a text profile.
Valid kernel MemAvailable is preferred for each explicit profile's admission
threshold. ActivityManager is a recorded fallback, and Android lowMemory always
refuses. An admission threshold is not measured peak-memory qualification.
The app admits at most 4096 installed launcher packages and exposes bounded
search pages. `APP-DISCOVERY.md` defines search and prompt pagination semantics.

## Evidence and service indicators

Task receipts bind original instruction hash, task/nonce, observation IDs,
model run ID, actual prompts, grammar/input/output hashes, actions and post-action
observations. Native receipts bind runtime, model, backend request, publication,
budget and cleanup. A resolved device name or token speed alone does not prove
accelerator execution; positive offload/buffer/profile evidence is required.

`model_reported_done` is not independent success. Acceptance needs final UI
predicates and required dispatched effects. Track all planned attempts, passes,
failures, unverified and not-run cases; retain unknown submission outcomes.
Useful measures are task completion, latency to first action, prefill/decode
speed, peak process/RAM use, stale/format rejection, stop latency and sustained
temperature/throughput. No unmeasured performance SLO is claimed here.

Raw tasks, app inventories, screenshots, prompts, local signing material and
private histories remain outside the public repository. Published host checks
use synthetic fixtures. See `tools/PHONE-ACCEPTANCE.md` and `tools/PHONE-SUITE.md`.

## Build, migration and rollback

`PUBLIC-BUILD.md` defines source closure, host checks, Android compilation and
assembly. Assembly binds cached outputs to current source and actual APK version.
An installed package must be upgraded with its original signer and its app-private
model retained. A differently signed CI package is not an upgrade artifact.
Do not uninstall or delete model/session data merely to make a test pass.

Before device promotion, capture the actual installed identity and retain the
previous source/APK evidence. Rollback requires the matching signer and a reviewed
version strategy; Android downgrade/data loss must not be assumed safe. Restoring
an earlier source build does not resolve an interrupted task or replay its actions.

Required gates still include exact-source Android build, actual installed APK,
ordinary-UID NPU/GPU execution, model-driven app discovery/actions, independent
UI goals, offline operation, interruption/restart, thermal endurance and a vision
path for inaccessible custom UIs. Host/CI success cannot substitute for these.

Official Android API references:

- https://developer.android.com/reference/android/accessibilityservice/AccessibilityService
- https://developer.android.com/reference/android/view/accessibility/AccessibilityNodeInfo
- https://developer.android.com/guide/components/activities/background-starts
