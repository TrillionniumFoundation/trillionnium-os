# Explicit background application tasks (v36 candidate)

This candidate adds an owner-selected background display to the existing local
model controller. It is based on v35 owner authorization and includes the v34
private-files identity and pre-ranking scope projection fixes from 93cbeb0.
Host protocol passes alone do not qualify Android operation or model success.

## User flow

The user chooses **在后台空间操作**, selects one to six installed applications,
chooses the initial application, and enters the task. The initial application is
an explicit owner bootstrap, recorded as `bootstrap_model_issued=false`.
Subsequent model requests, decisions, authorization, observations, semantic
Accessibility actions and completion evidence use the existing ordinary app UID.

Background mode is the default when no preference has been saved. An explicitly
saved manual foreground choice is preserved. A task or qualification-scope
prefill never switches display mode. An existing foreground qualification scope
still blocks background execution; it is not removed or reinterpreted.

Automated App tests must use the normal background **开始任务** path after the
current application range and initial target have been verified. The legacy
`auto_task` Intent is refused before reading the nonce-backed private request,
consuming the nonce or scheduling work: that format has no verified background selection.
Its rejection leaves the current task text, scope claim and display choice intact.
The old `tools/phone_acceptance.py run-task` and `tools/phone_suite.py run` drivers
are also retired at their entries, before creating output, connecting to ADB,
writing a nonce or launching Hepta on the main display. They have no override flag.
The `collect-status` receipt reads, offline suite `validate` parser and pure
evidence helpers remain available; retained legacy flow tests use fake IO
only and do not establish current background operation.
Model-only probes remain available, and explicit manual foreground operation is
still a separate supported user choice. A rejected automatic request is not a
successful background test.

The normal `su` request starts the broker from the installed APK. This requires
the phone owner to have authorized Hepta through the existing system mechanism;
the application does not change privilege policy or authorize itself. Devices
without that authorization return an error. An enabled qualification scope is
not converted, disabled, or bypassed by this feature.

## Execution and observations

The broker creates a trusted display with independent focus and disabled top
focus stealing, reads its actual flags and IME policy back, and accepts only
create, state, launch, back and close operations. Its socket authenticates the
app UID, per-task UUID and a fixed package allowlist. It does not expose a shell,
arbitrary Intent, taps, typing, HOME or external model endpoint.

The controller selects Accessibility windows on that exact display, including
the display generation in observation identity and node freshness checks.
Screenshots target that display. Back also binds the expected current package
and target UID. Background coordinate gestures and HOME are refused. No
background failure routes an action to display zero.

The selected application must not already have a task on another display.
Android application launch is not an atomic operation with this preflight
check: an application can launch other activities, and a user can concurrently
open the same application. Actual phone testing must therefore measure both
display placement and main-screen behavior; the design does not establish
complete isolation between applications sharing one Android user.

## Stop, expiry and recovery

A durable app-private lease is written before any broker spawn. The absolute
lease deadline prevents a delayed privilege prompt from creating a fresh long
session. Stop, keyguard lock, expiry and teardown retire the session. Dispatch
and release share a gate; independent monitoring records unknown cleanup if
Binder fails to return.

Only a broker release receipt plus app-side display absence removes the lease.
An error, process kill or journal unlink failure is not reported as successful
cleanup. Recovery closes the recorded generation or verifies expiry/reboot and
display absence; it never resumes a task. Unknown cleanup blocks new work.

## Verification boundaries

`tools/run_host_checks.py` runs the existing regression suites, the actual
BackgroundSession client tests with explicit host IO surrogates, and the actual
pure-Java BrokerProtocol tests. Its release build uses `--release 8` and strict
compiler warnings. These tests do not start root, Android or a model.

`build_mac.py` compiles all Java against the cached Android 34 SDK, produces DEX,
and compiles the native runner against the pinned existing inference libraries.
`assemble_pocket4.py` verifies exact compiler inputs, runtime library pins,
package permissions and the existing signer before an APK can be installed.

Phone acceptance must separately establish local NPU/GPU inference, successful
task effects, main-display concurrency, lock/stop/expiry recovery and complete
release. A model's `done` output does not independently verify the requested
goal. Shopping and flight queries may use the target apps' own network access;
Hepta continues to declare no Internet permission for model inference.
