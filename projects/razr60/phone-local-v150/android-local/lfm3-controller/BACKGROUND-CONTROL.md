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
