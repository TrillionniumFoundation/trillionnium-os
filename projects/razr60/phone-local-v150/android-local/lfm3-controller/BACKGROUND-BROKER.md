# Hepta background display broker candidate

This candidate adds two Java classes to the **existing Hepta APK**. It does not
install another application, add a Manifest component, alter Magisk policy, or
move inference into a privileged UID. The ordinary Hepta process is the only
permitted IPC client. An already-authorized root/shell `app_process` owns one
bounded virtual display and only the display lifecycle, launcher, and Back tools.

## Source set and entry

Copy these files into the controller's matching `src/` paths and include them in
its normal APK compile/D8/sign/build-identity workflow:

```text
src/org/trillionnium/hepta/background/BrokerProtocol.java
src/org/trillionnium/hepta/background/BackgroundDisplayBroker.java
```

Entry class: `org.trillionnium.hepta.background.BackgroundDisplayBroker`.
The classpath is the actual installed APK's `ApplicationInfo.sourceDir`. Its
source and installed APK identities must belong to the same accepted build.
The app's existing startup mechanism supplies these **six** exact argument pairs:

```text
--socket hepta-bg-<lowercase UUID>
--owner-uid <the ordinary org.trillionnium.hepta.local Android UID>
--generation <lowercase UUID>
--allowed-packages <comma-separated exact installed launcher package names>
--ttl-ms 540000
--expires-elapsed-ms <absolute SystemClock.elapsedRealtime() deadline>
```

The startup command is constructed by the app client, outside this broker. The
broker has no command execution API. It accepts only its existing shell/root UID
at startup, verifies that the ordinary owner UID resolves to the Hepta package,
and currently supports Android user 0. It does not request or grant privileges.
Expiry is `min(started + ttl, supplied absolute deadline)`; a late `su` startup
cannot renew it. TTL is 1,000–600,000 ms.

## Protocol v1

Transport: an Android `LocalServerSocket` in the abstract namespace. One request
and one response per connection. Frames are a four-byte big-endian positive byte
length followed by UTF-8 JSON. Requests are at most 16 KiB; responses at most
64 KiB. The peer UID must equal `--owner-uid`, with no root/shell client bypass.
The APK client should independently require the server peer UID to be its
selected authorized root/shell launcher UID and validate all response identities.

Requests have exactly these fields; `launch` and `back` require `package`:

```json
{
  "version": 1,
  "request_id": "abe8fba6-998b-47c9-9df3-362c77357e5b",
  "generation": "cd68504a-7fc7-40c3-a1c1-02ed5bcab8bb",
  "deadline_elapsed_ms": 12345678,
  "op": "launch",
  "package": "com.motorola.cn.calculator"
}
```

The per-request deadline is absolute Android elapsed realtime and at most ten
seconds ahead at admission. Duplicate/unknown keys, malformed UTF-8, nested JSON,
coerced numeric strings, arbitrary operations and caller-supplied display IDs are
rejected. Valid operations are `create`, `state`, `launch`, `back`, `close`.

Responses always contain:

```json
{
  "version": 1,
  "request_id": "abe8fba6-998b-47c9-9df3-362c77357e5b",
  "generation": "cd68504a-7fc7-40c3-a1c1-02ed5bcab8bb",
  "ok": true,
  "state": "ACTIVE",
  "display_id": 5,
  "flags": 0,
  "width": 720,
  "height": 1280,
  "density": 240,
  "dispatched": true
}
```

Here `display_id` and `flags` are illustrative placeholders, never fixed expected
values. Actual flags are read from the allocated Android Display. The response
also includes `operation`, `display_name`, `expires_elapsed_ms`,
`capture_secure=false`, `always_unlocked=false`, and `ime_policy="hide"`.
Failures include a fixed `error` code; no raw UI or credentials are returned.
An invalid unparseable request has `request_id=null`.

State vocabulary is `INITIAL`, `ACTIVE`, `CLOSING`, `RELEASED`,
`CLEANUP_UNKNOWN`. Actions require `ACTIVE`; a retained nonnegative display ID in
a terminal receipt is never permission to reuse it.

Completed request/response bytes are retained for the session, capped at 128
request IDs with the last slot reserved for `close`. An identical request ID with identical bytes receives its original
receipt without another effect. The same ID with different bytes is rejected.
At the cap, new request IDs are refused, rather than evicting old effect identity.
Automatic retries must preserve the original request bytes and deadline. A
transport error after dispatch remains indeterminate; a new ID must not be used
to blindly repeat it.

## Display and action contract

- Exactly one 720×1280 / 240 dpi ImageReader-backed virtual display is created.
  Its name is `hepta-bg-<generation>`. The ImageReader only drains buffers; it does
  not save or transmit screenshots.
- Requested flags match the verified prototype: PUBLIC, OWN_CONTENT_ONLY,
  SUPPORTS_TOUCH, DESTROY_CONTENT_ON_REMOVAL, TRUSTED, OWN_FOCUS and
  STEAL_TOP_FOCUS_DISABLED. Constants are resolved on the device by name.
- Actual `Display.FLAG_TRUSTED`, `FLAG_OWN_FOCUS`, and
  `FLAG_STEAL_TOP_FOCUS_DISABLED` must be present. SECURE and ALWAYS_UNLOCKED must
  be absent. Display name/ID and hidden IME policy are checked on every operation.
  The IME policy is HIDE. Chinese `ACTION_SET_TEXT` is the app accessibility
  adapter's separate operation; this broker does not open or route a keyboard.
- `launch` accepts only the exact captured package scope and a real exported,
  enabled launcher component. The privileged whole-root task query must work.
  If that package already has a task on display 0 or another display, launch is
  refused. Root-task metadata does not enumerate every buried activity; absence
  in that query is not proof that a framework task-reuse launch is safe. The
  broker therefore requires the existing standard/NONE fresh-task policy to be
  eligible and otherwise returns `BACKGROUND_LAUNCH_CAPABILITY_UNAVAILABLE`
  before changing Intent flags or dispatching launch. The policy evidence is
  retained on refusal. An eligible launch additionally requests NEW_DOCUMENT,
  keeps NEW_TASK and MULTIPLE_TASK, and clears RETAIN_IN_RECENTS. The owned
  display is selected through ActivityOptions. The launch uses the existing shell/root Binder
  identity through `IActivityTaskManager.startActivityAsUser`, a null app caller,
  the fixed shell package and Android user 0. It does not use `Context.startActivity`:
  `ActivityThread.systemMain()` supplies a Context but does not register the
  standalone shell process's ApplicationThread as an application caller.
  Success requires subsequent task readback showing
  that package visible on the owned display and absent from other displays.
- `back` requires the explicit expected package to match the unambiguous visible
  allowed package immediately before input dispatch, and no same-package task
  on another display, and a resolved target UID. Both key events carry the
  owned display ID. The framework's UID-targeted injection overload rejects a
  window belonging to a different UID. An accepted input is not a verified
  business outcome.
- There is no HOME, tap, type, scroll, screenshot, arbitrary Intent, shell command
  or general RPC operation. Existing APK accessibility code owns target-node
  observation and actions and must independently bind every node/gesture to this
  session and display.

## Cancellation and cleanup

An independent watchdog enforces startup, connection, admitted request and
session deadlines. Keyguard polling runs separately; a locked device or stale
keyguard monitor stops the session. Mutating framework calls and release share a
gate so a late call cannot start after the broker has released its display.

Cleanup runs on a separate thread and releases the display and surface, stops the
surface worker, then queries actual display absence by both ID and generation
name. Only observed absence, with no outstanding create/effect call, produces
`RELEASED`. Failed or stalled cleanup is `CLEANUP_UNKNOWN`. An independent final
deadline terminates the process if Binder or socket work stalls; process death
alone is not reported as confirmed cleanup. Normal `finally` and the shutdown
hook also request cleanup. A `close` response is flushed before normal exit.

The app must preserve a pending startup/task journal before invoking `su`, retain
unknown dispatches, and independently read back disappearance when recovering a
lost response. The absolute deadline and generation-based display name are
provided for that recovery. Kernel/system failure can still prevent timely
cleanup, so the state is intentionally capable of remaining unknown.

## Boundaries requiring phone acceptance

This code is a candidate, not a completed phone qualification. There is no
UiAutomation observer and no suppression of existing accessibility services.
The public display flag is not a security or app-data isolation boundary. Target
apps may reject secondary displays. Prelaunch checks and readback are not an
atomic Android transaction: a user concurrently opening the same app remains a
race that must be tested and may lead to refusal/cleanup. Do not advertise
universal support or guaranteed absence of transient main-screen disturbance.

Framework hidden APIs are used only in the authorized shell/root process and
fail closed when unavailable or denied. No hidden-API policy or SELinux/Magisk
policy changes are made. In particular, this candidate requires the actual
Android 16 device to expose `getAllRootTaskInfos`, IME get/set policy,
`IActivityTaskManager.startActivityAsUser` with the Android 16 signature,
`InputManagerGlobal.injectInputEvent(InputEvent,int,int)`, and
`KeyEvent.setDisplayId`. Compile success cannot establish those runtime facts.

## Host checks

```sh
python3 run_host_checks.py --java /path/to/jdk17/bin/java \
  --javac /path/to/jdk17/bin/javac --out /absolute/new/result-directory
```

The default is `--release 8 -Xlint:all -Werror`. It executes the actual
`BrokerProtocol` parser, caller/generation/package authentication, deadlines,
framing and replay table. There are 43 adversarial and successful cases. It
does not instantiate Android classes or execute a device operation. The optional
`--development-platform-only` is expressly a current-JDK development check and
cannot satisfy the Java 8/Android release gate.

The component-wide `tools/run_host_checks.py` also executes the actual launch
admission callsite, policy and task-snapshot parser with explicit Android IO
fakes. A buried-activity metadata counterexample is retained. Unsupported plans
must refuse before Intent mutation or the fake launch endpoint; standard/NONE
fresh-task plans remain admitted. This is a host logic check, not proof of
Android task isolation or absence of main-screen effects.

Full APK compilation and phone acceptance remain necessary: exact source/APK
identity, current permissions, create/state, collision refusal, model-driven
launch/observe/action/back/close, wrong UID/generation, lock, cancellation,
expired startup, process death, stale display IDs and main-screen concurrent use.

## Primary API references

- AOSP Android 16 DisplayManager flags:
  https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/core/java/android/hardware/display/DisplayManager.java
- DisplayManagerService dependency checks for own-focus/no-focus-steal:
  https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/services/core/java/com/android/server/display/DisplayManagerService.java
- ActivityTaskManager RootTaskInfo and unfiltered task interfaces:
  https://android.googlesource.com/platform/frameworks/base/+/android16-release/core/java/android/app/ActivityTaskManager.java
- ActivityThread system versus application attach:
  https://android.googlesource.com/platform/frameworks/base/+/android16-qpr2-release/core/java/android/app/ActivityThread.java
- ActivityStarter validation of a nonnull registered application caller:
  https://android.googlesource.com/platform/frameworks/base/+/master/services/core/java/com/android/server/wm/ActivityStarter.java
- Activity task Binder launch signature:
  https://android.googlesource.com/platform/frameworks/base/+/refs/heads/main/core/java/android/app/IActivityTaskManager.aidl
- LocalSocket peer credentials:
  https://developer.android.com/reference/android/net/LocalSocket
- Android InputManager UID-targeted injection contract:
  https://android.googlesource.com/platform/frameworks/base/+/HEAD/core/java/android/hardware/input/InputManager.java
- KeyEvent explicit display routing:
  https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/view/KeyEvent.java

The exact earlier feasibility probe remains in commit
`93cbeb011eb63befb4f013ccf207a181b1615711`; its device result does not qualify this
new broker's IPC, launch, cancellation, or APK integration.
