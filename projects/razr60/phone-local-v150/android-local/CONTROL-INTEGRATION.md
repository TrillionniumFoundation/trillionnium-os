# Standard Android local control candidate

Package: `org.trillionnium.hepta.localprobe`. Java 8; compileSdk 34, minSdk 30.
These sources add standard Accessibility control to the separate ordinary-app
candidate. They do not access the old owner-open domain, its claims, ingress,
protected files, native socket, SELinux policy, ADB, or any shell command.

## Integration ownership and API

Copy the seven Java files under `org/...` into the application's existing Java
source tree. `EngineInferenceAdapter` uses the already agreed `LocalModelEngine`
API; the remaining controller knows only the injectable `LocalInference`.

```java
HeptaAccessibilityService service = HeptaAccessibilityService.connected();
LocalTaskController controller = service.taskController(existingLocalModelEngine);
controller.start(exactOwnerInstruction, listener);
controller.stop();
controller.setListener(recreatedActivityListener); // no task replay
```

Keep one model engine in the application/session owner and obtain the single
service-owned controller through `service.taskController(engine)`. An
Application-scoped listener/session should forward state to weak Activity
listeners across Activity recreation. Do not call `start` again on rotation, process restoration,
or activity intent receipt. A rejected `start` means busy, blocked, disconnected,
or closed. `setListener` can reattach the UI to the same live session.

Before starting an ordinary task, use the normal `moveTaskToBack(true)` and a
short UI settling delay; then call `start`. Keep the standalone NPU probe path
unchanged. Dynamic status/log views should not themselves appear as targetable
Accessibility nodes while a task runs, so UI progress updates cannot invalidate
a screenshot of Hepta when the user explicitly asks to return to Hepta. Do not
hide the user's editable instruction or action buttons from Accessibility.

Listener callbacks run on the main looper, with Chinese progress strings.
`TaskResult` exposes taskId, status, summary, steps, evidenceDirectory,
finalObservation, modelReportedSuccess, and cleanupKnown. A model's `success`
becomes **`model_reported_done`**, with “模型已结束，请核对结果”; it is not represented
as independently verified goal completion. Root's device tests must verify their
own actual UI postconditions. The final package/window/rotation/tree must still
match the model's last observation. `partial`, `failed`, `cancelled`, and
`blocked` remain distinct outcomes.

## Manifest additions (application owner integrates these)

No INTERNET permission is required or supplied. Do not add an exported action
receiver. Keep any approved one-shot debug nonce/file trigger private to the app
and separate from the normal owner-input path.

The system binds the service through the Android BIND_ACCESSIBILITY_SERVICE
permission; the user enables it through normal Accessibility settings:

```xml
<service android:name=".HeptaAccessibilityService"
    android:permission="android.permission.BIND_ACCESSIBILITY_SERVICE"
    android:exported="true">
  <intent-filter>
    <action android:name="android.accessibilityservice.AccessibilityService" />
  </intent-filter>
  <meta-data android:name="android.accessibilityservice"
      android:resource="@xml/hepta_accessibility_service" />
</service>
```

Copy `res/xml/hepta_accessibility_service.xml`. Add this disclosure string:

```xml
<string name="hepta_accessibility_description">根据你输入的任务，在本机读取当前画面并执行点击、文字输入、滚动和返回。模型在手机本地运行，可随时在Hepta停止。不会自动重做旧任务。</string>
```

Use a normal `Settings.ACTION_ACCESSIBILITY_SETTINGS` activity for enabling the
service. Installed launcher-app discovery needs the matching package-visibility
query rather than broad package access:

```xml
<queries>
  <intent>
    <action android:name="android.intent.action.MAIN" />
    <category android:name="android.intent.category.LAUNCHER" />
  </intent>
</queries>
```

## Effect and observation contract

The service captures the original-size display image and a bounded active-window
node graph. Each observation has a fresh 32-hex ID, package/window/rotation,
geometry, screenshot SHA, tree SHA, and explicit truncation information. Full
observations used by the controller are saved in private task evidence; prompt
projection is independently labelled and does not rewrite the original task.

Actions are only open/click/type/scroll/back/home/wait/done. Open requires an
installed launcher entry. It alone admits unchanged window/package/rotation/geometry
without requiring an identical full tree; opening the current package is rejected
before dispatch. Node actions require the same observation, package,
window, visible/enabled node, and unchanged target identity. Password nodes are
rejected. Unicode text input uses ACTION_SET_TEXT and must read back exactly.
Coordinate clicks use 0..1000 normalized integers, remain in the observed active
window, and require a new screenshot with identical target pixels immediately
before dispatch. No arbitrary command, URI, package install, network fallback,
or external model operation exists in this control layer.

Every accepted action is followed by another observation before planning. There
is one active service lease, 20 steps, an eight-minute task budget, a 55-second
model request budget, at most one format correction per step and two per task,
and at most two stale-screen replans. Invalid JSON never executes. An action
that may have partially occurred is not automatically retried. Repeated effects
without a confirmed tree change are stopped. `stop` cancels the owned inference
handle and prevents the next effect; an already dispatched action cannot be
undone. Unknown inference/gesture termination blocks a new task.

Screenshot callbacks use a serial token and five-second watchdog. Late callbacks
close their buffers and do not replace a newer task's snapshot. Lock screens and
Android-protected screenshots are refused; there is no bypass.

## 4096-context admission

`ConservativeTokenBudget` pins the reviewed Qwen tokenizer SHA and labels its
result **an upper bound, not exact tokens**. For each actual system/prompt string,
it takes the larger of raw UTF-8 and NFC-normalized UTF-8 byte counts, without
normalizing or changing the bytes sent to the model. This is a conservative
byte-level BPE bound for that reviewed tokenizer. It then adds a 192-token
formatter margin (the reviewed formatter has 80 literal UTF-8 bytes), 256 image
tokens, two vision boundaries, one BOS token, 256 generation tokens, and 256
reserved tokens. Total must not exceed 4096.

When necessary the prompt omits explicitly counted low-priority nodes, unused
apps, and old result summaries. It prioritizes owner-matched labels and action
nodes. The screenshot stays at original size, and the owner's complete original
instruction remains the final prompt segment. If even the required minimum
cannot fit, the task is rejected without truncating the instruction. Each model
request saves the actual bound and projection counts. Reserved processor image
markers cannot be supplied as an instruction; markup in untrusted JSON data is
escaped before formatting.

## Validation and remaining qualification

The revision-5 strict parser's pure Java 8 suite passed 41 accepting cases, 548 rejecting
cases, and 142 field assertions. The conservative-budget suite passed 11
assertions including raw/NFC expansion, exact boundary and overflow, CJK/emoji,
reserved markers, and rejection of a foreign tokenizer. These are host checks.
They do not establish Android framework compilation or device operation.

The application owner must compile the complete app against SDK 34, verify the
ordinary app UID can actually load the NPU bundle, enable Accessibility normally,
and run real-app cases and stop/restart checks. This source delivery makes no
phone-operation or end-to-end success claim on its own.

Official API references consulted:
- https://developer.android.com/reference/android/accessibilityservice/AccessibilityService
- https://developer.android.com/reference/android/view/accessibility/AccessibilityNodeInfo
- https://developer.android.com/reference/android/view/accessibility/AccessibilityNodeInfo.AccessibilityAction
