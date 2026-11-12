# Scoped Web and asynchronous control integration contract

This unqualified v57 candidate integrates the action/Stop/session work from
`0b9e0031d2e137d6823668946d48e8154b339787` with the installed scoped Web source
`dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e`. The actual common ancestor is
`42d3a0f447807659c0f78c8273edee01dd1b734f`. File selection follows that ancestor;
version numbers and file sizes are not used to choose behavior.

The integration retains the original candidate's existing files, brings in the
29 fresh source/test paths and resolves the eight overlapping paths. Additional
necessary fixture adaptations preserve their original semantic assertions.
The 164 fresh historical host-evidence paths stay at their original immutable
source; they are not newly copied into this component. The complete regenerated
SOURCE-MANIFEST.json binds every actual file in this integrated component.

Android version 57 / `0.57.0-off-main-action-stop-candidate` identifies this
candidate. It does not establish an APK, original signature, installation,
phone acceptance or production release. Model/native/sampler pins remain fixed.

## Validation boundaries

The original 112-source compilation and prior targeted receipts are historical
evidence for the preceding implementation. This integration has 117 Java sources
and must pass a new complete Android/native/resource/APK build and canonical host
regression against its exact 219 production inputs. Host fixture boundaries are
explicit; they do not establish Android Binder/fsync behavior or phone operation.
The unchanged 105-check runner is retained with the fresh Web query and other
source/test extensions. Actual result counts belong to source-bound receipts.

The selected action node, the bounded scoped-Web role nodes and WebView node use
owned copies for worker-side validation. Original task, observation, authorization,
display-generation and absolute action-deadline checks remain before the effect.
Worker code must not borrow the mutable current observation graph.

Flight result completion and purchase completion remain unqualified. The current
scoped flight source still lacks actual same-record flight-result completion;
public product price evidence is not order/payment completion.

## Thread and node ownership

The main looper retains service lifecycle callbacks, its current graph/observation ownership, short clone handoff and callback publication. The action worker receives copied graph metadata and an owned `AccessibilityNodeInfo.obtain(original)` for the selected node. Scoped Web native-region validation also receives bounded independently owned copies of the required role nodes and WebView node. The handoff never borrows live currentGraph.refs nodes. Worker-side refresh, parent/child reads and validation keep the original absolute deadline. Full readGraph/refresh/children traversal, scope/package checks, attempt-journal write and fsync, action invocation, settling and readback run on one process-wide serial action worker. Its owned graph is closed in actual finally.

Target app View work still uses that app's own main thread. A caller-side worker does not guarantee target app or Binder latency. Existing foreground coordinate/gesture and unrestricted negative-window paths retain their legacy behavior and are not claimed as repaired; background paths cannot fall back through those exceptions. Initial background creation remains on the existing controller worker.

A separate process-wide native cancellation queue handles the exact captured task/handle. It is independent of the action and controller workers. Signal return, cancellation-worker drain, native process exit and model cleanup receipt remain different facts. An ordinary Stop never waits for a stuck action journal, native signal, or worker drain.

## Process admission and lock order

The native cancellation queue and LocalModelEngine share one short admission monitor. Exact old-handle capture and cancellation reservation are atomic with process/start/warm/external/recovery reservation and Service task-lease admission. Task tickets and independent diagnostic run tickets have different identity fields. No fallback looks up a new engine handle or replacement service.

Normal queue reservation order is admission → Ticket → Work. Service acquire uses Service → admission; its fresh filesystem check occurs outside admission. Worker signal calls run after releasing Ticket/Work/admission locks and use only the captured object. Worker lease predicates read short volatile/atomic identity values; they do not acquire Service or Controller. Ordinary Stop briefly takes Controller → handleLock, releases those before normal queueing, and performs native calls on the separate worker. The package-private stopIfTask keeps the Controller monitor across an exact-task check and nonblocking Stop, which does not invoke native IO. No worker drain wait occurs under these UI locks.

Legacy Controller.start and recovery owner acknowledgement retain existing synchronous checks. The current patch does not assert a general all-thread proof for every legacy API. Its tested ordinary Stop chain is MainActivity → LocalTaskSession → captured Controller/task cancellation → refresh(false) with cached eligibility getters. Full model-file inspection remains in explicit/full refresh paths; recovery/startup retain separately documented synchronous IO.

## Deadline, effect and cleanup rules

The original action deadline is never restarted by main posting, queue delay, graph reads, fsync, settling or publication. Legacy perform overloads retain their original default budget. Bound BackgroundSession requests cap the original four-second budget with the action deadline, recheck cancellation/generation/deadline after connect and immediately before the first byte, and tighten each read timeout to remaining time. Legacy bootstrap/state/close requests keep their old budget.

Connect and Binder calls are not claimed to be interruptible. A passed deadline retires authority while actual worker lifetime continues. Once a broker write is attempted, an absent acknowledgement is unknown and is never resent. Scope, authorization, package/window/node, observed label, IME and fixed-intent checks remain before effect, with deadline/generation rechecks after blocking work. Original durable attempt semantics are retained.

The action slot and native cancellation slot remain occupied until actual finally. Cleanup acknowledgement after native cancellation entered cannot erase the active worker. Definitive executor rejection proves unstarted work; other submission exceptions retain unknown/pending state, do not retry and do not throw through Stop. Drained-but-unpublished callbacks can be revoked; an already accepted original receipt is not rewritten by a late Stop.

## Session journal and ordinary UI

Ordinary Session callbacks capture immutable bytes on main, then use one serial journal worker shared with the existing recovery executor. A pending reservation must read current private background/web leases and finish the real write before its matching epoch/service acknowledgement can schedule Start. Stop immediately retires a pending epoch; later successful persistence cannot revive it.

The bounded queue retains outstanding work through actual writer exit and UI acknowledgement. Write/submit/ack failure immediately sets a volatile blocked barrier and invokes the exact old controller/task failure hook outside the queue lock. A late callback cannot look up and cancel a replacement task. Saturation at 64 preserves existing jobs and blocks admission. Explicit verified recovery is required to clear failure; no old success callback clears it.

The UI lease cache is display/eligibility state only. Workers re-read leases before real task/recovery admission, and Controller.start still performs its original independent check. Startup initializes the cache; ordinary writes and reconciliation refresh it. `refresh(false)` does not probe the model file.

The Android writer does not trust AtomicFile.finishWrite's normal return as durability proof: it performs explicit file-descriptor sync, checks exact readback bytes plus no .new/.bak sidecars and file type/UID/link/mode/size, then syncs the owned parent directory before allowing pending Start. This Android writer is statically reviewed, not executed by JVM fixtures. Startup recovery, installAcknowledgedSession and recoveryLeaseRetained retain their original synchronous boundaries and are outside the ordinary Stop claim.

## Diagnostic evidence

ActionExecutionState samples an injected monotonic clock inside synchronized transitions, validates before mutation and never clamps regressions. Phase/marker vocabulary is finite. Bounded private diagnostics contain only IDs, fixed phases and monotonic times, not added instruction/page text. At most 64 rows are retained; truncation is explicit and complete_phase_coverage remains false. Diagnostics do not enter model prompt/history/tool text.

A cancelled task, a returned cancellation signal and a cleanup proof cannot be substituted for each other. “已请求停止任务” is an acknowledgement, never a phone Stop/drain pass.

## Official Android source basis

All Android implementation references below are exact AOSP Android 16 commit `99b01a65cc4c104933788b3143285ab6bae65827`, resolved from android-16.0.0_r1.

| Official source | Git blob | Basis |
| --- | --- | --- |
| [AccessibilityInteractionClient.java](https://github.com/aosp-mirror/platform_frameworks_base/blob/99b01a65cc4c104933788b3143285ab6bae65827/core/java/android/view/accessibility/AccessibilityInteractionClient.java) | bdfc236d82e09a546519521c3e034b5461ec31e0 | Client keyed by calling thread; query/action waits belong to that caller. |
| [AccessibilityNodeInfo.java](https://github.com/aosp-mirror/platform_frameworks_base/blob/99b01a65cc4c104933788b3143285ab6bae65827/core/java/android/view/accessibility/AccessibilityNodeInfo.java) | ede0b3cf8cce4ceda0e7454ad259c1376d26f5d8 | refresh mutates node and can fail for obsolete nodes; obtain creates handoff ownership. |
| [AccessibilityService.java](https://github.com/aosp-mirror/platform_frameworks_base/blob/99b01a65cc4c104933788b3143285ab6bae65827/core/java/android/accessibilityservice/AccessibilityService.java) | 19ffc17f6a94621c50cba7754a67909acfacc7bc | Service callbacks use main executor; global/root Binder paths and explicit callback executors are separate. |
| [ContextImpl.java](https://github.com/aosp-mirror/platform_frameworks_base/blob/99b01a65cc4c104933788b3143285ab6bae65827/core/java/android/app/ContextImpl.java) | 99a2763650cd2e94df0209046cca254d63b372c7 | Service activity start retains NEW_TASK; this Binder path has no caller-main-looper check. |
| [AtomicFile.java](https://github.com/aosp-mirror/platform_frameworks_base/blob/99b01a65cc4c104933788b3143285ab6bae65827/core/java/android/util/AtomicFile.java) | 36800eac254d79cfce7f52604029024f1c6e8649 | finishWrite logs some sync/close/rename failures instead of throwing, requiring explicit commit checks. |

These sources justify the implementation design, not Motorola runtime response or successful app operations.

## Remaining required gates

The complete canonical strict host suite must run against this exact component. Legacy fixtures must represent asynchronous callbacks and captured cancellation faithfully, using the actual production queue and extracted methods where those boundaries are exercised. Preserve the first actual failures and all product assertions. The background-client and warm-finalization fixtures include the captured task/ticket and a bounded wait for actual cancellation-worker drain; the socket lifecycle assertion includes the pre-write deadline update. The qualification fixture uses actual action/cancellation/session helpers with explicit host IO boundaries and waits for real worker completion before its original semantic assertions. Test barriers do not make production Stop synchronous or release production slots artificially. The original 24-case action suite, its six added scoped-Web ownership cases, the 16-case session suite and complete Android build are separate evidence levels. The earlier 112-source Java/D8 receipt is historical; this integration requires a new 117-source build. These targeted levels do not replace the full regression gate. Native/resource/packaging/signing qualification and actual upgrade/cold-start/disconnect/restoration remain pending for this follow-up.

No phone task may start without normal cooperative ownership, actual APK/receipt/inventory/config bytes and fresh UID/physical-display identity. Notes task A preserves all existing native/authorization/9-field context/save/list/same-item reopen gates and adds one semantically effective foreground gesture. Task B separately collects at least three effective foreground interactions across real model/action intervals plus ordinary Stop and actual drain. A cancelled B cannot count as successful Notes A.

The existing TWO-TASK-PHONE-PLAN.md is unchanged. A disappearing scrollbar is rejected: the pretask scrollable starting position and displacement of three matching content anchors must be observed. A single sampled gesture does not prove continuous responsiveness. No uncertain operation is automatically replayed, and a stuck worker continues to block new work.
