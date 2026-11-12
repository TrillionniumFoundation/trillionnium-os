# Action, cancellation and session journal contract

This nonrelease source candidate follows the frozen v56 component at
`5da3c83fe46edb2617934a92c06a10608accb68e`. Its nine production changes are six
modified Java classes and three new classes, yielding 112 Java sources. The full
source membership is bound by this component's regenerated SOURCE-MANIFEST.json.
The original build-input method must independently compute 214 production inputs
on the complete staged component; a source-map prediction is not that execution.

The inherited Android version metadata remains 56 only to keep this source
review separate from a future release decision. No new release version, APK,
signature, installation or phone qualification is established by this contract.
The model, native runtime, sampler and dependency pins remain those of the frozen
base. Source-bound evidence is recorded separately; an earlier v56 green run
cannot qualify this changed component.

## Validation boundaries

The targeted action/cancellation and session journal suites use real new pure
classes and exact extracted production methods, with explicit Android, Binder,
native and filesystem fixtures. They do not execute the Android durable writer
or prove a physical Binder/fsync stall. The Java/D8 runner binds all 112 sources,
its own bytes and four previously observed SDK/JDK files, then records actual
class and DEX output. It does not build or sign an APK. The full canonical strict
host gate and affected fixture regressions remain mandatory on the current tree.

Flight-result completion and purchase completion are unchanged and unqualified.
Calendar/form fixtures do not supply a real flight-result provider.

## Thread and node ownership

The main looper retains service lifecycle callbacks, its current graph/observation ownership, short clone handoff and callback publication. The action worker receives copied graph metadata and an owned `AccessibilityNodeInfo.obtain(original)` for the selected node. It never borrows a live currentGraph.refs node. Full readGraph/refresh/children traversal, scope/package checks, attempt-journal write and fsync, action invocation, settling and readback run on one process-wide serial action worker. Its owned graph is closed in actual finally.

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

The complete canonical strict host suite must run against this exact component. Its legacy qualification fixture assumes synchronous callbacks and needs a truthful asynchronous fixture boundary; warm-finalization extraction also needs the cancellation-ticket dependency. Preserve the first actual failures and all product assertions. The targeted 24-case action suite, 16-case session suite and 112-source Java/D8 build are separate evidence levels. They do not replace the full regression gate. Native/resource/packaging/signing qualification and actual upgrade/cold-start/disconnect/restoration remain pending for this follow-up.

No phone task may start without normal cooperative ownership, actual APK/receipt/inventory/config bytes and fresh UID/physical-display identity. Notes task A preserves all existing native/authorization/9-field context/save/list/same-item reopen gates and adds one semantically effective foreground gesture. Task B separately collects at least three effective foreground interactions across real model/action intervals plus ordinary Stop and actual drain. A cancelled B cannot count as successful Notes A.

The existing TWO-TASK-PHONE-PLAN.md is unchanged. A disappearing scrollbar is rejected: the pretask scrollable starting position and displacement of three matching content anchors must be observed. A single sampled gesture does not prove continuous responsiveness. No uncertain operation is automatically replayed, and a stuck worker continues to block new work.
