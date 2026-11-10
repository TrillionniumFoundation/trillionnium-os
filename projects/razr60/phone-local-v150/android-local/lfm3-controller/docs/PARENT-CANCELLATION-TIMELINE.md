# Parent cancellation and exit observations

The additive `parent_process_timeline` object in
`hepta.local-model.task-session.v1` records Java parent lifecycle observations for
one warm task. It does not change cancellation, waiting, termination, receipt
acceptance, process ownership, or terminal success rules.

The timeline is created before the warm task is published and before its lazy
worker launch. The task owner, request handles, session, and fallback cleanup
share that object. Its `worker_generation` and `task_id` must match the session;
a mismatched timeline is rejected before a session reader is started.

## Clock and fields

The object has schema `hepta.parent-process-timeline.v1`. All event times are
`elapsed_ns`, in nanoseconds from `parent_warm_task_timeline_creation`, measured
with `System.nanoTime`. `clock_scope` is `same_parent_process_only`. These offsets
are not wall-clock times and cannot be compared with native clocks, another app
process, or another task's independently created origin.

Each non-null event contains `elapsed_ns`, a first-event `sequence`, and a
`source`. `first_exit_observed` also contains the real observed `exit_code`.
`sequence` orders first recorded event kinds under the shared recorder's lock;
it is not a native execution or signal-delivery sequence.

| Field | Observation |
| --- | --- |
| `first_cancel_requested` | First entry into an existing handle/session cancellation path. |
| `first_destroy_invoked` | First parent `Process.destroy()` invocation boundary. |
| `first_destroy_forcibly_invoked` | First parent `Process.destroyForcibly()` invocation boundary. |
| `first_exit_observed` | First existing parent exit-value path, after its corresponding wait or liveness check. |
| `destroy_invocation_count` | Number of existing `destroy()` invocations recorded by this snapshot. |
| `destroy_forcibly_invocation_count` | Number of existing force invocations recorded by this snapshot. |
| `snapshot_elapsed_ns` | Time of this immutable snapshot relative to its origin. |

Absent events are JSON `null`; cancellation before process launch therefore has
a cancel event and no destroy event. Healthy graceful close has an exit event
and no cancellation or destroy events. A process whose exit is not observed
keeps the exit event null. Repeated calls retain the first event and increment
invocation counts where the existing code actually calls the Process API.

The instrumentation preserves existing duplicate invocations. For example, a
request handle cancels its owner and can then invoke destroy itself; session
cancellation can be followed by another destroy in termination. This patch
neither adds a retry nor deduplicates existing calls.

## Sources and interpretation

Cancellation sources distinguish `request_handle_cancel`, `owner_handle_cancel`,
`session_cancel`, `request_deadline`, `request_failure`, `close_write_failure`,
and `non_graceful_close`.

Destroy sources additionally distinguish `close_wait_expired`, `termination`,
`fallback_close`, and `engine_failure`. Force escalation uses
`force_wait_expired`. Exit observations identify the existing observation path:
`request_wait`, `graceful_close_wait`, `termination_wait`, `fallback_wait`,
`engine_wait`, or `engine_exit_value`.

These sources describe the parent path, not the child's exit cause. An ordinary
close that exhausts its wait can invoke destroy while
`first_cancel_requested` remains null. No new cancel flag is synthesized.

A destroy event is recorded immediately before invoking the Java Process
method; a thread can be descheduled between that record and the call. The
event does not prove that the method returned, a kernel signal was delivered,
or the child was alive when the kernel handled it. The explicit
`signal_delivery_proven` flag is false. A count is an attempted invocation
count, not a count of delivered signals.

An exit observation can occur after a destroy invocation even when the child
already exited before the call. The explicit `exit_cause_inferred` flag is
false. Parent ordering can help investigate a native `0x2e`/exit-134 result, but
it alone cannot establish whether a signal, DSP fault, or another condition
caused that native failure. Native log timestamps must have a demonstrably
compatible clock before cross-log time comparisons are made.

The receipt contains a snapshot. Concurrent late cancellation calls after the
snapshot are not retroactively included in the create-only persisted receipt.
No additional waits, synchronization of termination calls, or publication
changes were introduced to force such calls into the snapshot.

## Compatibility and verification

Existing v1 receipt consumers select required fields rather than reject
unknown keys, so the object is additive. It is diagnostic only: no legacy
receipt is rejected for lacking it, and it cannot turn a canceled, forced,
unknown-exit, nonzero-exit, or invalid-native-receipt run into an accepted run.

`WarmProcessTimelineHostTest` exercises the production `WarmProcessSession`
using real Java subprocesses for healthy close, request deadline, close
deadline, and an already-exited child; controlled Process implementations cover
repeated cancellation, force escalation, and unobserved termination. It asserts
the baseline Process invocation counts and retained terminal results.

`test_warm_handle_timeline.py` compiles the exact production `RunHandle` body,
rather than a rewritten model of it, and exercises owner/request propagation,
first-wins recording, prelaunch cancellation, an already-dead child, and the
unchanged one-shot path. `test_warm_receipts.py` checks additive compatibility
and that diagnostic data never bypasses existing acceptance gates.

These are host checks with synthetic protocol peers. They do not test Android
signal delivery, Hexagon/DSP behavior, a model, phone actions, or model quality.
The Android candidate and phone tests must retain their separate evidence.
