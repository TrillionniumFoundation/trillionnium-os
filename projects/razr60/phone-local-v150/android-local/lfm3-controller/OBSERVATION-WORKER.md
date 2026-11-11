# Observation worker and original-deadline preservation

This patch is based on the version-45 source. It does not allocate a new APK
version, install an APK, contact a phone, or claim to fix the specific cause of a
previous device failure. The recorded v43 Notes task
`816e5081a04b456aac0b2ca355d87624` ended with a screen-observation timeout after
five model decisions; its saved observation uses display 0 and no background
request. Those records do not identify whether Android node retrieval, a
transition, screenshot delivery, encoding, storage, or scheduling caused the
particular timeout.

## Confirmed source problem

Previously, the complete observation graph traversal, screenshot-buffer copy,
PNG encoding, file sync/hash and both graph rechecks ran on the service's main
looper. The screenshot watchdog ran on that same looper. A blocked graph read or
image operation could therefore delay the watchdog and cancellation callback.
The task-controller thread still had a ten-second absolute observation deadline,
but could report only a generic timeout while the UI thread remained occupied.

## Changes

The main looper remains the single owner of observation state, the stability
gate, current snapshot and callback publication. A process-wide single worker
performs only observation reads and writes of this request's private PNG
 evidence. It is separate from the existing broker-operation worker. Its busy
flag is released by the worker's actual `finally`, never by a cancellation or
clock timeout. A service replacement cannot create a second read queue around a
stalled old Binder call. Task admission and recovery-idle checks reject while
that shared worker remains busy.

The original caller deadline still covers queuing, both stable samples,
screenshot delivery, buffer copy, PNG encoding, `fsync`, hashing, final graph
checks and callback publication. No retry renews that deadline or the original
settling window. The five-second screenshot-callback deadline is also retained.
A separate main-looper observer watchdog can now retire a request while the
worker is blocked. Error messages carry the observed stage and elapsed times.
Worker checks use immutable deadline/lease identity; only main touches the
stateful stability gate.

Every graph and screenshot product has one owner. Worker samples transfer to
main only if the same request is still active. Immutable copied frame identity,
display and background generation enter the screenshot worker; no worker borrows
the main-owned captured graph's node references. Root and descendant acquisition
is covered by cleanup, with cooperative deadline/cancellation checks between
reads. Android Binder calls and `fsync` are not forcibly interrupted; their late
results can only be discarded. A stopped task cannot publish into another task,
or into a later observation of the same task.

The existing two stable samples and both complete screenshot graph rechecks
remain mandatory. A display-specific accessibility-event epoch additionally
rejects a result if a known UI event occurred between worker sampling and main
publication. On API 33 and newer, events from another display do not invalidate
the target display's observation. On API 30–32, the event has no supported display
identity API, so the fallback conservatively invalidates for any event; concurrent
main-screen use can therefore reduce background-observation liveness on those
older versions. Event absence is never a replacement for graph comparison.

Snapshot age starts at screenshot-request time, rather than when a queued result
finally publishes. This is a conservative age bound and does not claim the
request timestamp is the Android compositor's actual pixel-capture timestamp.

## Cleanup and qualification boundaries

`observation_read_worker_pending_at_terminal` independently records whether the
read worker is still active at terminal-result serialization. Existing
`cleanup_known` covers the native-inference/action/background-display cleanup
contracts; it does not assert that every Java read thread has exited. New task
admission remains blocked while a late observation worker is active and becomes
available after its real exit. This does not create a permanent recovery latch
for a read-only operation.

The worker may write only an observation's uniquely created PNG. Unpublished PNG
removal is best effort; no durable-deletion or empty-directory claim is made. It
never deletes a pre-existing file when `createNewFile` fails. Published PNGs keep
their original evidence identity. Resource lifetime and publication exclusion do
not prove all filesystem cleanup succeeded.

The action-side `performOnMain`, validation and foreground coordinate-click
paths still contain synchronous graph or image operations. This change improves
the observer chain, not all accessibility-service work. It does not change tool
permissions, display admission, background broker flags, task authorization,
model configuration, completion requirements, or the treatment of secure
screens. No phone business success is inferred from host tests.

## Focused validation

`tests/observation-pipeline/run_host_tests.py` extracts the actual production
observer and task-acquisition methods, records their source hashes and executes
them against explicit Android IO fakes. Cases cover main-loop responsiveness,
original timeout while reads/copy/encode/hash are blocked, busy-to-exited task
admission, worker/handler refusal, late screenshot ownership, repeated and retired
request identity, two graph rechecks, queued-result expiry, per-display event
fencing, and age preservation. These are synthetic concurrency/resource tests;
they do not run Android, a model or a phone.

The qualification-scope fixture also executes the real budgeted graph traversal.
Four added cases cancel after root acquisition, during child refresh, inside the
label collector and before foreground metadata. They verify reference cleanup
and that a child-label helper cannot suppress an expired read budget.

The strict host runner includes the new observer gate without removing existing
gates. Android compilation and exact candidate/device qualification remain
separate requirements.
