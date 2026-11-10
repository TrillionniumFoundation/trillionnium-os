# Code19: bounded stable observation

## Reason for this change

The observation caller already grants at most ten seconds, clipped to the task's existing absolute deadline. Code18's internal stability gate stopped collecting fresh stable evidence after two seconds. An ordinary app transition, temporary absence of the active root, or a required recheck after screenshot processing could exhaust that shorter internal window while time remained in the same observation request.

A retained Code17 LFM3 navigation case accepted its app launch and then failed during the following observation. The App's execution-state and terminal timestamps are 2,821 ms apart. This is consistent with the old settling cap; the retained evidence does not identify whether the root was absent, its full observed identity kept changing, or a screenshot/post-save mismatch required another sample. The independent final UI was collected later, so it cannot prove the earlier observation was stable. The original case and its failed verdict remain unchanged.

Evidence identities:

- Code17 case: `core-settings-home-settings-01`.
- Original action receipt SHA256: `b4767207bfc54d80594732fdf7ce1dc35adbfb42f6767c9a97c2c45334e3fc32`.
- Original task result SHA256: `fd630dd348e9fe7d62c2a6c9c1f23586feb555a1955ada4a55e367f988ccee94`.
- Frozen Code18 source manifest SHA256: `2b32fd6c47cabd3c6fe778c3ebe18cb04933c19c4bd7f8289b9569e8c61a3954`.

## Exact behavior change

`ObservationStabilityGate.SETTLE_LIMIT_MS` changes from 2,000 to 10,000 ms. The constructor still computes:

```
settleDeadline = min(saturatingAdd(started, SETTLE_LIMIT_MS), originalRequestDeadline)
```

The controller's existing `min(taskDeadline, elapsedRealtime() + 10000)` observation deadline remains unchanged. It is passed into the request once, before posting the first main-thread sample. A retry clears prior frame evidence on that same gate and never creates a new request or extends either deadline. A sample at the absolute deadline is too late.

The original service comment describing a two-second cap is updated. No other service behavior, controller code, model configuration, action protocol, executor policy, or native interface changes in this patch. Historical Code16 documentation continues to describe Code16.

## Preserved observation and cancellation requirements

Two equal complete observed frame keys must still be separated by at least 200 ms. Missing roots clear previous evidence; they are never empty successful observations. Equality still includes the active package/window, rotation and bounds, complete graph digest and truncation state. The digest still binds all existing text, focus, IME, scroll and window metadata evidence.

Screenshot spacing, the one interval-error retry, and both graph rechecks after screenshot acquisition and after PNG encoding/fsync/hash remain unchanged. Mismatched evidence must obtain a new stable pair. An old observed screenshot may already finish after the old internal two-second window if its rechecks match; that path is not the source of a new timeout allowance.

Every capture watchdog tick first checks the same request's original absolute deadline, task ownership, cancellation and lock state. Only then does it check the separate five-second screenshot callback deadline. Thus a screenshot requested nine seconds into a ten-second observation does not receive another five seconds of task authority.

Failure retires the gate, closes its captured graph, invalidates a pending capture token, and clears the active request. A late success callback checks request identity, finished state and capture token before using the result, closing its hardware buffer if stale. Normal screenshot copying also closes the hardware buffer, and any rejected local bitmap/graph is released. The controller checks cancellation and the original deadline again after its callback wait.

Android may deliver a callback later, and main-thread scheduling or synchronous screenshot encoding is not a hard real-time process. The request gates prevent a late result from becoming a new task's observation or authorizing an action. This patch does not change Android callback cancellation or claim tighter scheduling guarantees.

## Validation scope

The focused host contracts exercise:

1. All existing observed-identity components and the unchanged 200 ms matching interval.
2. A transition lasting more than two seconds, followed by a fresh stable pair before the original deadline.
3. Temporary and persistent missing roots.
4. A screenshot/post-save mismatch followed by a new stable pair after the old two-second boundary.
5. Continuously changing frames until the fixed ten-second settling cap, including a longer caller window.
6. A reset that cannot renew either the settling cap or a shorter caller deadline; exact-deadline and clock-rollback rejection.
7. A capture starting at nine seconds that remains bounded by the original ten-second caller deadline.
8. Cancellation or invalid ownership before readiness, cancellation priority at expiry, and retirement that reset cannot revive.

The unchanged Code18 gate with its original tests is retained as a baseline. Running the new transition test against the original gate must fail at the former two-second boundary. This negative control establishes that the test detects the intended behavior change.

Host test results are stored separately from the source's historical host receipts. These tests do not execute Android screenshots, model inference or phone tasks. Real Android build and ordinary offline phone regression remain necessary before claiming the navigation failure is fixed. Persistent instability may now consume more of the already-existing ten-second observation window; it still fails within that original authority.
