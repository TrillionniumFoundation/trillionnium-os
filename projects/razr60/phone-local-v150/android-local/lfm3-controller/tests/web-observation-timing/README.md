# Task-local web observation timing

The shared Flight-named observer is also used by shopping. A retained shopping failure ended before the first model action, after its final authenticated capture had returned. Existing evidence could not distinguish queue delay, repeated DOM checking, live native traversal, or final identity checks.

This change records bounded task-local timing spans for those phases. It preserves the original deadlines, authority checks, DOM/native comparison rules, main display protection, and slot/NodeRef cleanup. `WebObservationTiming` records only fixed phase labels, clocks, booleans and exception class names. It records no page text or exception messages. The controller writes `web-observation-timing-<trace>.json` to the existing task evidence directory in `finally`; a diagnostic write failure does not replace the original ordinary outcome. A pending phase is explicitly not proof that native work drained.

## Validation

The existing exact-method worker fixture now includes four additional timing regressions. It passes all 21 cases (476 assertions), while the exact R22 baseline passes the original 17 cases then fails the new missing-main-queue-timing assertion. Existing real-capture Flight session replay passes 16 cases; shopping retry keeps the legacy 1, previous-budget 1, and current 30 cases. See `HOST-VALIDATION.json` for sanitized results and source digests. Android compilation and phone acceptance remain separate gates.

Run the existing `tests/flight-observation-worker/run_worker_host.py` and `run_session_host.py` with a fresh `--output` and pinned `--json-jar`. Run `tests/shopping-observation-retry/run_host.py` with those arguments plus `--java-home`. The fixtures are explicit host carriers, not Android runtime or live native authority.

## Retained capture performance replay

`CaptureDomReplay.java` accepts the private directory containing the exact four retained `raw-*.json` capture envelopes and an output JSON path. Compile it against the existing query/session host class closure. As in the existing shopping host gate, host execution requires the Android `JSONObject(Map)` explicit-null retention adapter in `WebTaskPurpose`; no production validator or captured input is changed. The private originals are intentionally absent from this repository.

The first original pair remains rejected. The retry pair is accepted in all four rounds with identical pure proof hashes. On the host, eligibility plus the repeated independent capture validation took 4.66–5.75 seconds. This is not a phone timing claim. No cached proof reuse is implemented; any later reuse must remain task-bound, exact-byte/digest-bound, and independent of the live native checks.
