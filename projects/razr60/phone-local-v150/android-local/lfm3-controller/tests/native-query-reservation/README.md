# Native query reservation regression

This gate exercises the real NativeAppSession, native Ctrip year round-trip parser, ActionExecutionState, and the Controller's verbatim nativeQueryExecution projection.

A query reservation is released only after a durable, same-attempt outcome proves a definite stale rejection before effect entry, a physically drained worker, and a published callback with current authority. The prior private guard, observation and model run remain consumed. A newly captured observation and a new model decision are required. API entry, ambiguous completion, missing fields, changed identity, retired callbacks, missing journal durability and expired work never refund a reservation.

All new published inputs are portable synthetic host fixtures. The lifetime cases generate their own task, run, observation, clock and private-history facts using the real host Session and ActionExecutionState. The JSON round trip explicitly preserves nullable lifecycle fields with JSONObject.NULL. Five present non-object guard types must make the real Controller projection unavailable; an absent guard remains distinct, and cannot release a guarded query. No captured phone receipt, device identifier, private path or raw device provenance is included.

The neighbouring native-action-integration gate retains its original 76-case pure comparator matrix and all 49 integration cases. It adds complete synthetic two-tree tests using the hand-authored geometry and horizontal action lists in fixtures/synthetic-carousel.json. The production comparator still requires the actual complete census and rejects omissions, target/form/ancestor/role/window changes and overlapping or sensitive branches.

Run with the same pinned full JDK17 and json-20240303.jar used by the other native gates:

    python3 tests/native-query-reservation/run_host.py --source . --output /absolute/new/output --java-home /absolute/jdk17 --json-jar /absolute/json-20240303.jar

Optional --previous-source /absolute/baseline/component recompiles the pinned original Session and comparator against the same synthetic behavioral regressions. Optional --previous-projection-source /absolute/prior/component extracts the pinned prior Controller method and compiles it with the current real Session. Each requested original execution must really fail with exit code 1 at its recorded behavioral assertion. Raw compile/test stdout, stderr and exit codes are retained. These comparison sources are caller-supplied local evidence and are not part of the published fixtures. The default CI gate runs the current candidate only.

No phone, ADB, Android platform effect, model, SDK, external network or business task is executed. RESULT.json binds all source files and the five tool inputs before/after, compiler inputs, generated Java, original streams, extraction identity and CASES.json.
