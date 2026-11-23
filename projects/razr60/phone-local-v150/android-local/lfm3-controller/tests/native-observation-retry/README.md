# Bounded native observation retry: Service lifecycle gate

Run with a complete JDK 17 and the repository's pinned JSON jar:

```sh
python3 -B tests/native-observation-retry/run_host.py \
  --source /tmp/component --output /tmp/read-retry-results \
  --java-home /path/to/jdk17 --json-jar /path/to/json-20240303.jar
```

The gate compiles the actual Service observation block, callback, admission,
retirement and complete-native-graph predicate, plus the actual stability gate,
window metadata, observation state, collection counters and cancellation types.
It reuses the original native-observation-events fixture's explicit collected
graph, Android screenshot, clock and callback endpoints. Production bodies are
extracted verbatim and independently hashed in `EXTRACTION.json`.

The fake Android Handler can hold a real read Runnable inside `post()` after
its callback was queued. The main callback therefore runs after `worker(false)`
but before that Runnable returned. The positive case requires no proof until
the actual serial executor reaches the no-read drain marker. Returning false,
throwing or rejecting that marker produces no proof. No future cancellation or
global busy flag is substituted for this return boundary.

The 40 cases also cover resource release before proof, Stop and deadline races,
actual task/Service/authorization/observation object binding, unknown events,
missing or incomplete graphs, changed package/window/display/owner/generation,
initial reads, one-use consumption, unchanged 12-second single-read budget,
both ordinary screenshot graph rechecks and terminal replacement failure.
All input and tool bytes are checked before and after execution. Original
native-observation-events, observation-diagnostics and observation-pipeline
cases remain separate required gates and are not replaced by this suite.

The Session's actual opaque pre-effect permit and Controller's durable intent,
task-wide one-use limit, original task deadline and Stop boundaries have their
own production-code gates. This suite does not create a Session action permit,
execute Android UI operations, infer model output, relax any action comparison,
verify screenshot pixels, or claim a phone/business result.

Every UI value in this directory is synthetic and portable. No phone receipts,
screenshots, private task identifiers or local device paths are test inputs.
