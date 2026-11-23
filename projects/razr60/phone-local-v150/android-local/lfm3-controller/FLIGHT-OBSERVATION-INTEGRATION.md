# Current flight observation and asynchronous control integration

This source candidate combines the installed flight observation work from
`313685edc580a750aea6301d8ff3cfd617d6fab6` with the complete asynchronous control
candidate `f519f2081b11dbbe851c2fb6528d32fffbc20c62`. Its Android metadata is
version code 59 and `0.59.0-flight-observation-action-stop-candidate`.

The four changed production inputs are `AndroidManifest.xml`,
`HeptaAccessibilityService.java`, `WebFlightNativeStability.java`, and
`WebFlightSession.java`. The complete build still has 220 production inputs,
including 118 Java sources. Existing build, assembly, identity, runtime and
host gate programs are unchanged. A new full Android build and original-key
assembly must bind these exact inputs before installation.

## Why this merge is necessary

The installed code-57 package has SHA-256
`c1e126031ff8728a3335a5ef1e6d546b3b089ca03ee73a8b3671b67b7e124ad4`.
Its signed source inventory identifies the current flight observation changes.
The earlier code-58 candidate contains the older flight session and stability
predicate and would lose those changes if installed directly. Version numbers
alone do not establish which functional changes are present.

The merge preserves every preexisting code-58 accessibility service block.
Its additions retain one original target reference and immutable native evidence,
then perform complete native observation revalidation on the owned observation
worker. The main-thread handoff only checks in-memory current identities and
copies bounded retained state. Slow native traversal, refresh, ancestor/window
reads, scope and geometry work stay on the worker.

Cancellation or a caller deadline abandons the result, while the worker keeps
independent references and the process-wide observation busy slot until its
physical exit. Late results cannot cross task, authorization, service instance,
background generation, or current-frame identities. Definitive executor
rejection releases ownership; an unknown submission outcome retains the fence
until the captured runnable really exits.

## Actual homepage failure and limited correction

Task `b350fd8665b640608093602b1e6a9f14` failed on the installed code-57 package
with `AX/DOM bracket changed; no current page capability published`.
Each original capture had equal before/after raw DOM. Across the two captures,
the existing complete homepage predicate accepts one horizontal translation of
the exact `slider4` eight-image carousel. Every other DOM record is unchanged.
The generic DOM predicate rejects that cross-capture change, preventing the
installed session from invoking its own stronger native observation proof.

The corrected session can invoke that stronger read-only proof after a generic
bracket rejection. Each capture must still be internally full-raw stable. The
existing `compareDom(first,last)` accepts only its already compiled homepage
scope. The original task binding, instance, navigation epoch, helper identity,
background selection, display, window, geometry, full native traversal, retained
node pairing, target, ancestors and live authority checks remain required.
No generic ignored-field or arbitrary stable-region rule was added.

The observation proof records its v2 schema, both original DOM hashes, and a
false all-four-raw-equal flag when appropriate. It creates no action Permit and
does not verify a business result. Publishing the new current observation clears
all prior flight-native and dispatch authorizations. Any subsequent model action
still passes the unchanged original-target and live Permit path.

## Validation scope

The following host groups executed against the reviewed source:

| Group | Result | Boundary |
| --- | --- | --- |
| Existing asynchronous action/Stop | 33 cases passed | Exact production method extraction, instrumented Android IO |
| Existing observation pipeline | 31 cases passed | Exact scheduling/ownership methods, instrumented native/screenshot IO |
| Flight observation worker ownership | 17 cases, 380 assertions passed | Exact service lifecycle/orchestration; blocked native call is an explicit host boundary |
| Existing compiled flight policy | 36 cases passed | Pure production predicates with synthetic complete trees |
| Complete observation bracket | 20 cases passed | Pure production predicate with explicit synthetic DOM/native/capture pairs |
| Session with original failed-task DOMs | 16 cases, 39 assertions passed | Exact `observe` and `sameFrame` bodies plus original DOM/geometry; private service/IPC/publisher boundaries are instrumented |

The worker cases include deadline/cancellation during a blocked native call,
late identity changes, queued-main expiry, completed-but-unclaimed results,
reference recycling, executor rejection and physical busy retirement. The
session cases include equal AX with a moving DOM carousel, generic-bracket null
publication, native refusal, absent private source, identity changes, and
unchanged-path regression. Form/date/route/price value changes, target labels,
carousel semantics and nonhorizontal geometry remain rejected.

Original failed runs were retained. The first worker run exposed a test helper
that did not accept `RejectedExecutionException`; its correction changed only
the harness. The first original-capture session run exposed a host JSON-library
difference: JSON-java `JSONObject(Map)` drops a Java-null `find_query`, whereas
the Android record contains explicit JSON null. Original fixture bytes were not
changed. The scoped session replay uses the production checked-stability
geometry overload and explicitly does not claim authenticated binding replay.

These are host results, using Java 8 syntax/bytecode targets. They do not prove
Android compilation, live native authority, native model inference, successful
shopping, successful flight results, installation, or complete phone operation.
The original flight task failed and made no flight-query dispatch. Flight result
provider completion remains a separate functional gap requiring real page
evidence and phone validation.

## Reproduction

Use the repository's unchanged original host gates and Android build entry
points. The additional focused runners accept an existing JSON-java jar and a
new output directory:

```sh
python tests/flight-observation-worker/run_worker_host.py --json-jar /path/json-20240303.jar --output /new/worker-output
python tests/flight-observation-worker/run_bracket_host.py --json-jar /path/json-20240303.jar --output /new/bracket-output
python tests/flight-observation-worker/run_session_host.py --json-jar /path/json-20240303.jar --output /new/session-output
```

`fixtures/actual-flight-r2/PROVENANCE.json` binds the two original capture files
by exact byte count and SHA-256. They contain public homepage evidence. They
cannot recreate a live service NodeRef or establish phone-native completeness.
The `reference-current57` source is an unchanged reference fixture; only its
explicit factories are reused. Its legacy test main is not executed by the
additional bracket runner.
