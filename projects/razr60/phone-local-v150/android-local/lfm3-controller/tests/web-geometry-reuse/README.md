# Same-call geometry replay and bounded failure diagnostics

This follow-up starts from controller commit `c662471c570170f42af855943224c71fc1eb960c`.
It keeps each shopping capture's locally verified, immutable own-pair result and
passes that result to the existing checked geometry overload. The same call has
already strictly parsed the exact four original DOM strings. Cross-capture DOM,
card region, accounting, native geometry, binding and ordering checks remain.
The final owned native comparison still performs its first independent complete
own-pair replay for each capture. No result is shared across tasks or receipts.

The saved four-capture replay contains one rejected pair and one accepted pair.
The rejection, accepted proof hash and every non-timing stage result must remain
identical. The recorded JVM timing comparison is a host measurement; it does not
establish an Android speedup and overlapping stages must not be added together.

A rejected protected native row can now attach one bounded diagnostic to the
existing native DOM comparison span. It contains sorted changed field names and
the two canonical row hashes, without row values or page text. The original
exception type, message, native path, fixed deadlines and rejection remain.
Diagnostic construction failure records unavailability and cannot authorize an
action. Metadata is limited to 64 fields and 4 KiB. The synthetic tests include
the actual 20-field producer namespace, including `input_sha256`.

The accompanying calendar change binds a composite day-and-price label to the
already verified literal date cell and the same native month/list. A price
annotation is label evidence only. It does not prove a flight quote or result.
The ordinary fresh-frame, target, native action and later form readback guards
remain required. No task or observation budget is extended and no action is
automatically replayed.

Run the existing observation, geometry and quote boundaries with pinned local
dependencies and a new output directory:

```sh
python3 -B tests/shopping-readonly-observation/run_host.py \
  --source . --output /tmp/hepta-shopping-new \
  --java-home "$HEPTA_JAVA_HOME" --json-jar "$HEPTA_JSON_JAR"
python3 -B tests/native-change-diagnostic/run_host.py \
  --source . --output /tmp/hepta-native-diagnostic-new \
  --java-home "$HEPTA_JAVA_HOME" --json-jar "$HEPTA_JSON_JAR"
```

The host receipt identifies the exact tested inputs and separates synthetic
native boundaries from saved phone captures. Raw phone captures, private note
bodies, device identifiers, internal host paths and signing material are not
included in this follow-up. A fresh signed Android build and real phone task
regression are required before claiming a business task completed.
