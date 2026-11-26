# Ctrip sampling form integration checks

This gate exercises the actual pre-capture observer worker and main callback,
the full raw snapshot adapter, the Ctrip comparator, the stability gate, and
capture/publication through the established synthetic Android IO fixture.

## Fixed state transition

The Gate retains the time at which it first accepted an unchanged whole-graph
key. A later complete census with that same key still advances the consecutive
read ordinal, the event endpoint, and its own main-thread acceptance time.
These clocks have different roles:

- `gateAcceptedAt` binds the actual key retained inside the Gate.
- `acceptedAt` binds the latest actual complete census and its serial read order.

A classified changed-key pair requires at least 200 ms since the latest census
acceptance and must match the Gate's real prior key and original key timestamp.
Null/stale/incomplete evidence, owner or profile changes, and event boundaries
retain their original rejection paths. The 10 s settle cap, 12 s total cap,
task deadline, and transition deadline stay fixed.

The actual scheduler regression is A at 1210 ms, identical-key A at 1420 ms,
then a valid changed-key B at 1640 ms. The upstream candidate retained ordinal 1
after the second sample and rejected the next pair as non-consecutive.
The fixed candidate retains ordinal 2 and uses Gate time 1210 ms, so the actual
pair ordinals 2 and 3 enter capture at 1640 ms.

A second scheduler case produces a 160 ms latest-pair gap. It establishes the
actual changed key as a new first sample and starts the next graph read exactly
200 ms later. Intermediate 100 ms watchdog jobs execute through the real queue;
they are not mistaken for graph reads.

## Run

```sh
python3 tests/native-ctrip-sampling-form/run_host.py \
  --source CURRENT_SOURCE \
  --fixture-baseline PINNED_0A8_SOURCE \
  --output NEW_OUTPUT_OUTSIDE_SOURCE \
  --java-home JDK17 \
  --json-jar JSON_20240303_JAR
```

The fixture baseline is the unchanged 0a8 signed source. Its Service SHA-256 is
`3208f0203a56b446a4d5f54fd26896c6a8a423bc0742e7a42b52458e42a0070c`;
its Gate SHA-256 is
`426100c4f31e825c9e0f0c556c8c89d23aa45a40593978cb5fd8d5946a4beeb8`.

The baseline is used to generate the already-protected Android IO fixture.
The complete observer section is then replaced with current production source.
The replacement is reversible, every changed production body is checked
verbatim in the compiled host, and the current comparator and Gate are compiled.
The fixture's unrelated calendar-only type boundary stays unchanged.

To run the specific regression against an upstream candidate with these test
files present, add:

```sh
--only same_key_real_scheduler --skip-existing-cases
```

## Coverage and qualification boundary

The suite retains 68 existing observer scenarios and adds 18 pre-capture
scenarios. The new scenarios cover distinct and repeated keys, actual delayed
queue scheduling, screenshot throttling, census/main clock separation,
future owned content events, unknown/untyped/window boundaries, post-read
events, owner/profile changes, protected form changes, incomplete census,
cancellation, original settle expiry, unchanged capture age, and the final
post-capture graph guard. Resource disposal is checked after every scenario.

The positive sampling cases preserve two complete 276-node raw censuses from
the existing real-geometry fixture, with explicitly synthetic host identities.
Their persisted sampling history is 344636 bytes under the existing 786432-byte
limit. Existing pre/post-encoding comparison history is separately covered.
A live approximately-280-node sampling plus pre/post-encoding history still
requires device evidence.

These are host protocol tests with synthetic Android census, window, pixel,
clock and Session permit IO. They do not assert phone execution, local model
inference, a completed flight search, or Android focus isolation.
