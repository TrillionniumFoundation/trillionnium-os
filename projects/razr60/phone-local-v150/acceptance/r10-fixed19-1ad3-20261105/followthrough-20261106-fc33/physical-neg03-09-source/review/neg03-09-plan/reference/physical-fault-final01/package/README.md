# Physical NEG04 / NEG05 / NEG07 — source candidate

This package supplies a one-Send Root coordinator, the existing single-pidfd
fault actor bridge, original phone and P4 collectors, an independent host
closer, and a read-only final-result audit. It is a **source candidate**.
Every `FINAL_DEPENDENCIES` is `None` until the source-only freezer reads and
binds the actual completed policy/runtime/consumer/readiness/fault cascade.
No physical case has been run by this package in this delivery.

The source manifest is `SOURCE-MANIFEST.json`. Its `files` list contains the
exact runtime sources, immutable reference sources, and portable tests. Files
under `validation/operator-source-fixture` are explicitly old, immutable
source fixtures used only by local interface tests. The live watcher receives
the eight sources from the **actual finalized fault manifest** supplied in the
freeze input. It never uses those test fixtures as a live runtime.

## Contract and authority

The whitelist is `NEG-04`, `NEG-05`, `NEG-07`. The original protocol is
37,318 bytes / `c573959e59fd9fbe7a850d6d2d6d747e3135718493f15de4a8acde850bad93b0`.
These three cases each require `host_isolated` and `physical_native_task`.
This package only closes the latter. Its final result keeps
`host_isolated_not_inferred=true` and `whole_case_pass=false`.

The separate host-five run has already been performed and retained by Root.
The CPU cancellation NEG08/NEG09 closer and its whitelist are unchanged.
No positive acceptance materializer or positive closer is broadened.

| Case | Existing actor action | Required physical evidence |
| --- | --- | --- |
| NEG-04 | One TERM to the held original carrier pidfd before any dispatch | Actual admission, zero original tool calls/results, consumed claim, native/provider failure, bounded original model cleanup when a model request exists, preserved draft restoration |
| NEG-05 | One TERM to that carrier after the first disposable probe effect | One original `phone.open_app`, fresh independent public page/viewport read, original running worker/transport ownership at injection, no provider result consumed, later original sidecar terminal/cleanup, no second effect |
| NEG-07 | One STOP to the exact r6 worker pidfd | One original call, original `timed_out` result, before-late terminal/input/output/claim copies, durable pending-receipt bookend, later original cleanup receipt, unchanged four original files, no second dispatch or success upgrade |

The original actor is 32,953 bytes / `cd5100c0f12dc77b275a55893aa31fdc7d6b5ec61839635b70c0c9a11f0cbb1e`.
The original sender is 40,788 bytes / `5ab04019e94adb989e9909ae3a9aa10db0689de62821ec549db8beb3ec4d0281`.
The P4 phone actor is 5,652 bytes / `179a3a57ad8859a256f7e244e34171e9dd90544012928d65405efd22c8a74b22`.
The owned capture is the unchanged 29,065-byte standalone extraction
`f12a251542894d0e8c0dedc9d62eb96d4f39e2b1d563f849c2f60e6ee02580e3` from repaired0374.

Root remains the sole phone/remote operator. Freezing, plan preparation and
the two validation scripts below perform no phone operation or native Send.
`run_physical_fault_once.py --execute-once` is the only Root effect entry.

## Exact host workflow

Set `B` to the existing stock16 HEPTA Root work directory, `CANDIDATE` to this
staged candidate package and `CANDIDATE_SHA` to the delivery's explicit
source-manifest SHA. These are task variables; they do not replace any system
home or configuration variable.

### 1. Freeze the actual source relationships

Fill `FREEZE-INPUT.template.json` from actual retained descriptors. The actual
adoption must already have been independently verified. The freezer checks
the exact `adoption.v1` / `decision.v1` relationships, original linked reports,
44 permission atoms, R8 runtime32 manifest, source consumer/readiness pins,
and the actual exported policy. It does not award policy adoption itself.

The output must be a new direct child of `B` named
`physical-fault-r10-r1-final-<tag>`. Existing output directories are rejected.

```text
/usr/bin/python3 -I -B CANDIDATE/source/freeze_physical_fault.py \
  --source-manifest-sha256 CANDIDATE_SHA \
  --inputs ACTUAL_FREEZE_INPUT.json --inputs-sha256 ACTUAL_FREEZE_INPUT_SHA \
  --freeze-source-only
```

The result provides the new exact source-manifest descriptor. The freezer
changes only one `FINAL_DEPENDENCIES` RHS in each of four files, and proves a
whole-byte inverse to the candidate. All other candidate bytes remain
unchanged. The current fault package's seven non-active members remain exact;
its shared active source must reverse to its original bytes by changing only
the four existing consumer/readiness/policy/adoption pin RHS values.

Use the returned frozen package and SHA for every subsequent step.

### 2. Prepare one newly registered normal request

`PREPARE-INPUT.template.json` requires exact retained originals for:

- the fresh registered UTF-8 request and original v150.3 task template;
- current original transport-only READY;
- the unchanged sender's previous selection, nonempty preserved draft,
  retirement resolution, and successful unconsumed-registration readback;
- the exact shared configuration and service-input originals.

Use a new registration/nonce for each case. Preparation derives its nonce
from the original task template; it never invents a replacement identity or
rewrites the owner's text. For NEG04, `expected_probe_component` must be null.
For NEG05/NEG07 it must be one of the original actor's two canonical probe
components and belong to the registered app scope. The existing pure page
projection normalizes `.Activity` spelling for this comparison while the raw
registered app-scope bytes remain unchanged.

The existing `b25125bc...` materializer can create normal `visual` request
material with the explicit `视觉挑战` allowed-app subset. Its actual sealed
release/build SHA and selected session/profile are required. Keep its
`REGISTRATION-ARGV.json` and use the existing sealed registration helper once.
Read back the actual template bytes and registration result. A materializer
case label is not a positive case result: the fault case obtains its separate
qualification solely from this package's actual negative originals.

```text
/usr/bin/python3 -I -B FROZEN/source/prepare_physical_fault.py \
  --source-manifest-sha256 FROZEN_SHA \
  --inputs ACTUAL_PREPARE_INPUT.json --inputs-sha256 ACTUAL_PREPARE_INPUT_SHA \
  --prepare-host-only
```

Preparation writes a new `B/physical-fault-plans-r10-r1/<label>/` directory,
including `WATCH-PLAN.json`, `ROOT-PLAN.json` and `PREPARE-RESULT.json`.
`PREPARE-RESULT.execute_argv` is the exact effect-entry argv. It also reports
the actual plan's static-stage and watch wire sizes before any phone actor
starts. It does not register, Send, run a model, query the phone or signal.

### 3. Execute that exact plan once

Run the generated `execute_argv` once. It has this form:

```text
/usr/bin/python3 -I -B FROZEN/source/run_physical_fault_once.py \
  --source-manifest-sha256 FROZEN_SHA \
  --plan B/physical-fault-plans-r10-r1/LABEL/ROOT-PLAN.json \
  --plan-sha256 ROOT_PLAN_SHA --execute-once
```

Root output is `B/physical-faults-r10-r1/<label>/`. P4 source/phase output is
`/home/alex/codex-physical-faults-r10-r1/<nonce>/`. Phone evidence is private
under the existing GNU base:

```text
fault-source-bundles-r10-r1/<nonce>/
fault-watch-r10-r1/<owner_request_sha256>/
fault-injections-r10-r1/<owner_request_sha256>/
fault-original-captures-r10-r1/<nonce>/
```

The static operator-source stage creates only a new private source-bundle
original; it does not modify installed production files or dispatch a task.
The long watch then runs in the foreground of its original phone shell. Its
owned P4/Root pipe captures continuously drain while Root prepares and starts
the sender. The existing route helper uses independent sockets on this path;
the package does not detach a background phone process or take over an ADB
lifecycle.

After the watch is armed, the unchanged sender performs its source preview,
one Send, original native-terminal observation, and original draft restore.
The watch calls the unchanged signal actor only once after the eligible
original phase has been freshly observed. A missed phase is retained as a
failure. Actor preflight failures do not cause another invocation.

### 4. Audit the completed final originals without effects

The standalone verifier first produces
`PHYSICAL_FAULT_ORIGINALS_VERIFIED_PENDING_ROOT_VERIFIER_JOIN`, with
`physical_case_pass=false`. Root may publish its physical result only after
that actual verifier child joins with both pipe EOFs and the original capture
deadline still valid. `ROOT-RESULT.json` binds that actual child and sidecar.

For an independent read-only final audit, use the actual execution descriptor
and hash retained at `EXECUTION.original.json`:

```text
/usr/bin/python3 -I -B FROZEN/source/verify_fault_once.py \
  --source-manifest-sha256 FROZEN_SHA \
  --plan OUT/ROOT-PLAN.original.json --plan-sha256 ROOT_PLAN_SHA \
  --execution OUT/EXECUTION.original.json --execution-sha256 EXECUTION_SHA \
  --out OUT/closure --audit-final-originals-only
```

This recomputes the exact closure bytes, checks `ROOT-RESULT.json` against the
actual independently owned verifier capture, and performs no phone access or
new output write. The final physical result still does not infer the separate
host layer or whole-case qualification.

## Bounds and completeness

| Boundary | Preserved limit |
| --- | --- |
| ADB command wire | strictly less than65,536 bytes |
| Phone packed-source expansion | 262,144 bytes |
| P4 phase packet | 131,072 bytes |
| Source package | 32 MiB, at most128 manifest members |
| Capture stdout/stderr | 64 MiB per stream, explicit refusal above cap |
| Watch | one original240-second deadline;140-second eligibility window;30-second actor; at most90-second follow-up, all clamped to the original watch deadline |
| Native request | original300-second Send-to-terminal limit;7 tool calls /8 model rounds remain unchanged |
| Phone archive | original50-second capture +15-second finalization;64 MiB retained/archive,128 MiB native scan,2,048 files |
| P4 sender collector | original60-second collection; complete flat sender-directory census |
| Root host collection |1,200 seconds, including final owned verifier; this is not an extension of the native300-second request deadline |

Every Root and P4 phase requires its actual original child, both EOFs,
original execution deadline, complete output hashes, and created-inode bound
capture sidecar. Successful transport `RESULT.json` keeps its original seven
fields; `OUTPUT-CAPTURE.json` is separate. The independent verifier checks the
exact complete phase set, including all512 KiB phone and P4 archive chunks.
It also checks the unchanged phone actor's raw stdout against its retained
wrapper hash, original intent/request and original boot/ADB/Enforcing baseline.

The closer consumes complete provider files, original native WAL segments and
their selected locations, full global ledger prefix, original r6 action/client
receipts, current15-source seal, model request/cleanup producer originals,
selected-state checksum/CAS and no-pending bookends, registration/template and
app scope, sender retirement evidence and private exact draft restoration.
No zero count is fabricated for missing usage/cost data.

## NEG07 ordering

The watch first observes the original timed-out result and provider failure.
It reads the same still-running r6 receipt around two reads of all four files:
terminal, provider input, provider output and claim. It saves each raw file and
the FENCE with file and directory fsync. A third full-nine-metadata/raw read
must still equal the original running receipt. The durability acknowledgment
binds that exact FENCE and this later observation time.

Only then can the watch record the original later terminal receipt with
`waitpid_joined=true`, `process_group_absent=true` and no identity loss. The
closer requires action-return ≤ PRE observation ≤ durability observation <
late-receipt observation ≤ POST observation. The four original files must
remain byte- and metadata-identical through POST and the final archive.
A missed window or changed receipt retains the failed first attempt; it is
never reconstructed after the fact.

## Unknown and recovery

Any disconnect, deadline, source change, output identity failure or incomplete
archive leaves a non-PASS original attempt. The Root coordinator sends no
cleanup signal, CONT, Cancel or automatic retry. Stopping an owned capture
reader never proves remote child cleanup. `FAILED-OR-UNKNOWN.json` distinguishes
remaining owned host children and retains the explicit no-replay disposition.

The P4 dispatcher supports read-only `--inspect-joined-phase PHASE` for an
existing phase that actually joined. This neither replays a phone actor nor
repairs an incomplete case. The unchanged sender's retirement/draft gates are
mandatory; a gate rejection remains a failed/unknown physical attempt. Do not
create a replacement nonce to erase an unresolved attempt.

## Local validation

The final candidate has24/24 source/transport interface checks and6/6
freeze/prepare interface checks. The latter use explicitly synthetic source
relationships and issue no actual adoption. Source-discovery independently
reviewed the NEG07 durable bookend and the producer/consumer phase interfaces;
the reports state their limited scopes. No source test is a phone result.

Portable commands, each with a new output directory:

```text
/usr/bin/python3 -I -B CANDIDATE/validation/test_physical_fault_source.py \
  --package CANDIDATE --manifest-sha256 CANDIDATE_SHA --out FRESH_HOST_CHECK_OUT
/usr/bin/python3 -I -B CANDIDATE/validation/test_freeze_prepare_interfaces.py \
  --package CANDIDATE --manifest-sha256 CANDIDATE_SHA --out FRESH_PREPARE_CHECK_OUT
```

The first attempted freeze/prepare test invocation supplied an incorrect
manifest hash and was rejected before any test began. Its rejection record is
retained; the subsequent correct-pin results are separately named. Earlier
source snapshots and their reported checks are also preserved, including the
correction to canonical Android component comparison. No actual case evidence
was rewritten or rerun during this source work.
