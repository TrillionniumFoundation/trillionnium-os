# Independent Hepta lifecycle validation

This tool is outside the frozen Android source. Preparation and host tests do not
contact a phone. `monitor` and `idle-restart` operate only the explicitly supplied
device. The operator must finish any other phone task first and own the phone
exclusively throughout a lifecycle experiment. Do not run it alongside a core
matrix or another automation loop.

## What is actually qualified

The cancellation case binds the original private one-use nonce, task owner,
observation, local-model request, ordinary App UID, App parent PID, native child
PID and process start ticks. It records the focused foreground app while the
owned native process is alive, establishing whether Hepta was in the background.
The installed APK hash/version/profile/configuration and absence of an INTERNET
declaration are checked before a task is submitted. A local model path and model
hash are then checked in the owned process arguments and App receipt.

The monitor shows the existing task through a normal MainActivity launch without
`auto_task` or `auto_run` extras. It captures a screenshot, then waits for an
explicit operator request identifying the visible **停止** control and its pixel
rectangle. It does not guess button coordinates. After the operator request, it
waits for the pinned SDK's actual `llm.cpp:...:generate` entry marker in **this
run's** stderr, rechecks the same worker and visible control, and sends one tap.
This proves entry to generation/prefill, not that a decoded token already exists.
The operator can inspect the UI during slow hash/create work so a short
generation window does not require another remote round trip.

Passing cancellation requires the original native process to exit, the original
App process to survive, a nonzero owned native exit with `cancel_requested=true`
and no timeout, a clean nonce-bound `cancelled` task/session, no new native run,
and no new action dispatch after the observed Stop. A naturally completed native
receipt, a changed PID/start time, an expired screenshot, a changed Stop region
or uncertain cleanup is inconclusive. There is no retry or active-app kill.

The idle restart case first proves the complete SessionRecovery contract twice
over a stable interval: a fully identified known-clean terminal session, no
pending/running/blocked flags, no unknown cleanup, no native worker and no
`.bak`, `.new`, interruption latch or unconsumed debug request. An immediate
same-shell hash/sidecar/process guard precedes its single **idle-only** force-stop.
It then opens MainActivity without auto extras and observes that the previous
session bytes and all task/run/consumed-nonce memberships stay unchanged.

Restarting an Activity does not prove Accessibility has rebound. The tool saves
the exact package's `dumpsys activity services` component/ProcessRecord evidence.
It never treats identical `Bound services` display labels or an enabled-settings
entry as exact binding proof. If a recorded rebind is needed, the operator does
it separately. A fresh task's real accepted nonce trigger (which checks
`connected()!=null`) and new native run establish operational recovery.

The device's radios are not disabled or measured. `device_offline_proven` stays
false. No-INTERNET/local-model evidence does not become a whole-device network
isolation claim. No lockscreen, screen-off, broad app or power qualification is
implied by these lifecycle cases.

## 1. Prepare an exact plan offline

Use the actual source and candidate matching the installed APK. The candidate
format is the same one used by `phone_suite.py`; no SHA or profile is hardcoded
in this tool. Supply an exact short instruction in a UTF-8 host file.

```sh
python3 phone_lifecycle.py prepare \
  --source-dir /absolute/path/to/frozen/source \
  --candidate /absolute/path/to/candidate.json \
  --instruction-file /absolute/path/to/cancellation-instruction.txt \
  --output /absolute/path/to/new-lifecycle-plan
```

Source members and the four imported base drivers are hash verified. The plan
also pins this tool and its guards. Subsequent source/tool changes require a new
plan rather than silently changing an existing attempt.

## 2. Arm a persistent monitor

Before launching, the operator obtains the **physical** SurfaceFlinger display
ID and the **logical** input display ID, dimensions and pixel mapping from the
actual device. They are different namespaces. The tool rejects a physical ID
missing from the observed inventory or screenshot dimensions that do not match
the explicitly supplied input dimensions. There is no default display guess,
coordinate scaling or rotation correction.

```sh
python3 phone_lifecycle.py monitor \
  --plan /absolute/path/to/new-lifecycle-plan/plan.json \
  --output /absolute/path/to/new-cancel-run \
  --adb /absolute/path/to/adb --adb-host 127.0.0.1 \
  --adb-port OBSERVED_PORT --serial OBSERVED_SERIAL \
  --physical-display-id OBSERVED_PHYSICAL_ID \
  --logical-display-id OBSERVED_LOGICAL_ID \
  --input-width OBSERVED_WIDTH --input-height OBSERVED_HEIGHT
```

Use a host supervisor timeout longer than the 30-minute armed wait plus the
10-minute task and one-minute cleanup bounds, or explicitly terminate the
**armed** job before any start request. Do not terminate the host monitor while
the phone task is active. The monitor initially writes `status.json` with phase
`armed` and does not contact ADB until a correct `start-request.json` arrives.
This avoids remote process-start latency consuming the cancellation window.

The status includes an exact `start_request_template`. Publish it to
`RUN/start-request.json` as a new private **0600** regular file with one link.
An atomic host file-write API is suitable. Or, with a low-latency host shell:

```sh
python3 phone_lifecycle.py request start --run-dir /absolute/path/to/new-cancel-run
```

## 3. Observe and request the visible Stop

When phase becomes `awaiting-observed-stop`, inspect
`RUN/stop-observation.png`. Its raw command output and any Android display
warning prefix are retained separately. The PNG signature, chunks, CRCs,
geometry and decompression bound are checked. Active UiAutomation is never used.

Locate the actual enabled **停止** control. Record its rectangle `[x1,y1,x2,y2]`
and a point strictly inside it. The status includes a
`cancel_request_template` binding the screenshot hash, nonce, task, run and
worker PID/start ticks. Fill only `point`, `rectangle` and
`requested_host_wall_ms`, then publish it once as
`RUN/cancel-request.json`, private 0600. If a low-latency host shell is available:

```sh
python3 phone_lifecycle.py request cancel \
  --run-dir /absolute/path/to/new-cancel-run \
  --point OBSERVED_X OBSERVED_Y \
  --rectangle OBSERVED_X1 OBSERVED_Y1 OBSERVED_X2 OBSERVED_Y2
```

The monitor compares the approved control's decoded pixels with a fresh capture
immediately before the tap. Changes elsewhere, such as the status-bar clock,
do not invalidate the control. It checks foreground package, logical display,
same native/App PID/start ticks, nonce/session and receipt ownership again.
It records the tap attempt **before** injection, so an ambiguous transport
result can never cause a second tap.

If the worker finishes first or any guard fails, no speculative click is sent.
Read the final status; do not manufacture a pass or delete recovery evidence.
An inconclusive run can leave a live task or an unconsumed private request, so
the operator must inspect its actual state before another experiment. The tool
does not clear such files or stop the active App on the operator's behalf.

## 4. Prove a fresh task can start afterward

After `cancel-complete`, `verdict=pass`, `cleanup_known=true`, run **one new**
nonce-bound case with the already approved core/phone driver. Do not replay the
cancelled nonce. Then evaluate its retained evidence offline:

```sh
python3 phone_lifecycle.py followup \
  --prior-status /absolute/path/to/new-cancel-run/status.json \
  --case-dir /absolute/path/to/fresh-suite/cases/CASE_ID \
  --output /absolute/path/to/new-followup-review.json
```

The review checks fresh task/nonce identity, exact instruction and observation
ownership, accepted private trigger and new owned local-model process receipts.
It reports ability to start/infer separately from the new task's actual goal
verdict. A failed navigation goal does not become a lifecycle success claim for
phone control.

## 5. Idle restart and no automatic replay

Wait for the previous fresh task's clean terminal publication, not just its
worker exit or `result.json`. Then execute the separate explicit idle experiment:

```sh
python3 phone_lifecycle.py idle-restart \
  --plan /absolute/path/to/new-lifecycle-plan/plan.json \
  --output /absolute/path/to/new-idle-restart-run \
  --adb /absolute/path/to/adb --adb-host 127.0.0.1 \
  --adb-port OBSERVED_PORT --serial OBSERVED_SERIAL
```

Observe `idle-restart-no-replay-observed`. Service-process evidence is retained,
but actual Accessibility recovery remains unqualified until a new task is
accepted and starts native inference. If the operator performs a necessary
service rebind, retain that intervention separately; the tool never toggles
services. Run another fresh case and use `followup` with this idle-restart
`status.json` to verify operational recovery. Never delete a latch, `.bak` or
`.new` simply to make this test run.

## Host checks

```sh
python3 -m unittest -v test_lifecycle_guards.py
```

These focused host checks exercise complete-session identity, real host `/proc`
parsing and PID reuse detection, screenshot-region change/CRC handling, private
request-file rules and the natural-completion cancellation race. They do not
count as device lifecycle results. Keep actual phone screenshots, prompts,
receipts and runtime records outside this source directory and out of GitHub.
# Runtime path correction in revision 2

Revision 2 preserves the original lifecycle protocol and records new evidence separately. The first code8 revision-1 monitor launched one task and sent zero Stop taps. It rejected a valid native process because it treated `legacyNativeLibraryDir` as the final executable directory and assumed `run-as pwd` had the same spelling as Java's private data directory. That run remains inconclusive; the task later completed naturally and does not demonstrate cancellation.

Before submitting a task, revision 2 reads the SHA-verified installation's package record, requires its exact package code path and `arm64-v8a` ABI, and searches only the declared library directory to depth two for one regular `libhepta_local_runner.so`. Its observed canonical path must be exactly `<codePath>/lib/arm64/libhepta_local_runner.so`. The private roots `/data/user/<current-user>/<package>` and, for user zero, `/data/data/<package>` are resolved individually under the App UID. They are accepted as aliases only when the observed canonical paths agree and remain inside that same user/package. Missing, ambiguous, changed or cross-user paths stop preparation before a task is launched. No suffix match or unobserved alias substitution is used.

The live native check still requires the ordinary App UID, exact parent PID, unchanged PID/start ticks, exact run/profile/model/configuration and owner/observation binding. Prompt, result, text, system and grammar paths must refer to the same exact private run. `runtime-path-binding.json` records the observed path qualification; small `process-<pid>-latest.json` files aid diagnosis while the complete raw reads remain in private command evidence. Existing visible Stop, generate-entry, exit, cancellation receipt, clean session and natural-completion race rules are unchanged.

Run `python3 -B -m unittest discover -s . -p 'test_lifecycle_guards.py' -v` in this directory for the 14 host contracts. These are host qualifications, not proof of a successful device cancellation. Use this directory's own `phone_lifecycle.py prepare` to freeze a **new** plan; revision-1 plans intentionally fail the tool-hash gate in revision 2. Never overwrite an old run or relabel it as cancelled.

