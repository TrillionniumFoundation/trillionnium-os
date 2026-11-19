# Personal Notes current-absence recovery

This is the ordinary application's recovery path for an expired, failed personal
Notes display lease. It does not perform administrative retirement. A separate,
private operator tool must have already retired a retained creator when that is
necessary. Neither an administrative JSON record nor a remembered task ID grants
the application cleanup authority.

## Product behavior

The request derives its task, generation, owner, user 0 Notes UID and remembered
task IDs from seven exact original records for a pre-model failure. A separate versioned
request accepts one drained `notes.create` attempt with an unknown effect, adding
eight exact originals: model step, action step, consumed fixed-intent attempt,
request/session/native-session receipts, worker generation identity and its native
cleanup receipt. There is no wider model-cancellation or retry recovery branch. It separately binds the current
blocked control-session record and the actual installed controller. There are no
device, boot, PID, task, APK hash or maintenance-path pins in product sources.

The root checker takes two new read-only samples after retirement. Each sample
requires complete process, root/leaf task, display and recent-history information.
The original display identity, remembered task IDs and all Notes package/UID
matches must be absent. Both physical displays and every remaining history entry
must remain unchanged across the recovery interval. Recent-history comparison
retains complete internal, visible and hidden records and order; only a bounded,
monotonic inactivity-age increment is normalized. No old pre-retirement physical
hash is used, and no remembered task is excluded from the history comparison.

The application accepts a private in-memory receipt only from its own completed
checker process, with exit code 0, complete EOF, the same installed APK and a fresh
12-second request. It durably archives all seven or fifteen originals and the current
control snapshot before compare-and-swap removal of the exact active journal.
The original task result and cleanup remain failed/unknown. This receipt means
current absence; it does not mean normal broker release or business success.

The existing ordinary cleanup button is the entry point. Its worker drains,
controller generation, recovery reservation, current-control and journal inode
checks remain in force. Cleanup leaves the interrupted session blocked. The
existing separate acknowledgement action is still required before a new session.
The profile-10 recovery branches and their proof formats are unchanged.

## Portable host gate

Run from a complete source tree with a full JDK and the existing pinned org.json
20240303 JAR:

```sh
python3 tests/personal-notes-absence/run_host.py \
  --source . --java-home /path/to/jdk17 \
  --json-jar /path/to/json-20240303.jar --output /new/output/path
```

The runner compiles with `--release 8 -Xlint:all,-options -Werror`. It retains all
previous cases and runs 91 pure policy cases / 109 assertions and 27 application
client/lease cases / 247 assertions, plus 33 post-model cases / 47 assertions.
All original/task/controller values are authored synthetic values; captured
phone records, task instructions and private scope material are not embedded.
The complete production BackgroundSession, private-files implementation and
Notes client are compiled. Only the client's owned Process factory is replaced.
Four service admission methods are extracted exactly from production source.
Android clock, display, package identity and transport are explicit fixtures;
there are no phone operations and no Android runtime qualification.

The shared background-session fixture retains its original default behavior.
Its new `include_terminal=False` option only omits the unrelated controller
finalization fixture for this dedicated recovery gate. All existing callers keep
the default. Generic legacy gates compile the complete new Notes client against
the same always-refusing process boundary used by the existing recovery clients.

The optional `--java8-syntax-only` mode is explicitly draft-only. It supports a
JRE exposing the compiler module without a Java 8 API symbol archive. Its result
sets `strict_release8=false`, which the canonical integration hook rejects.

The read-only Android Main is part of the full Android source build. This host
gate does not replace Binder/PackageManager execution or claim that Main has run
on a device. A maintenance-only wrapper may pin candidate DEX and actual installed
APK separately; it cannot create the application's opaque receipt or acknowledge
an interrupted ordinary session.

## One drained model request

The extra branch binds the successful bootstrap and later failed create response
separately, retaining all originally observed task identities. It cross-checks the
consumed attempt and unknown action result, requires no pending workers, and binds
the request output to the single action. A normal model close must include the
App's observed exit, the native SDK close receipt, and the unchanged
`WorkerGenerationProof` verification of the exact generation identity and cleanup
bytes. No TERM/KILL attempts are accepted in this narrow branch. The original App
PID is historical evidence and need not equal the new recovery UI's process PID.

All extra file paths are derived from validated task/run/generation/nonce IDs.
Receipt-supplied paths do not authorize arbitrary file reads. Every extra original
is held and rechecked before sampling, durable commit and lease acceptance;
additional steps, attempts or completion evidence are refused. The ordinary
12-second double-absence check and the separate acknowledgement are unchanged.
A model close does not establish that a dispatched unknown tool had no effect.

## Display creation failed before application launch

The same seven-record request also accepts a narrowly proven prelaunch failure.
Both original bootstrap and cleanup records must say that no application launch
was dispatched. The failed final operation must be `create`, with retired and
closing admission, an empty task-location record and no launch-policy field.
The creation response's `dispatched=true` describes display creation; it does not
mean that the application or a model was launched. Both version-2 custody records
must show zero observed tasks, no pending reads, no release call and no previous
absence assertion. An uninitialised custody display ID of -1 is accepted only in
this branch; the exact positive display identity still comes from the journal.
The original result must retain zero steps, no model/native dispatch and no
business effect. A post-model input set cannot enter this branch.

Eligibility permits an already stopped Notes lease with a recorded spawn attempt
to enter this validation. It cannot itself retire a journal or accept a JSON
cleanup flag. The normal private receipt, current control CAS, current APK check,
deadline and fresh complete absence samples remain mandatory. Empty remembered
task IDs never substitute for the absence of every Notes task and history record.
The host regressions exercise the actual client and lease through this path,
including failed checks, current-control replacement and rejected eligibility.
