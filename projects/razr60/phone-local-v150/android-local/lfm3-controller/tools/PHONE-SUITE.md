# Frozen phone suites

`phone_suite.py` runs an explicitly enumerated navigation suite, using
`phone_acceptance.py` for each task. It does not download models, install an APK,
change the selected backend, reset ADB, modify permissions, force-stop an app,
or repeat an uncertain request. Use the current phone inventory and a locally
signed build before constructing a runnable plan.

## Validate the draft without a phone

```sh
python3 tools/phone_suite.py validate tools/suite-navigation-draft.json
```

The supplied draft has no APK hash and is intentionally not runnable. It defines
two real navigation cases: open Settings, and open Settings → Home → Settings.
These are a first regression suite, not the complete product acceptance matrix.
Each listed repetition must have its own case ID. Failure attempts remain in the
denominator; `not_run`, `unknown` and `unverified` remain separate counts.

For a real run, copy the draft into a private execution directory and fill the
candidate's actual signed APK SHA-256, versionCode and runtime configuration from
the build/installation records. An installed APK is compared to that preselected
hash; the driver never automatically trusts whatever happens to be installed.

```sh
python3 tools/phone_suite.py run /private/execution/frozen-suite.json \
  --adb /absolute/path/to/adb --adb-port EXISTING_PORT --serial DEVICE_SERIAL \
  --output /private/evidence/new-suite
```

All paths and identifiers are explicit. An existing output directory is a
conflict and causes no device contact. Only the `run` command contacts the phone.
The preflight checks the installed APK SHA/version, absence of INTERNET in the
package dump, the current private runtime configuration, and an idle, resolved
app session. It does not change any of them. The lack of INTERNET in this
application is recorded separately from the phone being offline.

Preflight also checks for the independent app-private
`files/control-session.interrupted.json` latch. It first establishes that the
app's `files` directory exists and is readable/searchable, then performs only
fixed `test -e` / `test -L` presence checks. Any entry blocks the suite, including
an empty, corrupt or dangling-symlink latch, even if the ordinary session JSON
looks idle. Only the explicit missing exit code is accepted. The suite never
reads, rewrites or clears this latch.

Before the initial and each per-case preflight, the driver checks the already
running ADB server protocol and the exact selected device through its smart socket.
It refuses a missing server or mismatch and never requests start-server or
kill-server. The task driver still uses ordinary ADB CLI commands after this
check, so a later server replacement is a residual race. The read-only inventory
uses shell-v2 sockets throughout and has no CLI daemon-start path.

## What a case proves

A case needs all underlying acceptance gates: exact original instruction,
nonce/task binding, clean terminal state, independent final UI predicates,
native and app receipts, exact model identity, actual backend/offload logs, and
grammar/input/output binding. On top of those, `required_actions` checks an
ordered subsequence of accepted, actually dispatched effects linked to their
before/after observations. An `open` additionally needs the target package in
the after observation. A generated action or a model's `done` statement does
not count as a dispatched effect. Local `find_app` catalogue reads are not UI
effects and do not count as taps or launches.

Each counted effect also requires independent model-output attribution:

- The action receipt must state `model_issued:true` and an exact 32-hex
  `model_run_id`.
- Exactly one model-attempt receipt from that same step must name the run,
  current observation and original owner-instruction SHA. A correction attempt
  is selected by its actual run ID; the first attempt is not assumed to be the
  executed one.
- Its raw model text must equal the collected `runs/<id>/raw-text.txt` bytes in
  standard UTF-8. `native-result.json` must bind that same request ID, raw SHA,
  byte count and complete, nontruncated output.
- Strictly decoded native JSON must equal the dispatched action object. Field
  order, JSON whitespace and escape spelling do not matter; exact Unicode text,
  values and types do. Only an explicitly empty optional `reason` may be omitted,
  matching the controller's serialization. Duplicate keys are rejected.
- One native model output cannot be counted as effects in multiple action steps.

The suite records each checked model/action binding and its source paths and
raw-output SHA. These checks supplement all existing case acceptance gates;
they do not substitute for model/runtime, offload, cleanup or final-UI checks.

Missing, corrupt or contradictory observation/model evidence produces
`unverified` for an otherwise passing case. A known launch count stays known;
an evidence gap does not mean the phone action failed or that nothing ran.
An underlying failed case remains failed. A complete observed action
sequence that omits a required effect fails the case. This proves the specified
navigation history and final predicates; it does not prove every intermediate
side effect. Form entry and settings-change tests need stronger task-specific
final predicates before they are added.

The effect verifier also recognizes production v6 `notes.create` and
`web.search`. Each requires its native-hashed fixed-tool projection, exact
installed target/component/UID and projected app label, literal payload SHA,
task/run/source-window binding and one matching durable before-call attempt.
Consumed journals must cover every ordinal from one through their total count;
a retained second attempt cannot hide a missing first attempt. Each fixed tool
may be consumed only once per task. A background launch also
needs the corresponding broker proof with the same display, generation,
ordinary caller, target, payload and attempt. Unknown/refused outcomes,
replayed attempts, arbitrary components and app-label substitutions cannot
count as accepted effects. A counted fixed launch still reports
`saved_or_search_results_verified=false`; final business-goal proof is separate.
v6 query-submit uses the same consumed-attempt and current-node checks as v5.

On an unknown cleanup or uncertain submission, following cases remain
`not_run`. `actual_launches` is null when a submission count is unknown; the
known launch count and unknown count are both retained. There is no automatic
retry or replay. Already confirmed failure remains visible even if execution is
incomplete. The full plan and every actual task receipt are retained privately.

The result always declares that full phone acceptance is not assessed by this
navigation driver. Offline-device operation, vision, dynamic UIs, interruption,
process restart, thermal endurance and coverage of the installed app catalogue
require their own observed tests.

## Host checks

```sh
python3 -m unittest discover -s tools -p 'test_phone_suite.py' -v
```

These use synthetic receipts and a fake ADB transport. They validate the test
driver, not the phone or the model. They execute no ADB commands.
