# Independent local phone core acceptance

This suite adds concrete goal checks to the sibling `../../lfm3-controller/tools`
drivers. It is kept outside the frozen APK source directory so its development
does not change that app's 105-member source manifest. It does not install the app,
select a model, import weights or change permissions. Only `run` contacts a phone.

## Cases and evidence

| Case ID | Required result |
|---|---|
| `core-settings-home-01` | Open Settings and finish with its package, home title and search entry independently visible. |
| `core-settings-apps-01` | Actually click an observed Apps entry and finish on the app management page. |
| `core-calculator-keypad-01` | Clear the Motorola calculator, then press `2`, `3`, multiply, `1`, `9`, equals. Require the entered expression and visible final result `437`. Any calculator `type` shortcut fails. |
| `core-settings-chinese-search-01` | Model types exactly `蓝牙` into observed `android:id/search_src_text`; require readback, the exact final field value and a separate result in `com.android.settings.intelligence`. |
| `core-search-return-home-01` | Model uses the system `back` action from the search page to Settings and finishes on Settings home. The owner instruction explicitly requests system Back for this action-specific case. |
| `core-settings-home-settings-01` | Model opens Settings, goes Home and opens Settings again, in order. |
| `core-cross-app-01` | Model opens Settings, calculator and Settings in order, with each target actually observed. |
| `core-settings-scroll-01` | Model scrolls an observed Settings node; visible nonnumeric content must change between bound observations. |
| `core-find-calculator-01` | Model first issues read-only `find_app` for `计算器`, receives the target in its bound result and opens that returned app. |

The first four cases are the original requested functional goals. The following
five separately exercise system Back, ordered navigation, switching apps, scrolling
and discovery. The recovery case has no external Home setup and follows the search
case in the default order. It requires its actual starting state; a failed preceding
search is not silently reset. A visible Back-arrow click does not qualify the
explicit system-Back case, even if it completes a more general navigation goal.

Every counted effect is bound to one complete native raw output from the same task
step, original instruction and observation. Its selected node or app must be in
the actual model input. `find_app` is a read-only catalogue lookup with its own
request/result binding, not a dispatched UI effect. Original nonce, model hash,
native execution, budget, accelerator offload, cleanup and final-UI gates remain
mandatory. Missing evidence cannot become a pass; an upstream failure stays failed.

The calculator result check currently targets the observed Motorola application
contract and excludes `EditText` result nodes. A different widget implementation
needs independently retained UI evidence and a new assertion revision; these
fixtures do not establish compatibility with every calculator app.

## Freeze a real candidate

The checked-in candidate JSON files bind the separately assembled same-signer
code4 APK described in `BUILD-PROVENANCE.json`, MiniCPM5 and NPU at 4096 or 8192
context. A newly built APK, different signer, profile or configuration requires a
new candidate with its actual values. No candidate changes the phone itself.

From this directory, freeze the current model-aware driver closure and all nine
cases without contacting a device:

```sh
python3 core_phone_suite.py freeze \
  --drivers ../../lfm3-controller/tools \
  --candidate candidate-code4-minicpm5-npu8192.json \
  --suite-id code4-minicpm5-npu8192-core9-r2 \
  --output out/plan-code4-minicpm5-npu8192-core9-r2.json
python3 core_phone_suite.py validate out/plan-code4-minicpm5-npu8192-core9-r2.json
```

For the original four goals, use a distinct suite ID/output and add:

```sh
--case core-settings-home-01 \
--case core-settings-apps-01 \
--case core-calculator-keypad-01 \
--case core-settings-chinese-search-01
```

Every top-level Python/JSON file in `--drivers` is pinned, including
`model_profiles.py`. Execution copies this closure into the new result directory.
Changed, missing or extra driver files prevent execution. Optional candidate
`model_profile` passes unchanged to the base driver; this framework does not
hardcode a model hash. An omitted profile retains the base driver's strict legacy
LFM3 contract.

## Execute once on the explicitly selected phone

Use the test owner's confirmed existing ADB executable, server port and exact
serial. The runner supplies no device default and will not start a missing server.
Choose a new result directory:

```sh
python3 core_phone_suite.py run out/plan-code4-minicpm5-npu8192-core9-r2.json \
  --adb "$HEPTA_TEST_ADB" --adb-host 127.0.0.1 --adb-port "$HEPTA_TEST_ADB_PORT" \
  --serial "$HEPTA_TEST_SERIAL" --output "$HEPTA_TEST_OUTPUT"
```

The installed APK/version and current private runtime configuration must match the
frozen candidate. An active or unresolved app session blocks submission. Cases run
sequentially, once each; unknown submission or cleanup stops later cases. Home
setup is recorded separately and cannot satisfy a model-issued action requirement.

`suite-result.json` retains case membership, original verdicts, launch counts,
candidate, code identities and errors. Each case additionally contains retained
native output, prompt, action receipts, before/after observations, independent final
UI evidence and `core-checks.json`. Keep actual phone evidence private rather than
committing it. Offline re-evaluation writes a separate report without replay:

```sh
python3 core_phone_suite.py evaluate /absolute/path/to/existing/result
```

The suite reports `full_phone_acceptance: not_assessed`. Nine functional goals do
not qualify every app, vision, locked-screen operation, cancellation, recovery,
sustained thermals, power consumption or production release.

## Host validation and revision boundary

```sh
python3 -B -m unittest -v test_core_assertions.py
```

The 20 synthetic fixtures cover real keypad evidence versus typed shortcuts,
Chinese typing and results, scroll changes, native/input tampering, app discovery,
model-profile forwarding and stopping unknown submissions without replay. They are
not phone or model-quality acceptance results. The optional
`HEPTA_CORE_TEST_DRIVERS` environment variable selects another explicit driver
directory for host-only compatibility checks.

The publication copy clarifies the system-Back owner instruction and uses a
repository-relative default test-driver path. Existing deployed r1 code and its
frozen plans are not rewritten by this publication. The frozen app source,
signature and APK remain unchanged. Full device qualification is still in progress.
