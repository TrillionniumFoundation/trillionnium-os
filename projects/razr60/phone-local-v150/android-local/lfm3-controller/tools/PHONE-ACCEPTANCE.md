# Hepta phone acceptance helper

`phone_acceptance.py` is a host-side test driver. It has not been run against a phone by its author. It never installs an APK, changes permissions, reruns the model qualification fixtures, or kills phone processes. Device serial and the existing ADB server port must be supplied explicitly; no default points at a phone or port 5037.

## One new test

```sh
python3 phone_acceptance.py \
  --adb /absolute/path/to/adb --adb-port <existing-port> --serial <selected-serial> \
  run-task --case-id settings-open-unique \
  --instruction '打开设置。' --evidence-root /absolute/private/evidence \
  --expected-package com.android.settings --setup-home
```

`--setup-home` is optional and is recorded as a test precondition, never as a model action. `--expected-visible-text '95'` adds an exact text/content-description predicate; multiple such flags require every value. `--text-match contains` explicitly permits substring matching. When an expected package is supplied, text matches must belong to that package and an explicitly different focused window fails the package predicate.

`--expected-model-profile <id>` accepts exactly the closed `PROFILES` registry in
`model_profiles.py`; omission retains its `DEFAULT_PROFILE`. The read-only
`phone_inventory.py` v2 configuration projection uses the same registry. An
unknown profile is rejected by the task CLI or leaves the v2 inventory projection
unverified. Selecting an expected profile does not change phone configuration,
import weights, or relax model identity, native execution, and independent goal
checks. Legacy v1 inventory remains a four-field projection without an inferred
`model_profile`.

Every case gets a new directory and conflicts are refused before contacting ADB. The phone's own `date +%s` supplies request time. The driver writes a new app-private 0600 debug request without clobbering an existing one, verifies its bytes, and sends exactly one launch Intent. A command timeout does not cause another submission. Trigger nonce SHA, Session nonce SHA, stable task ID and the task's exact original owner text/SHA must agree. All commands, including binary file reads, use `adb shell -T` with shell v2 exit-status handling; exit 40 alone means a missing optional file. Empty bytes from exit 0 remain a corrupt JSON error, not a missing file.

## Read-only status

```sh
python3 phone_acceptance.py \
  --adb /absolute/path/to/adb --adb-port <existing-port> --serial <selected-serial> \
  collect-status
```

This subcommand only reads the app's trigger, Session and final task receipts. It does not launch an Activity, send input, run a model, or dump the UI. Optional `--task-id <32-hex>` selects an existing task result. `--output /new/private/directory` preserves the read-only command evidence on the host and refuses an existing directory.

## Pass criteria and evidence

A `pass` requires a nonce/owner-bound terminal `model_reported_done`, known cleanup, independent final Android UI XML predicates, and complete associated native receipts: actual process exit, successful inference, matching run IDs and raw output size/hash. Every app receipt must identify the fixed package and the UID observed through `run-as` before launch, use the expected schema, declare `runtime=llama_cpp`, `compute_requested` matching the explicit expected mode, and confirm native binding. Every native receipt must explicitly identify `runtime=llama_cpp`, `compute_requested` matching the explicit expected mode, `device_resolved=HTP0 for NPU or GPUOpenCL for GPU`, `device_warning=null`, and UTF-8 output. Backend evidence is part of the pass gate, not merely recorded metadata. Model self-report alone is never a pass. With no independent predicates, a normal terminal task is `unverified`. Missing native evidence also downgrades a potential pass to `unverified`.

Version 29 additionally supports explicit task-worker schemas. A successful
request in a retained worker has `process_exit_observed=false` and
`exit_code=null`; it cannot pass the old one-shot exit contract. The collector
requires `warm_receipts.py` alongside this driver and fetches the exact
generation's app/native terminal receipts and shared accelerator log. All
requests must bind to one task, generation and PID, consecutive unique request
IDs and reset counts, and the controller's final terminal-receipt SHA. The app
terminal must record actual owned exit, successful native destruction/deinit
and known cleanup. Missing terminal proof, an uncommitted late output or a
foreign generation cannot qualify even when final UI predicates happen to
match. See `../CODE29-TASK-WORKER.md` for the complete lifecycle contract.

The directory contains `acceptance.json`, `file-manifest.json`, bound trigger/Session/owner records, task JSON, and associated native run receipts, raw text, prompt/system text, complete logs and incomplete `.pending` outputs. When failed inference never produced a step-model record, association uses both the exact owner bytes and the task's unique observation ID from the saved native prompt. Other candidate runs are not added to the associated run list. Screenshots are not exported by default; `--include-screenshots` explicitly enables copying existing task screenshots and native image inputs.

Final UI observation uses Android's `uiautomator dump` only after the nonce/task-bound terminal receipt declares known cleanup and the matching Session confirms both pending and running are false. The default UiAutomation observer may temporarily suppress and reconnect Accessibility services, so it is never used while a task is active. It writes a unique temporary XML in `/data/local/tmp` that is removed after collection; it does not navigate or execute a model action. Raw XML and window-focus output are retained on the host. Full stdout, stderr, return codes and timestamps for ADB commands are saved. Evidence includes private phone UI and instructions and must not be committed or uploaded as source code.

## Timeout behavior

The default task timeout is 540 seconds, polling interval 2 seconds, and terminal collection grace 25 seconds. On timeout, the driver only reads the Session and result receipts. It records that no qualified non-suppressing Stop observer is available and requests manual normal-UI stopping when the active Session still belongs to its nonce/task. It sends no UI dump, launcher Intent, guessed coordinate click, force-stop, or PID kill during timeout teardown. Cleanup stays unknown until a matching terminal receipt establishes it. An operator may independently use a visual screenshot to locate the real Stop button or a separately verified observer with `FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES`; this helper does not silently assume the stock CLI has that flag. A timeout cannot become a pass merely because a late result arrives.

Exit codes: `0` pass, `2` failure/driver error, `3` unverified. Failure artifacts remain available. To retry deliberately, choose a new case ID and submit a new owner task; the script does not replay a failed request itself.

## Offline checks

`test_phone_acceptance.py` uses only an in-memory FakeAdb and synthetic XML/JSON. The 23 checks cover independent predicates, missing/corrupt native evidence, nonce rejection without replay, directory conflicts, literal instruction transport, exact text/focus checks, failed-run association, Stop-button uniqueness, read-only status, shell-v2 exit transport, explicit backend/app identity gates, and timeout collection with no UI commands. These tests do not establish real device acceptance.

`test_profile_registry_consumers.py` exercises the actual CLI parser for every
registered profile and runs the actual scalar projection script against private
host fixtures. It checks the unchanged default and legacy configuration, rejects
unknown profiles, and retains the other configuration limits. It contacts no
phone and supplies no model-quality or device-qualification evidence.

## LFM3-specific gates

The independent package is org.trillionnium.hepta.local. Use --expected-compute npu|gpu and --expected-context 4096|8192 to match the fixed private runtime configuration. The driver requires the official model SHA, text-only llama_cpp mode, matching app/native model paths, no fallback warning, nonzero layer-offload request and the native actual-template budget. Positive layer-offload and selected-accelerator model-buffer log evidence are also required; resolved-device metadata alone cannot pass. This demonstrates tensor offload, not 100% operator coverage or power efficiency.

Revision 2 additionally collects grammar.gbnf and requires its actual SHA to match the app receipt, native input_sha256.grammar and the associated observation. Plain diagnostic inference cannot qualify as a control-model step.

## Production v6 compatibility

The collector accepts the explicit `hepta.observed-action-gbnf.v6-fixed-intents`
schema while preserving the older v4 app-pair and v5 query-submit checks. The
schema in the app receipt must match the actual native-hashed prompt; changing
only a receipt discriminator does not upgrade an older request. An explicitly
empty `fixed_intent_tools` list is valid and grants no fixed tool.

`notes.create` and `web.search` use their own closed prompt projection, not the
launcher `open_allowed_packages` list. Their exact app label, package, parameter,
payload limits and requested outcome are checked against the production fixed
profiles. The complete native prompt SHA binds this projection; the open-app
label digest does not pretend to cover it. No arbitrary component, URI, title,
extra parameter, omitted tool or crossed app label can qualify. v6 `submit`
retains the same focused-node/query-label/input-digest checks as v5.

This remains a native-input/output verifier. Use the suite's action binding to
verify a dispatched fixed intent against its installed-target receipt and
durable before-call journal. Neither an accepted launch nor a valid model
receipt proves a saved note or an actual search result. `run-task` still uses
the existing debug nonce/Intent entry and is not an ordinary-UI background-task
driver; `collect-status` remains read-only and works for a separately selected
ordinary-UI task ID. The archived background r2 helper pins are unchanged.
