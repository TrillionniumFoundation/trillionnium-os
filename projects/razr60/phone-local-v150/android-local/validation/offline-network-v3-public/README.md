# Measured offline phone-suite transaction — revision 3

Revision 3 only distinguishes the exact `Wifi is enabled` / `Wifi is disabled`
state header from the separate, known `printWifiInfo` connection description.
The real Android output can contain both. Duplicate/unknown/malformed headers,
conflicting disabled-plus-connected output, and ambiguous connection records
remain rejected. The transaction runner and all radio, SIM-binding, restoration,
deadline and initial-zero refusal behavior are byte-identical to revision 2.
No device operation is part of this parser correction. Public tests contain
synthetic network names only.

This independent Linux host tool wraps the already frozen core suite v2. It does not change Hepta, its APK, owner instructions, goal predicates, profile or model. Only an explicitly requested `run` or `restore` operation contacts the selected existing USB ADB transport. Preparing or testing this directory does not contact a phone.

The operator owns scheduling. Start only after the preceding phone task has a stable clean terminal session, and use a new output directory. Do not run another phone controller, lifecycle test or model job concurrently. The wrapper does not make an unfinished task safe to replay.

## Measured contract

Before touching radio settings, the wrapper checks that Linux `/proc` exposes the same PID namespace as Python, validates the exact SHA256 of the frozen plan and the pinned core v2 implementation, validates the base-driver closure through that core, checks the existing ADB server/client protocol, and requires a unique selected online USB transport. It does not start or reset an ADB server and does not accept a TCP-only device record.

Revision 2 additionally requires the explicit candidate data key to equal 1 in the stable baseline. If it is already 0, the wrapper refuses the transaction before any radio mutation: zero-to-zero does not establish the still-unverified key-selection relation, and the tool must not invent an original data value. Revision 1 and its journals remain separate; do not switch recovery implementations for an existing journal.

The wrapper then reads the original radio controls twice. The explicit default data subscription and multisim mode must match the operator's observed values before and after every snapshot. A data mutation checks them again immediately before issuing `svc data`; that check and Android's default-subscription command are not atomic, so the receipt describes an observed stable subscription scope rather than an absolute exclusion of every possible concurrent SIM switch.

For the currently investigated Razr, the operator observed subscription `1`, mode `dsds`, `wifi_on=1`, `mobile_data=1` and `mobile_data1=1`. The wrapper therefore accepts **explicitly supplied** `mobile_data1` as a candidate readback key. It does not infer a fallback key, write global settings directly, or claim that the Android 16 internal key-selection helper has been fully verified. The journal retains `android16_helper_storage_chain_claimed:false`.

Only `svc wifi disable` and `svc data disable` change the network controls. Mutation intent and the original values are durably written before each command, because a timed-out command may already have taken effect. A successful exit alone is not treated as proof of effect. The core suite starts only after two stable observations show all of:

- `wifi_on=0` and the unique complete Wi-Fi status line says disabled;
- the explicitly selected data readback key equals `0`;
- the default subscription/mode remain the selected values;
- the successful complete connectivity dump has exactly one unambiguous `Active default network: none` header.

The disabled Wi-Fi text alone is insufficient. A missing or conflicting header, unreadable switch, unexpected USB transport, changing SIM binding or an unchanged selected data key prevents the suite from starting. The global `mobile_data` value is recorded independently throughout; no missing per-subscription value falls back to it.

During the suite, the wrapper periodically rechecks those conditions and verifies them twice after normal child exit. These are sampled control-plane observations, not continuous packet capture. The separate Hepta preflight must still establish the APK's lack of INTERNET permission and local native profile/nonce evidence. The wrapper does not claim that every SIM or the modem is powered down.

## Restoration and deadlines

Normal completion, an exception and SIGTERM/SIGINT/SIGHUP all enter the same restoration block. The wrapper first interrupts only its own identity-bound host suite process group, then restores radio controls before waiting for potentially slow child evidence collection. A second signal during teardown records the request without interrupting restoration. No phone process is killed, no screen is locked, no accessibility setting is changed, and no interruption latch is cleared by this wrapper.

Restoration uses only `svc wifi enable|disable` and `svc data enable|disable` with the original target values. It verifies twice that Wi-Fi state, the selected data key, the independent global data value, default subscription and multisim mode all match the saved original state. Whether a default route has returned is recorded separately. If the observed default subscription changes, it still attempts Wi-Fi restoration but refuses to issue a data command against that newly observed subscription; data restoration remains explicitly unverified.

Every socket read **and send** has the remaining phase deadline. Local host-child supervision uses PID, process group, session and start ticks. Default budgets are 120 seconds per preparation/post-check phase, 6,000 seconds for the suite, 120 seconds for restoration and 45 seconds of child-exit grace, with additional outer-supervisor margin. With those defaults, set the actual external job timeout and `--supervisor-timeout-seconds` to at least **7,000 seconds**. The argument records/checks the required margin; it cannot alter an external supervisor's real timeout. A shorter explicit suite may use smaller budgets only when all frozen case timeouts and collection allowance still fit.

SIGKILL, host power loss, persistent USB loss or a stalled operating system can prevent finally from completing. The private journal supports explicit later restoration. If a host driver is interrupted while a phone task remains active, the wrapper reports `phone_cleanup_known:false` and requires the operator to inspect or visibly stop that task; it never labels the interruption as a successful cancellation.

## Run a reviewed frozen plan

The pinned core implementation is `core_phone_suite.py` SHA256 `22f1e4643e3076f630749a79c7f2a30beba7171097c5ef8c36bcaa80d83c753c`, with `core_assertions.py` SHA256 `65999f565846afda7ff7ba75dee4eff1cc4e32a29f670b9182039139eec0d836`. The v2 plan additionally pins the specific base drivers. For code8, freeze against the independent compatible drivers so reason-first grammar is validated correctly; do not modify the original code8 source tree.

```bash
python3 phone_offline_suite.py run \
  --core /home/alex/razr-local-ai-20261108-dda84ccf/core-suite-r2/core_phone_suite.py \
  --plan /absolute/path/to/reviewed-frozen-plan.json \
  --expected-plan-sha256 EXACT_PLAN_SHA256 \
  --adb /absolute/path/to/existing/adb \
  --adb-host 127.0.0.1 --adb-port 5061 --serial "$HEPTA_DEVICE_SERIAL" \
  --data-setting-key mobile_data1 --expected-default-subscription 1 \
  --expected-multisim-config dsds \
  --supervisor-timeout-seconds 7000 \
  --output /absolute/path/to/new-offline-run
```

There is no automatic task retry. The wrapper can wrap all nine reviewed goals or an explicitly frozen subset; it does not remove failing goals or edit a plan. Use the exact plan digest computed after freezing and keep the original plan and driver closure.

## Inspect the outcome

`offline-result.json` separates the network transaction from the core functional result. `verdict:completed_and_restored` means the normal suite completed under the observed offline controls and the original settings were restored; it does not mean that the phone goals passed. `suite_verdict` and `core_functional_acceptance` preserve the core result. Exit zero requires both a verified transaction/restoration and an actual passing core result.

`network-journal.json` retains original controls, pre-command mutation intents, every parsed state snapshot, exact USB identity, driver identity, errors and restoration attempts. Private command files retain bounded raw stdout/stderr, exit status and hashes. These files may include device/network details and remain in the operator's private evidence directory; they are not source artifacts to publish.

## Explicit recovery after interruption

Use the same frozen wrapper/guards revision and an owned private journal. The restoration command validates their recorded hashes and the original controls before attempting any mutation. It writes a new evidence directory and never overwrites the original run.

```bash
python3 phone_offline_suite.py restore \
  --journal /absolute/path/to/interrupted-run/network-journal.json \
  --output /absolute/path/to/new-restoration-attempt
```

If the same serial reconnects at the same USB path with a new transport ID, explicitly add `--allow-reconnected-usb`. The default refuses a changed transport. That option does not permit another serial, USB path, subscription or multisim mode. If restoration remains unverified, inspect the reported original values and current state before taking another action.

## Host qualification

```bash
python3 -B -m unittest discover -s . -p 'test_offline_transaction.py' -v
```

The tests use an in-memory radio-state provider, never an ADB server or phone. They cover ambiguous status text, exact USB selection, missing-key refusal, an effect followed by a command timeout, SIM drift, restoration of both independent data readbacks, refusal to start on an unknown network and separation of functional failure from restoration. A Linux-only test delivers two real SIGTERM signals while a harmless owned Python child is active and verifies that finally still completes. It is skipped when the host's mounted `/proc` does not match its PID namespace; that skip must not be reported as passed. Run the full host qualification on Pocket4 before phone execution.

## Publication-only documentation variant

This directory preserves the exact operational Python files and tests from the
frozen offline r3 tool. Its documentation example uses an explicit operator
device parameter. The original r3 manifest remains
`87b05fe3cb25f9b72edd4993b6b27ea467bfac3dfcfb41507ca9b08d4dbe3305`;
this publication copy has a distinct source manifest and must not replace the
original identity in retained phone plans or past execution evidence.
