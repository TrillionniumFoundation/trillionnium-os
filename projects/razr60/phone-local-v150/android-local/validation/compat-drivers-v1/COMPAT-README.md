# Independent base acceptance drivers, compatibility r1

Frozen application source and previous evidence remain unchanged. The base is the complete top-level Python/JSON/Markdown tool closure from code8, as identified in COMPATIBILITY.json. Only phone_acceptance.py and its synthetic tests change; model_profiles.py remains byte-identical to code8 and carries the three model pins inline.

## Reviewed change

The controller grammar gate accepts exactly hepta.observed-action-gbnf.v1 and hepta.observed-action-gbnf.v2-reason-first. Other or absent schemas fail. The exact grammar file SHA must equal both the app receipt and native input SHA. Its observation ID must refer to recorded step-before/after observations, whose package must uniquely match grammar_current_package. A model receipt or requested action cannot supply this window package.

All existing app identity, model profile/SHA, nonce/owner/run, native output hash, explicit backend/offload, context, cleanup and independent UI gates are retained. Nothing changes the task goal or makes a model self-report sufficient. No device command has been executed during this source change.

## Use

Freeze a new core-suite-v2 plan using --drivers pointing to this entire directory. Keep all top-level .py/.json files together. An old plan pins different driver bytes and must not be reused or edited. The independent core-suite-r2 source is unchanged. Previous acceptance.json and collection.json remain their original verdicts; any later offline compatibility audit must be a separate report.

## Host validation

- Independent drivers: python3 -m unittest test_phone_acceptance test_phone_suite test_phone_inventory: 108 tests passed.
- Frozen code8 tools: python3 -m unittest test_model_profiles: 3 tests passed. The copied model_profiles.py has exactly the same bytes. This test references adjacent Java/native source, so it runs in the complete frozen source tree, not this standalone driver bundle.
- Unchanged core-suite-r2 with HEPTA_CORE_TEST_DRIVERS set to this directory: python3 -m unittest test_core_assertions: 35 tests passed.

The initial combined test invocation in this standalone directory reported one missing-adjacent-source error in test_java_native_allowlist_pins_agree. It was resolved by running those unchanged source-aware tests in the complete frozen code8 tree and independently checking the copied model profile bytes; no test was disabled.

No Android app rebuild is needed for this host-only compatibility change.
