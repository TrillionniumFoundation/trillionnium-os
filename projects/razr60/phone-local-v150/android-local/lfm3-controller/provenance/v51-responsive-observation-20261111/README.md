# v51 observer host evidence

Candidate is based on v50 `9ecf87f313ef08cfd2f963671a19eb2358cebbfe`.
These are retained host checks with explicit fake Android/model IO, not Android
compilation, installed-app qualification or physical-phone task results.

The final full gate has 100 successful stages and 366 stable source inputs,
using JDK 17 and the strict Java 8 API gate. The observer fixture passes 28 cases.
Eight capture-event cases keep graph identities unchanged while target/other
display events occur during screenshot callback, copy, PNG encoding or hashing.
The same new fixture compiles the pre-fence source and then fails the target
event assertion; the fixed source passes. A separate scheduling negative control
shows the old v50 path failing main-looper heartbeat/deadline progress under a
blocked graph read while the worker-based candidate progresses.

The receipts pin exact tested source. Later Python acceptance-tool changes need
their own validation and must not silently inherit this source-map receipt.
No historical failed phone task is reclassified. Private device records,
screenshots, device identifiers and signing material are excluded.

## Final v6 acceptance-tool validation

`HOST-CHECKS-V6-ACCEPTANCE.json` is the final r2 gate for the later Python
acceptance changes: 100 successful stages, 367 stable source inputs and 289
Python-tool tests. `HOST-CHECKS-V6-ACCEPTANCE-R1.json` is retained as the earlier
gate before the independently discovered journal-gap fix; it is not the final
acceptance-tool validation. Android build inputs remain the same 182 files as
production commit `b4ff6d2c0b09208d341cacf8fc1cac18489c9cfd`.

The runtime configuration candidate reproduces the latest retained configuration
bytes for Qwen3.5-4B Q4_0 / NPU / 8192 / four threads. Saving this candidate does
not change a phone setting, establish a fresh installed-state read, or identify
a same-phone winning model.
