# Warm task acceptance and action binding — R5 review candidate

This is an **unadopted host-only review candidate**. It combines R1–R5 repairs for the exact observed Code29 acceptance tools and a separate import-closure patch for the reviewed homepage oracle. It has not changed shared tools, built or installed an APK, operated a phone, or qualified native inference. The publication parent is a storage and review location, not the production source baseline or a statement about the installed phone version.

## What this candidate fixes

The original collector treated a retained task worker too much like a process that exits after each inference. R1/R2 collect and validate all task-owned requests, the worker generation's terminal receipts, and its shared accelerator log. Request ownership is discovered independently of schema validity, so an owned failed or unknown-schema request cannot disappear from the request count. Embedded receipt comparisons distinguish JSON booleans from numbers while allowing ordinary numeric serialization such as `1.0` versus `1`; protocol integer fields retain their explicit integer gates.

R2 still rejected valid warm actions because `phone_suite.model_action_binding` accepted only the oneshot native-result schema. R3 added complete warm generation verification at this call. R4/R5 then closed concrete review findings: missing or contradictory controller steps, unbound terminal decisions, foreign cached helper imports, a base PASS that contradicted the task terminal, omitted support for the real `wait` action, and missing checks for the producer's stable successful-done state.

The existing oneshot branch retains its native-output constraints. Task submission, replay policy, Android permissions, model configuration, and app execution code are unchanged by this capsule.

## Warm evidence required for every action binding

`model_action_binding` keeps its existing call signature. Its warm branch obtains the complete evidence from the supplied case directory and rechecks the following:

1. `acceptance.json` and `collection.json` agree, the collection is complete, the original instruction and task identity match, and the collected terminal is the one retained by the case report. Warm mode has independent app, terminal, and collection anchors; changing only a selected result's schema cannot select the old oneshot path.
2. The recorded file inventories match actual files, byte counts, and SHA256 hashes. Extra or missing request directories, extra or missing collected files, duplicate entries, unsafe paths, and symlinks fail closed. Reads are bounded to 16 MiB per file and 128 MiB per call; these are verifier limits rather than device memory measurements.
3. Every request has one step-model journal. Controller model steps are contiguous and requests follow step/attempt order, independently of random directory names. A corrected model attempt preserves and validates the rejected first request.
4. Every request passes the task/generation/PID/sequence contract and its embedded native receipt agrees. The verifier rechecks native bytes, prompt/system hashes, the exact owner instruction and before-observation identity, controller grammar, observed package, approved model/runtime metadata, context budget, and the same generation's actual positive accelerator log. Summary success flags do not replace these source checks.
5. Every controller step has a complete before/action/after inventory. The recorded action must equal the exact decoded output of that step's last model attempt and use its run and observation identity. Accepted, stale, and dispatch flags must be coherent. Read-only `find_app` retains its read-only classification.
6. `wait` is supported without being added to dispatched `EFFECTS`. Its receipt must say it was not dispatched, and `duration_ms` must be an exact integer from 100 through 2000. A changed or out-of-range duration cannot qualify even if summary hashes are resealed.
7. The task terminal identifies the final complete step and its after-observation. A base PASS requires a successful task terminal, `model_reported_success=true`, and a final native `done` decision with `status=success`. A failed base remains failed; complete earlier action evidence can still be used for diagnosis.
8. A successful done has the producer's four actual serialized state fields, with valid types and equal before/after values: `package`, `window_id`, `rotation`, and `observation_state_sha256`. The last field is the serialized `PhoneObservation.treeSha256` used by the controller's own completion check. This does not introduce a new page classifier.
9. The full session contract accounts for all requests in one generation, successful teardown return values, an app-recorded observation of actual worker exit with code zero, and the app session receipt hash in the task terminal. A request from a retained worker still must not claim that worker has exited.

Every binding call builds a new bounded byte snapshot. It does not cache a successful approval for a later call. These checks establish consistency of captured evidence; the synthetic tests do not constitute evidence that a physical worker exited.

## Core oracle and frozen dependency imports

The reviewed core's three binding call sites already provide the complete case directory: the homepage terminal `done`, dispatched/read-only events, and the initial precondition. The core case evaluator passes the same directory to `action_sequence`. No call signature changes are needed.

The separate `core-driver-closure.patch` changes only `core_phone_suite.load_drivers`. It checks the origin of every Python module in the frozen driver inventory before and after importing the entrypoints. A correctly pinned file on disk no longer permits another directory's preloaded `warm_action_evidence` or `warm_receipts` module to be used. The two main imported modules are still checked separately. This is an origin and inventory check, not attestation of arbitrary in-memory Python code.

Tests invoke the actual core homepage, initial-precondition, read-only discovery, ordered action, case-verdict, and driver-loading code with synthetic warm evidence. They include a complete `wait → done` binding and a real core `open → wait → done` case; only `open` counts as a dispatched effect. Missing exit evidence, missing final controller records, contradictory terminal data, and foreign helper imports are rejected. An existing failed verdict is not upgraded.

## Patch contents and exact baselines

`acceptance-evidence.patch` is the complete **Code29-to-R5 tools patch**, covering eleven files and all R1–R5 changes. `core-driver-closure.patch` applies to the exact output of the sibling homepage oracle R2 patch. Its before SHA is `d1bae5a4a43b92d3b7bb0b87664449107777dc515df45c31848265f7d8d35db4`; its after SHA is `87cf221f07b0a36395e0760123f782ecab210d42a5b7f306146755d7d36e04c1`.

`BASELINE.json` records the Code29 manifest identity and all existing-file before hashes and output hashes. Both patches were applied to disposable copies and every resulting hash was checked. Seven complete test files and the new helper are included under `tools/` for review; they are byte-identical to the cumulative patch's outputs. Existing production tools and core modules are represented by diff hunks, not full file copies.

R1, R2, R3's 171-pass version, and R4's 178-pass version remain preserved with original log and patch hashes. This capsule contains only the final R5 candidate. No private phone XML, screenshots, WMS captures, prompts, model responses, app inventories, or device identifiers are included.

## Reproduce the host validation

Use fresh isolated source copies with the hashes recorded in `BASELINE.json`:

1. Apply `acceptance-evidence.patch` once to the matching Code29 source root.
2. Prepare the reviewed core by applying the sibling homepage capsule to its matching baseline. Copy that capsule's synthetic `test_core_assertions.py` into the prepared core directory.
3. Apply `core-driver-closure.patch` inside that prepared core directory. Verify the recorded output hashes.
4. Set `HEPTA_WARM_CORE_SOURCE` to the prepared core directory, `HEPTA_CORE_TEST_DRIVERS` to the isolated patched tools directory, and add the prepared core directory to `PYTHONPATH`.

From the isolated patched tools directory, run:

```bash
python3 -B -m unittest -v \
  test_phone_acceptance test_labeled_target_binding test_warm_receipts \
  test_warm_collection test_warm_collection_integrity test_phone_suite \
  test_warm_action_binding test_warm_core_integration \
  test_warm_terminal_closure test_warm_terminal_verdict test_core_assertions
```

The explicit core source is required: skipping an integration module does not reproduce the recorded result. The new tests construct fictional receipts, controller journals, windows and UI files and invoke the actual collector through a read-only file adapter that has no phone command method. They block ADB construction, socket connections and subprocess calls while checking warm binding and core evaluation. Required producer state fields are supplied during synthetic fixture construction; the verifier never invents missing fields in a captured case.

## Results and retained counterexamples

| Validation | Result | Scope |
| --- | --- | --- |
| Existing R2 related closure | 114 methods passed | Collection, receipt, grammar, runtime, oneshot action and failure gates |
| R3 warm binding regressions | 15 methods passed | Complete generation, corrections, NPU/GPU artifacts and rejection boundaries |
| R3 actual core integration | 7 methods passed | Homepage, precondition, discovery, failure preservation and source pin inventory |
| R4 terminal/import regressions | 7 methods passed | Complete controller journals, exact final decision and helper import origins |
| R5 verdict/wait/done-state regressions | 8 methods passed | Coherent base verdict, supported bounded waits and producer completion invariants |
| Existing synthetic core regressions | 35 methods passed | Reviewed goal-specific behavior remains compatible |
| **Final combined run** | **186 methods passed, zero skips** | Host-only verification |

The counterexamples were run before their corresponding fixes. Three complete warm positives failed on unchanged R2. Seven added R4 regression methods produced 21 failing assertions on preserved R3. The eight R5 methods produced 16 failing assertions and zero errors on preserved R4 production bytes; the only overlay in that replay was the new tests and their complete synthetic fixture fields. That last replay contains both erroneous PASS cases and valid wait cases rejected by R4.

`r5-host-pass.txt` is byte-exact. The published failure log normalizes scratch prefixes and abridges fifteen large repeated synthetic result payloads while retaining test/subtest identities, tracebacks, result differences, and failure reasons. `VALIDATION.json` preserves the original byte count and SHA256 alongside the normalized log's identity and records the fixture overlay. Earlier original logs and patch hashes are retained separately and have not been rewritten to obtain a newer version number.

The independent reviewer read the R4/R5 increments and the saved test results, found the identified changes addressed, and reported no new blocker in the reviewed increments. The reviewer did not rerun the tests. This is a limited source review, not formal GitHub approval or Android qualification.

## Remaining qualification limits

The current controller's stale-observation retry paths do not always publish a complete action/after journal. R5 deliberately leaves those cases **unverified**; it does not reconstruct a missing step, assume no effect, or replay a task. Producer instrumentation is needed before those paths can meet this complete-journal contract.

This work does not build or exercise Android, run a native model, select the best model, measure GPU/NPU utilization or throughput, or qualify background execution, screen-off behavior, offline isolation, sustained thermal/power behavior, or whole-phone usability. It cannot recover remote evidence that the collector never captured, establish atomic Android result publication or disk durability, or attest to evidence under concurrent hostile host modification. Existing frozen plans require a deliberate refresh over the reviewed tools and core source before a future run. No old failed phone case is upgraded by this candidate.
