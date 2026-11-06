# Selected NEG-12/13 checks on the complete current source candidate

This package records a real Mac execution of the shared business/admission implementation with explicitly synthetic owner requests and native/public receipt fixtures. The run passed 14 selected host scenarios. It does not close whole NEG-12 or NEG-13, deploy a provider, or adopt a source combination.

## Complete source provenance

The package preserves all 15 current production Python originals and all 15 candidate files. Originals were read from the actual frozen component's shared/provider/source directory using O_NOFOLLOW, stable full9 metadata, exact byte counts and SHA256. The original files total 362872 bytes.

Only phone_observation_tools.py and daily_phone_local.py differ. Their candidate hashes are respectively 22580b8aa22d5c0ab4040888872e642a5176042023dd7bcf50e67efe51248409 and 689db3908014940a1e39689b966d30ab16ac6f9c0d7892becf1718b9840c824f. These are the unchanged candidates in the sibling native-streams package, committed at 095a0604ce94d0f3f33819ef8df95478ca0223e8. All other 13 sources retain their original bytes.

CANDIDATE-PINS.json is 6534 bytes with SHA256 ccdb924f7b8e1556008a443f8412b4d35604e884dc171c9e7d855299f40b1fb4. Its current-combination input is the original 02c2a26af79e367afe48cb1bc378808f3c5a32800548498a0262ea0265c9f708. This new host pin manifest does not replace the historical SOURCE-SEAL or constitute formal adoption.

The script imports all 15 complete modules. Importing daily_phone_local executes its original verifier of all 14 dependency hashes. It verifies all original and candidate bytes again after the run. No AST replacement or monkeypatch of production functions occurs.

## What actually ran

The real CodexAdapter receives turn.start through an OS pipe, persists an exclusive accepted-identity claim, loads a request-bound v150.3 template, and constructs the real PhoneTools. Real mappings are recorded but never dispatched. Synthetic receipt bytes pass through the real native_streams, PhoneTools.prepare, public/return parsers, and task postcondition evaluator. CodexAdapter.emit persists the actual business outcome, terminal, and outgoing JSONL to private host files.

| Selected business scenario | Actual outcome |
| --- | --- |
| Input mapped without a confirmation receipt | turn.fail, missing input |
| Input confirmation lacks exact readback | Real parser rejects; turn.fail, missing input |
| Public read mapped without a receipt | turn.fail, missing public |
| Public receipt contains the wrong text | turn.fail, missing public |
| Return mapped without a receipt | turn.fail, missing return |
| Return receipt reports a different launch Activity | Real parser rejects; turn.fail, missing return |
| All fixture facts present but coverage is partial | turn.fail, business remains false |
| All fixture facts present with complete coverage | Control produces turn.complete within the synthetic fixture only |

The fixture text contains Chinese, emoji and a literal LF. This tests the shared parser path; it is not an E2E-02 phone result. Each scenario retains its synthetic owner frame, exact template, mapping, synthetic native/public receipts, and unchanged production-generated output files. The complete control can contain business_verified=true inside its fixture outcome; the input declaration and this package explicitly exclude phone business credit.

The template tests use current v150.3 request/app scope. Missing nonce, duplicated nonce, a wrong request digest, and a wrong app-scope owner digest all reject without consuming the binding. Wrong session/profile scopes leave the original template and binding directory unchanged.

Two actual threads enter load_contract at a barrier and contend for the real O_EXCL binding path. Exactly one wins; the other gets the original ProviderError. Reusing the winning identity, replacing its stream, or using a new semantic turn with the old nonce cannot consume it again. Separate real pipe admissions using a previously accepted failed-turn identity, including a replacement stream, reject before mapping or outgoing frames. Original claim and binding bytes remain unchanged.

## Reproduce

Use Python 3 and a directory that does not exist:

    python3 -I -B test_shared_business_admission.py --out /absolute/fresh-host-attempt

The output parent must be canonical. The script pins the full source set, uses only private fixture directories, and registers an audit hook that rejects network, process launch, and writes outside the selected output. It imposes a 50-second test deadline. A supervisor also bounded the recorded Mac process group to 60 seconds. No production server or completion loop starts.

Recorded run: job 1a1b128da9b-fc05-765f, exit 0, complete durable output and no truncation. The script is 35757 bytes, SHA256 3269dbc7da98ab00ee60f1a458c71244ff312b17e541314b54e20c0ebec92bc7. The exact original result is 79185 bytes, SHA256 7b5061bcfc5059c1208d89600b58e8bc1b897dc6d04d9d38cecce3b133d8c6ce. FD/thread/child-CPU baselines returned; no audit-denied network, process, or outside-write operation was attempted.

evidence/HOST-ORIGINALS.tar.gz retains every original file from the closed attempt. Its file manifest enumerates exact paths, sizes and SHA256. evidence/RUN-RESULT.original.json is an unmodified copy of the actual result. The archive metadata is deterministic packaging metadata; the member bytes are original host evidence.

## Limits

The PhoneLocalAdapter and DailyAdapter classes are imported but not instantiated. The Mac does not satisfy the fixed P4 executor-client path/hash gate. That gate is not patched, monkeypatched, skipped or replaced with a fake client. The tested CodexAdapter business/admission methods are the shared implementation used by PhoneLocalAdapter, but the full local-adapter execution path is outside this run.

All owner and receipt data are marked synthetic. Zero phone calls, model requests, native tool frames or executor dispatches occurred. No physical UI receipt, installed runtime, pending-effect recovery, formal source propagation or production adoption was tested. The original r7-r3 host runner is retained solely as provenance; its historical seal and main entry point are not rewritten or run.

Current native_streams still has explicitly untested full-wire-schema fields beyond the earlier 42 checks. This package preserves that committed candidate and must not be presented as full NEG-11 qualification. Any separate wire-hardening investigation remains a separate candidate decision.

See LIMITS.json, DERIVATION.json, CANDIDATE-PINS.json, and SOURCE-MANIFEST.json for machine-readable scope and exact artifacts.
