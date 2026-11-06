# Native v2: current-schema consumer candidate

## Status

This package is an isolated host candidate, **not an adopted production combination** and not a complete NEG-11/12/13 closure. The frozen current combination and the earlier native-v1 candidate remain unchanged.

The complete 15-file candidate has three changed files:

| File | Bytes | SHA256 |
| --- | ---: | --- |
| daily_phone_local.py | 22059 | 203862a29023c827804d4e2a7ccc0217f917f789f49272dc09f4ab64ec029027 |
| phone_local_tools.py | 13846 | 6621f3463e525aa9eedeff927671045daca1065b3210ac0e34e0c2e9867afcd2 |
| phone_observation_tools.py | 46743 | ec015260f64e2c61c8f9953f6abe0d8dc4a7a62ce86943ce3c9cfcd250c35162 |

The full15 pin manifest is `CANDIDATE-PINS.json`, SHA256 `8c15ed8eabefe9c2587cd4bbadd2738461b592eb30b103bd0c52ac14de83114a`. The other twelve sources are exact copies of the reviewed current source set.

## Why v2 is needed

The preserved v1 candidate correctly rejects event-order errors and Python bool/float terminal equality aliases, but does not validate target_id, started.pid, or elapsed_ms. Its retained historical minimal-terminal compatibility is explicit. The earlier metadata coverage package records seven unchecked metadata examples. Those observations are retained as findings; they are not silently replaced by this candidate.

The current NEG01 archive was read without issuing a phone or native request. Its exact archive is 5,855,216 bytes with SHA256 `60904669449d1cc6a66707e6efc3cbaf98d22c4260d90255309dab277df3d978`, bound by the preserved CLOSURE `cdd271173ae84ea9d52a844eed86b08fac0def4bb6e175da3edcb6777728d288`. Thirteen original members were retained privately. The public schema report provides their exact byte/hash descriptors without republishing the screenshot payload.

The actual capture and guard calls are shell.exec records with only argv, call_id and tool; target and target_id are omitted. Their original event records contain exactly six fields, target_id is null, and their terminals contain exactly eight fields. Capture exited 0 with 71,365 stdout bytes. Guard exited 70 with stderr and is correctly rejected as a successful semantic result. These are historical NEG01 originals, not a new current UI execution.

## Changes

- `native_streams` receives a mandatory trusted `expected_call`. All eight existing consumer callsites pass the wire_call already saved by the real map function. No persistent semantic record field is added.
- Event target and registry routing identity must match the mapped call, including an omitted target resolving to null. A result whose wrong targets are internally consistent is still rejected.
- Event records and terminals must match the observed current field sets. Unknown event kinds/fields and legacy minimal terminal shape are rejected by v2.
- Started PID is an exact positive u32 integer; event and terminal elapsed_ms are exact u64 integers. A successful exited/0 terminal requires signal:null, error:null, and output_truncated:false.
- The existing event order, scope/sequence, output lengths, full terminal value/type comparison, and stderr rejection remain. Output base64 must be canonical.
- `phone_local_tools.py` changes only its existing callsite. `daily_phone_local.py` changes exactly two dependency hash strings. Its original fourteen-parent verifier executes normally.

The existing PhoneLocalAdapter dispatch gate already compares the outgoing call with the stored wire_call. It is not weakened or bypassed. The runtime client `tool_client_r6.py` is unchanged.

## Actual host verification

| Check group | Actual result | Meaning |
| --- | --- | --- |
| Same 14 shared business/admission scenarios | 14/14; job `1a1b154242e-fc05-77c6` succeeded, exit 0 | Same scenario IDs as v1, rerun against full15 v2; not added to an acceptance-case total |
| Current-schema parser regression | 73/73 | Positive controls, event/terminal types and shapes, trusted target binding, original v1 rejection cases |
| Outer receive → semantic parse → business gate | 12/12 | Production CodexAdapter receive/emit and PhoneTools map/prepare; bad metadata cannot create the required fact |
| Archived NEG01 originals | Verified read-only | Original capture accepted, original failing guard rejected, all-wrong-target copy rejected |
| Resource/audit checks | Restored; no denied attempts | File descriptors, threads and child CPU return to baseline; network/process/outside writes denied |

The parser and consumer job `1a1b15bf0df-fc05-77fc` also succeeded with exit 0, complete durable untruncated output. Raw controller texts and exact run results are preserved under `evidence/`.

All newly generated owner, native and public receipts are explicitly synthetic. The twelve consumer tests emit tool.call frames into their own regular files; no Host executor is attached. Actual native dispatches, phone calls, and model requests are zero. A full PhoneLocalAdapter or DailyAdapter is not constructed, and validate_executor is not patched or bypassed. The complete-control fixture's business_verified flag is a fixture result, not physical business evidence.

## Reproduce

Use a fresh absolute output directory for every run:

```bash
python3 -I -B test_shared_business_admission_v2.py --package-root /absolute/package --out /absolute/fresh-shared-output
python3 -I -B test_native_streams_v2.py --package-root /absolute/package --out /absolute/fresh-native-output
```

The public package reproduces the synthetic parser/consumer checks. The second script reports actual-original verification as unavailable if the private original set is absent. Our recorded run used `--require-actual` and verified all thirteen pinned originals; use that flag only with the preserved exact private set.

`build_candidate.py` can reconstruct the sources and deterministic source pins from the prior complete `neg12-13-host` package into a fresh output directory. It checks every source preimage, all fifteen syntax trees, and all fourteen daily dependency pins. Original sources are rechecked afterward. Source and harness diffs are under `patches/`.

## Limits and remaining work

Registry call/tool/target identity is checked. This parser does **not** reconstruct the canonical request digest, configuration fingerprint, generation, or observation_sha256. Those fields are not claimed covered by these tests. This package validates the observed current event/terminal schema, not every possible native protocol schema.

The local consumer tests exercise the real shared base adapter and semantic/business functions, without a full phone-local adapter instance or an installed runtime. They do not establish current phone effects, source activation, launch/focus correctness, cancellation/timeout behavior, or a final frozen formal combination. Source propagation and final physical qualification remain separate work.

The v1 package and its legacy-minimal positive control remain preserved. No historical SOURCE-SEAL, current COMBINATION, accepted production identity, or old successful NEG01 evidence is rewritten.
