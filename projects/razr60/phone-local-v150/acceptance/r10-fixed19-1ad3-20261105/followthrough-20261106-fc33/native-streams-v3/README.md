# Native consumer v3: trusted request, configuration and observation binding

This is an isolated host-reviewed candidate for the complete 15-file RAZR60 provider source tuple. It preserves the frozen R4 originals and the earlier native v1/v2 candidates. It does not adopt an installed runtime, grant current phone business qualification, or close whole NEG-10/11/12/13/14 cases.

## Exact source scope

Five files differ from both the original R4 tuple and native v2. All ten remaining production files are byte-identical. The daily module changes exactly four existing dependency SHA256 literals. The builder verifies complete byte inverses for every changed file, parses all 15 Python files and checks all 14 daily dependency pins.

| `daily_phone_local.py` | 22059 | `a16be75d5a47a86a7c0d222dc95e8b2373017b3291ce644864e2dd3b763447b8` |
| `phone_local_tools.py` | 13927 | `2d0c9cc8f1ff0c643aab3daeef07c12e84541f1c2f0bfd13c8043c5c8fa58930` |
| `phone_observation_tools.py` | 55981 | `4f95178996a2d7a604ae56eecd0f7725657222783f5cab5a7ff868f85a8cd086` |
| `provider_codex_host.py` | 41618 | `0ea72f9e38307055ead790aa5828143c4ba431ae33c8e44e19c5893073ade5fa` |
| `provider_phone_local.py` | 70303 | `0c04bbd0f2d8f88a0795776a23a6cb34bf5f9a88aabc09e8aa3c3ff34c534bee` |

The candidate pin manifest is 8,768 bytes with SHA256 `168cbbb9c49e86613622dfe6ce682516847cc856086b3369909e923ae8007d68`. It contains both complete source sets. `reference/native-v2/` preserves the five immediate parents; `patches/` contains each exact v2-to-v3 change.

## Consumer changes

`phone_observation_tools.native_bound_call(call, scope)` accepts the qualified argv-only shell/ADB shape and the five fields of an accepted turn. It independently reconstructs the normalized direct-request preimage and configuration fingerprint. The qualified configuration is the reviewed owner-open default executable, `/bin/sh` or `adb`, with null configuration generation.

The mapped wire call now carries all three declarations: `config_generation`, `request_sha256` and `binding_fingerprint`. Existing complete declarations must match the recomputed values; partial or changed declarations are rejected. Reviewed Rust producer admission independently checks them against the actual active turn/configuration before spawning. This package does not claim that a new physical dispatch with these declarations has already run.

`PhoneTools.dispatch_call` only upgrades an exact mapped base call to its stored complete call, or accepts that exact complete call. Changed argv, targets, partial declarations and wrong declarations fail before a local frame is written. The expansion happens before PhoneLocalAdapter's existing exact-mapping and ledger reservation gate. CodexAdapter also expands before serialization, dispatch intent and its frame write. The existing generic unmapped Codex path remains unchanged; PhoneLocalAdapter still requires a typed mapped record. No executor qualification gate is removed or replaced.

All eight semantic-parser callsites pass the existing saved mapped call and its accepted scope. The parser checks the current observed envelope, registry, six-field event records and eight-field terminal. It retains v2's trusted target binding, exact PID/u64 types, sequence/lifecycle order, terminal field types, canonical base64, lengths, zero exit, no signal/error/truncation and empty stderr. It additionally verifies:

- Canonical request SHA256 against the accepted scope and complete trusted mapped argv.
- Configuration fingerprint against the qualified source configuration.
- Exact generation type and actual registry allocator range, 1 through 2^64−2.
- ObservationDigest reconstructed from every decoded output byte and all fields included by the real producer algorithm.
- The complete registry Terminal receipt, including its generation, terminal class, code/signal, computed observation digest and stream counts.

An unknown current schema fails closed. Historical minimal terminal compatibility remains in the preserved v1 source; v3 deliberately requires the observed current full schema.

## Actual archived formula checks

The tests read pinned copies from the existing NEG01 archive, SHA256 `60904669449d1cc6a66707e6efc3cbaf98d22c4260d90255309dab277df3d978`. They independently matched all three preimages and the full registry terminal strings for its capture and guard. The capture parsed successfully; guard exit 70 remained unsuccessful in the production semantic success parser.

| Original | Request SHA256 | Observation SHA256 | Generation |
|---|---|---|---:|
| Capture | `a14dd1639fb18afe951f3c573d937da8dac9b21a42bb248c86aa7858d5149929` | `43c402751c27b374286dfa9d39fc16cf52ae802e4c5fd2d3b4bd52506b541542` | 73 |
| Guard | `bd7517a414e889fa1d2ae747dff9a421212661a3f56ad1c8b11917b143c679f8` | `34c8404d0c79c322dae8b0dfc0488e8170010b539e7f63da15e63e712a634889` | 74 |

Both actual configuration fingerprints are `47c726ccbb9e433417f5f8bbe0a18aef909d93046dc58d398143e3d24db1de5d`. The independent preimage transcription follows the reviewed Rust primary sources in repository commit `744fc422a28bd6f505701503bf0d113ab49d4634`, specifically provider-jsonl protocol normalization, tool-bridge ObservationDigest and call-registry allocation/terminal handling.

The earlier v2 audit reproduced ten unchecked metadata mutations against copies of the actual capture. Its original result and executed input program are retained. That audit is evidence of the prior gap, not a v3 pass.

## Actual host runs

The following are separate scopes. Their counts are not added into a new acceptance-case total.

| Run | Actual observations | Durable job | Result SHA256 |
|---|---|---|---|
| Shared business/admission | Same 14 existing scenarios; eight business postcondition cases, four scope/nonce refusals, actual O_EXCL two-thread competition and old-identity admission refusal | `1a1b18878e5-fc05-7966` | `0250099e4209e1f13d5def2b38298826b3e574e3adf95048986f45f3362a75f2` |
| Native consumer | Preserved 73 parser and 12 outer-receive/semantic/business controls; 40 trust parser cases, 11 trust corruption consumer chains, nine dispatch binding cases and one actual ledger binding check | `1a1b18b95c3-fc05-7980` | `6c62408d6d19460757d0160ac49aaf3b2fa3b1e1673a5220bbf4ba1a1e945968` |
| Selected NEG10/14 | Four real map refusals, eight filesystem checks, one FD/thread/child-CPU/owned-temporary-tree baseline check | `1a1b19980ee-fc05-79c6` | `1a0e24bb1d9caa9e7b95669bdedea9470ff769f4ac3335b0aef1e898cc0d4d90` |

All three authoritative statuses report succeeded, exit code 0, durable complete output, no stderr and no truncation or timeout. The first selected-guards MCP launch and a broad job-list query timed out. Their original errors are preserved. The exact same stable operation key/request was reconciled; its returned acknowledgment reported `reused:false` and the job identity above. The create-only script and output then completed. No phone/model/native operation occurred.

All generated owner requests and native/public receipts are explicitly synthetic. Real production functions, pipes, files, fsync, locks and O_EXCL races execute. Local tool.call frames end in owned regular files without an attached executor. The actual ActionLedger/LedgerPrefix check uses an explicitly synthetic sidecar-shaped record and proves the stored wire-call hash includes all three dispatch declarations. No full PhoneLocalTools/PhoneLocalAdapter instance is constructed, and validate_executor is never bypassed.

The selected filesystem cases use two actual renames, missing canonical/unknown temporary/missing parent, a symlink and real ENOTDIR. EACCES is explicitly a synthetic callback whose identical exception object must propagate. No full capacity-exhaustion, process-group cleanup or whole-runtime memory-return claim is made.

## Reproduction

The published candidate includes every production source needed for the three public fixture tests. Run each command with a fresh absolute output directory:

```sh
python3 -I -B test_shared_business_admission_v3.py --out /absolute/fresh/shared
python3 -I -B test_native_streams_v3.py --out /absolute/fresh/native
python3 -I -B test_selected_neg10_neg14_v3.py --out /absolute/fresh/guards
```

The native test reports archived-actual checks as unavailable when the private NEG01 originals are absent. On the preserved operator package, `--require-actual` requires all 13 exact originals and their pinned schema manifest. The public fixture tests do not fabricate that private evidence.

`build_candidate.executed.original.py` preserves the exact source-derivation program used on the operator. Its final attachment step requires the separately retained private NEG01 originals from the full v2 operator package; those private files are intentionally outside this public package. The public complete source sets, exact transformation data, inverse checks and all v2-to-v3 diffs remain reviewable.

`HOST-OUTPUTS.tar.gz` contains 520 actual host output files totaling 1,454,312 original bytes and an embedded complete output manifest. Every original was read with stable full metadata and SHA256 and rechecked after archiving. The output manifest also records the source directory names. Private NEG01 raw originals are not included. Top-level result copies preserve exact original bytes.

## Boundaries and next qualification

Generation is allocated by native claim_spawn after dispatch. The current protocol provides Python only the completed tool.result; it supplies no independent pre-spawn generation anchor. The consumer checks allocator range and complete receipt/digest consistency. Coordinated rewriting of generation and all matching unsigned receipt/hash fields remains indistinguishable without a new independent anchor or MAC. The tests explicitly demonstrate and label that boundary.

The producer's ObservationDigest includes terminal elapsed_ms but excludes event-record elapsed_ms. V3 checks the latter's exact u64 type/range and follows the actual digest definition; it does not claim a hash binding that the protocol lacks.

No frozen source seal, historical qualification, runtime package, phone state or accepted production identity is changed here. Actual source propagation must preserve the new full call through runtime instrumentation. If an approved guard instrumentation prepends `set -x; `, it must remove only the three old declarations from its trusted call copy and call `native_bound_call` again with the same accepted scope. The emitted call must retain the new declarations. Current NEG01/NEG02, business E2E tasks and the remaining physical negative tasks still need their own actual closed evidence under the final adopted combination.
