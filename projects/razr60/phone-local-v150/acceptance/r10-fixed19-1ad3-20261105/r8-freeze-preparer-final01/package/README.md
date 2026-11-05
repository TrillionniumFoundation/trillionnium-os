# Actual adoption to R8 freeze preparation

This host-only entry turns a completed actual adoption into the original reviewed R8 freezer's source binding, input JSON, and exact execution arguments. It does not create the R8 runtime, start a service, access a phone, create a task nonce, change policy, or claim a case pass.

The reviewed dependencies are fixed:

| Dependency | Bytes | SHA-256 |
| --- | ---: | --- |
| R8 freezer source | 35375 | `62bcfb5a3ece55526d6e3e5c4c5158426d0e0119b5a04d4754cc7903434ea509` |
| Original freezer input template | 8368 | `debd3165e14bf357f13bfa3b997ea3bb0b23e5d2bb4a0a8b54078477deff2934` |
| Independent verifier | 126796 | `74f4c89b32b36b074971b247de1951962b45384ef821330b94656d144e512152` |
| Actual applied verifier retained in provenance | 124306 | `5cd18af19e1cd4cbe98542996fa41960bc36f697c6687ce201312b8ceda91c00` |

All production dependency paths are the already reviewed canonical Mac paths under the original project. Source copies included here are review references; the preparation entry reads the fixed canonical originals when explicitly executed.

## Input and execution

The entry takes only:

- `--policy-adoption-desc`: JSON containing the actual completed adoption file's exact `path`, `bytes`, and `sha256`. A preview or `policy-adoption-inputs.v1` record is rejected.
- `--out`: a fresh direct project child named `native-guard-property-r8-freeze-actual-<suffix>`.
- `--execute-host-preparation`: explicit host preparation. Without this flag the entry returns a zero-I/O preview; it does not even parse the adoption descriptor.

Use `/usr/bin/python3 -I -B` followed by `source/prepare_actual_r8_freeze.py` at the Root-staged path and these arguments. The adoption descriptor must come from the actual successful adoption writer result. Neither a guessed policy hash nor the offline candidate is accepted as a substitute.

Recommended fresh source output:

```text
/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-property-r8-freeze-actual-1ad3-01
```

The fixed runtime destination remains:

```text
/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1/native-guard-r10-r1-operator-r8
```

If the fixed runtime destination already exists, the preparer rejects. Preserve and inspect that original generation; this tool does not choose another runtime namespace.

## Exact derivation and original preflight

The entry reads `actual_export` and `root_scope_decision` from the actual adoption. It reads the actual exported bytes and derives the new combination by changing only `live_policy_sha256` in the exact canonical parent combination. It computes the combination SHA from those new bytes.

The completed `FINALIZATION` has exactly the original fields:

```text
schema
scope_decision
policy_adoption
verifier_source
actual_export
combination_sha256
```

Only the `FINALIZATION` assignment RHS changes in the freezer source. Reversing that assignment must reproduce all 35375 original bytes and SHA62bc. The generated input JSON changes only the original template's `finalization` value; its whole inverse is also checked. The input's fixed history, source manifests, shared17, and runtime destination remain exact original values.

Before creating the output package, the preparer calls the derived freezer's unchanged `build(plan, raw)` function once. This original read-only factory independently calls74f4 `verify_adoption`, consumes the complete actual offline/live/post proof, validates the fixed historical chain, checks the reviewed source gates, and constructs the prospective Root3/runtime32 generation in memory. No freezer `main()` is called. A failure at this stage creates no output package.

The pure derivation helpers and local fixture tests do not independently qualify an adoption. Only the complete original build preflight authorizes publishing the prepared source package.

## Output and the next exact entry

Successful preparation writes a new source package containing:

- The bound `source/freeze_property_runtime.py` and original62bc reference.
- `FINALIZATION.json`, `FREEZE-INPUTS.json`, and the original input template reference.
- `COMBINATION.preview.json`, the original build derivation, and predicted runtime/root/combination descriptors.
- The complete original read sets, source increment, preparation derivation, source manifest, and result.
- `EXECUTION-ENTRY.json` with exact `preview_argv` and `execute_argv` arrays.

The preparation state is:

```text
ACTUAL_ADOPTION_AND_ORIGINAL_FREEZER_BUILD_VERIFIED_NO_RUNTIME_CREATED
```

Root then executes the `execute_argv` from `EXECUTION-ENTRY.json`. It is the unchanged original CLI:

```text
/usr/bin/python3 -I -B <new-source-package>/source/freeze_property_runtime.py
  --inputs <new-source-package>/FREEZE-INPUTS.json
  --inputs-sha256 <actual-generated-input-sha256>
  --execute-host-freeze
```

The original freezer rechecks all its inputs, creates its fixed output once, reads every output back, and emits `FREEZE-RESULT.json` with state `REVIEWED_PROPERTY_POLICY_R8_HOST_SOURCES_FROZEN_NOT_PHONE_QUALIFIED`. Only that actual result can feed the already prepared NEG01/02 plan helper or `prepare_final_cascade.py`.

## Preserved boundaries

The generated freezer keeps Root3, runtime32, the131072-byte verifier limit, the complete fixed historical ancestry, shared17 source bytes, and all original policy/adoption gates. Applied5cd remains the actual phone provenance; independent74f4 remains the downstream host verifier. The actual policy is always derived from `adoption.actual_export`, with no fixed candidate-policy assumption.

The ten local source/interface checks cover descriptor rejection, source drift, original metadata and symlinks, zero-I/O preview, actual-export-driven derivation, exact source/input inverses, unadopted-input rejection, verifier identity collision, and original build-before-write ordering. Their synthetic extraction fixture never invokes the actual verifier, original build, freezer main, or any phone operation.
