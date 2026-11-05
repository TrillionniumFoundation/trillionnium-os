# R8 component, cancel and fault source finalization

This helper creates three new source packages from the exact reviewed prior packages and the **actual published final cascade**. It has no phone, subprocess, network, model, signal or policy-write entry. It does not award any acceptance case, reverify the complete policy adoption, invent a native scope, or reuse an old case as current evidence.

The original three packages remain unchanged. The generated component directory contains only its original eight manifest members plus `MANIFEST.json`; provenance and entrypoint information stay in the outer directory so the existing strict component verifier accepts the package inventory.

## Preferred execution after the actual cascade

Stage the source under the current project root and retain its supplied source manifest. Obtain the exact descriptor of the **actual newly completed** `r10-boundary-consumers-final-r8/DELIVERY-RESULT.json` from the cascade's original output. Root must already have independently verified the actual policy adoption with the reviewed original verifier.

```sh
python3 -I -B /absolute/staged/source/finalize_component_cancel_fault.py \
  --prepare-source-plan-once \
  --delivery-result-desc '{"path":"/absolute/actual/DELIVERY-RESULT.json","bytes":ACTUAL_BYTES,"sha256":"ACTUAL_SHA256"}' \
  --prepare-out /absolute/new/downstream-plan-directory \
  --output-root /absolute/new/downstream-source-directory
```

`ACTUAL_BYTES`, `ACTUAL_SHA256` and the paths are placeholders, not executable values. Plan preparation reads the original cascade receipt, adoption, actual policy, runtime manifest, final consumer manifest, consumer, readiness, acceptance manifest and unchanged materializer. It verifies all three original source packages and all dependency relationships, then writes:

- `FINALIZATION-PLAN.json`, containing exact descriptors for all seven current dependencies;
- `EXECUTION-ENTRY.json`, containing the complete concrete next command and the actual plan SHA;
- `PREPARATION.json`, binding the original cascade receipt, planned package pins and source-only scope.

The preparation directory and package output directory must both be fresh and separate. Run the exact entry from `EXECUTION-ENTRY.json`. Its form is:

```sh
python3 -I -B /absolute/staged/source/finalize_component_cancel_fault.py \
  --plan /absolute/new/downstream-plan-directory/FINALIZATION-PLAN.json \
  --plan-sha256 ACTUAL_PLAN_SHA256 \
  --execute-source-finalization-once
```

An optional `--validate-source-plan` invocation uses the same exact plan and SHA, reads and checks originals, and creates no output. Invoking the script without an action flag returns `SOURCE_ONLY_NO_INPUTS_READ`, even if a plan path was supplied.

The final output contains `component/`, `cancel/`, `fault/`, `originals/`, `DERIVATION.json`, `ENTRYPOINTS.json` and `FINALIZATION.json`. The last receipt and stdout return the three actual manifest descriptors. Reusing an output directory is refused. Input identity changes, extra output members, output path replacement and different output bytes are refused. Partial output is retained without an automatic retry.

## Exactly what may change

| Package | Permitted change | Preserved bytes and limits |
| --- | --- | --- |
| COMP01 / NEG03 | Seven RHS expressions in `component_source_context.py`: `MATERIALIZER`, `CONSUMER`, `CONSUMER_PIN`, `READINESS_PIN`, `RUNTIME_SHA`, `POLICY_SHA`, `ADOPTION_SHA`; corresponding interface paths/runtime pin and manifest rows | Direct return source `915f57d9…`, geometry fixture `3cbc0d9d…`, original protocol `c573959e…`, host negative reference, plan templates, all production source pins and the `b25125bc…` materializer pair |
| UI cancel | Shared active `CONSUMER_SHA`, `READINESS_SHA`, `POLICY_SHA`, `ADOPTION_SHA`; manifest dependency/derivation fields | The other seven source files, including actor `d973891a…`; original parent policy, configuration, service, production15 and sidecar pins; 8s / 12s limits; 262144-byte decompression and exclusive 65536-byte ADB limits |
| Signal fault | The exact same generated active bytes and manifest dependency/derivation fields | The other seven source files, including actor `cd5100c0…`; held-pidfd validation, original process identity/roles, original timeout ownership and no retry |

The source rewriter replaces only the selected AST RHS byte spans. It checks the complete remaining AST, compiles the new bytes without importing product modules, and preserves every other original byte. Both physical actor packages receive one identical active helper.

## Current dependency bindings

| Input | Read bound | Required relationship |
| --- | ---: | --- |
| R8 runtime manifest | 262144 bytes | Revision `r10-r1-operator-r8`, exact 32 members, actual policy and explicit adoption pins, actual combination flag |
| Final consumer source | 131072 bytes | `PACKAGE_SHA`, `CURRENT_POLICY_SHA`, `CURRENT_POLICY_ADOPTION_SHA` match the actual runtime, policy and adoption |
| Readiness source | 65536 bytes | `BOUNDARY_CONSUMER_SHA256` matches the final consumer bytes |
| Final consumer manifest | 262144 bytes | Schema `hepta.r10.final-boundary-consumers.v8`, runtime/adoption cross-links, exact consumer and readiness member descriptors and paths |
| Actual exported policy | 8 MiB | Descriptor equals adoption `actual_export`; an offline candidate cannot substitute |
| Adoption | 16 MiB | Fixed release/boot, explicit actual-export Root decision, comparison/scope/expectation/prior-boundary links, 44 explicit atoms, all admission/qualification booleans false |
| Materializer | 65536-byte read bound; exactly 24834 bytes accepted | Exact `b25125bc0e204ea7aefde6f2a17fa2fb8e5edf132a4b62dfbb546964c1c09290`; no source change |

The actual complete adoption proof is **not rerun by this helper**. It checks raw identity and selected consistency links only. The completed cascade itself was derived from an independently verified adoption; Root must supply that reviewed actual cascade descriptor. Nothing in this source finalization constitutes current READY, a sealed release, component qualification, native task qualification or business success.

## Execution entries and remaining evidence gaps

The generated `ENTRYPOINTS.json` includes concrete new host source paths, actual package SHAs, all actor CLI arguments and explicit missing stages.

| Case / layer | Existing entry | Required remaining work |
| --- | --- | --- |
| COMP01 host preparation and receipt verification | `component/source/prepare_direct_return_component.py --mode baseline-request\|prepare-return\|verify-return ... --execute-host-once` | Actual sealed release with new qualified NEG01/02; fresh operator identity; original baseline and return records. A Root once-dispatch, complete transport termination, restoration and final COMP01 closure assembler is not included. The host result always leaves case pass false. |
| NEG03 host fixture | `component/source/verify_unqualified_geometry_fixture.py ... --execute-host-fixture-once` | Six synthetic geometry mutations with actual production parsers and positive controls. `physical_test=False`. An actual external-display/rotation entry and independent physical input-rejection closure are missing. |
| NEG08/09 physical cancellation | Exact staged `cancel/source/cancel_native_once_r10.py --plan ... --package ... --package-sha256 ... --out /home/alex/razr60-local-model-v150/cancel-native-r10/<plan.label> --execute-once` on P4 | Actual new native task plan, READY and original five-field scope; preserved P4 UI helper/configuration; one selected-CAS Cancel action. The task/host assembler and independent complete-original late/global closure assembler are missing from this package. Actor success remains `physical_case_pass=False`. |
| NEG04/05/07 physical fault | Exact staged or inline `fault/source/signal_fault_once_r10.py --plan-b64 ... --manifest-sha256 ... --execute-signal-once` under reviewed native Android Magisk-root Python | Actual roles, carrier/task phase and held pidfd. NEG04/05 TERM the original carrier; NEG07 STOPs the exact sidecar worker and leaves cleanup to its original timeout owner. Final counters, transport termination, cleanup and independent physical closure are still required. Actor result remains `physical_case_pass=False`. |
| NEG04/05/07/08/09 host lifecycle layer | **No runner for these five original host-isolated acceptance cases is present in the reviewed three packages.** | Protocol `c573959e…` requires both `host_isolated` and `physical_native_task`. The retained `host_negative_runner.original.py` covers only NEG10–13. Transport fault regression tests cannot substitute for these five original lifecycle cases. |

No AC positive `KINDS` are extended to cancellation cases. CPU, P4 and phone collectors retain their own dependency finalization and complete-original verification requirements.

## Local checks and their scope

Run the portable source-only harness with the original package root (the Mac project root, or the local cache):

```sh
python3 -I -B ./test_source_finalizer.py --base-root /absolute/original-package-root --out /absolute/new/test-output
```

Eight checks cover no-read default mode; all exact baseline members; synthetic dependency cross-links and refusal of an unqualified materializer; actual delivery-result shape; byte-preservation boundaries; the existing strict component package verifier; create-only output; and same-byte input/output inode replacement. The fixture directories explicitly say `SYNTHETIC` and are not acceptance evidence. No product main, phone, process launch, signal or model is used.

The full seven-original production `prepare`/finalization run is deliberately not claimed by the local fixture report: actual future pins and the exact materializer original were not available in this local review. The real default validator rejects the synthetic materializer. The concrete root execution above must run against the actual cascade before any generated package is treated as finalized.
