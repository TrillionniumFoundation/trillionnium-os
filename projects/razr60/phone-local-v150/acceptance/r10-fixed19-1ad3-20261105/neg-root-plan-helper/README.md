# R8 NEG01 / NEG02 Root plan preparation

This package creates a host plan only after it has called the **actual frozen
R8 coordinator's `validate_plan()`**. It never creates a native identity,
fixes a lease, instantiates `Chain`, starts a process, or contacts the phone.
The default mode performs the same read-only validation and writes nothing.

## Required order

1. Reconcile every existing policy/Root namespace and unresolved attempt.
2. Complete the actual property-policy adoption, then the reviewed R8 runtime
   freeze. This helper requires the actual completed
   `native-guard-r10-r1-operator-r8/FREEZE-RESULT.json` and verifies all listed
   output bytes. A preview or source-only candidate is rejected.
3. The Root owner chooses an explicitly authorized one-use identity and
   prepares its exact UTF-8 owner-request original. Supply the identity and
   request descriptor; this helper does not invent either.
4. For NEG01, the helper selects only the exact closed actual08 predecessor
   from the actual freeze inputs. It cannot substitute actual07.
5. For NEG02, supply the actual completed, qualified **same-generation NEG01**
   `ROOT-RESULT.json`. Its previous/closure/boundary chain is checked by the
   actual frozen R8 coordinator before any plan output is written.
6. Run this helper in preview or `--execute-host-plan` mode. On success, the
   latter prints the exact plan descriptor. The Root owner separately decides
   when to invoke the frozen coordinator's existing execution flag.

The historical08 Root plan is used only for retained private draft,
retirement, artifacts, and shared-material references. The actual new freeze
supplies the package, Root source package, policy adoption, and current policy
hash. Session/profile come from the selected actual predecessor. No old
request or nonce is reused.

## Inputs

Start with `PREPARE-NEG01.template.json` or `PREPARE-NEG02.template.json`.
Every null needed by the selected case must be replaced with an actual value:

- `freeze_result`: exact `{path, bytes, sha256}` for completed R8 FREEZE-RESULT.
- `base_plan`: exact descriptor for
  `native-guard-root-chains-r10-r1/root-r10-neg01-20261105-08/ROOT-PLAN.original.json`.
  Its bytes/hash must be obtained from the actual original; they are not
  guessed in this package.
- `label`, `nonce`, `request`: explicitly supplied one-use identity and exact
  owner request descriptor. Historical nonces and contaminated requests are
  rejected. The request must contain the chosen nonce exactly once.
- `qualified_neg01_result`: null for NEG01; the actual qualified current
  NEG01 result descriptor for NEG02.
- `host_out`: a new canonical directory beneath the project root, separate
  from the frozen R8 directory and all Root execution chain directories.

Pin that completed input file itself before invoking the helper:

```text
/usr/bin/python3 -I -B <staged-package>/source/prepare_native_guard_root_plan.py \
  --inputs-desc '<exact JSON path/bytes/sha256 descriptor>'
```

Add `--execute-host-plan` to create the new host-only output directory after
validation. It contains `ROOT-PLAN.json`, the exact preparation input/source,
and `PREPARATION-RESULT.json`. The actual Root execution directory must remain
absent. Existing labels or sender originals reject without a new identity,
retry, overwrite, or deletion.

The existing coordinator's ordinary no-execution CLI preview only prints a
preview summary; this helper explicitly calls its real `validate_plan()`.
No host result proves fresh phone state or absence of the nonce on the phone.

## Source and limits

Admission requires the reviewed capture Root template SHA256
`50a500e0c1cc014d3d4043f8c86172bf0b6068719473eb5646aca818416ed649` plus its
seven frozen literals, the reviewed bridge plus its package literal, and
the narrow freezer SHA256
`62bcfb5a3ece55526d6e3e5c4c5158426d0e0119b5a04d4754cc7903434ea509` plus only
its explicit FINALIZATION literal. All module `__file__` values identify
their actual frozen files. No historical validator is impersonated.

`validation/HOST-RESULT.json` records six local synthetic checks. Those
checks cover plan assembly, refusal of stale/replayed identities and invalid
NEG01-to-NEG02 progression, and exact source-literal round trips. They do not
run an actual adoption verifier, create an actual plan, or qualify a phone
acceptance case. Actual full validation remains a runtime gate when the
explicit inputs are available.

The helper adds no phone budget, lease extension, retry, signal, or policy
mutation. Every selected original uses bounded `O_NOFOLLOW` reads and full
metadata bookends. Source bytes and all selected original metadata are
rechecked before writing, and outputs are create-only with fsync/readback.
