# Independent runtime producer and current App consumer

The Android candidate CI previously passed its changing complete App source to
the MNN v8 and UI-Venus v1 producers. Both intentionally require manifest
f4af9855da4e62a2eeaa1cc8d734082c6c31d17f95d001b58b412dbd7604978a.
The public commit that owns those exact bytes is
cc4a7035760383a126e4510002139d88667e0b97, with 1,096 manifest members.
The retained MNN error mentions Code19, but this published closure is the
Code21 privacy derivative. Its complete source is not the current App.

## Contract and scope

This D5 build-evidence adapter separates two explicit identities:

- **Producer:** an independent checkout of that fixed public commit. The
  unchanged MNN rebuilder, macOS compiler qualification, MNN transport binder,
  UI-Venus builder, complete original ELF hashes and SDK/source pins still
  execute against their original frozen source.
- **Consumer:** the actual candidate checkout at the current workflow head.
  Every component file is checked against both its complete manifest and its
  exact Git blob/mode. The complete MNN/UI-Venus native provenance, Java and
  packaging pins, runtime verifiers and SDK fetch code must remain identical
  to the producer closure.

The original producer/verifier scripts are also checked byte-for-byte against
the fixed producer commit before invocation. They are not edited or loaded with
replaced constants. The App build and canonical host checks continue to run
against the current consumer, not the frozen producer.

A new outer transfer bundle contains:

- producer/: the original runtime, new build receipt, compiler identity and
  original current-workflow binding, still checked by the original consumer.
- CURRENT-CONSUMER-SOURCE.json: the complete independent consumer/producer
  identities, unchanged runtime closure, current head/run/attempt, original
  receipt digests and a second whole-payload verification using the consumer's
  own packaging verifier.

Mac binding first runs the original operation. Linux verification first runs
the original verifier. Both then reverify the complete source pair and the
runtime against the actual consumer. Linux requires exactly the two outer
members and exact bytes for the new binding. A changed head, run, attempt,
source, runtime contract, receipt or payload rejects admission.

The binding explicitly says consumer_android_build_proven: false.
It does not manufacture current App compilation, signed-device deployment,
ordinary tool success or phone acceptance. Original build receipt bytes remain
historical provenance and are never relabelled as the new build receipt.

## Failure, rollback and resources

A rejected original operation, unexpected source change or unknown identity
never publishes a valid consumer binding. Output directories are unique, and
binding creation is exclusive. Partial outputs are retained for diagnosis; no
phone, ADB, inference, force-stop, signing or pin rewrite is performed here.

This adds bounded source reads and Git object checks in CI. It does not alter
runtime code, model compute, device budgets or physical resource ownership.
Rollback is a normal revert of this workflow/adapter change; it must not remove
any producer, payload or integration-protection check.

## Validation

Run python -B -m unittest -v test_bind_consumer.py. Tests use actual temporary
Git repositories, manifest-vs-Git identity conflicts, unlisted/missing members,
aliases and mode changes, runtime closure drift, original argument routing and
the failure/source-race boundary before publication. The orchestration negative
cases use explicitly mocked original operations; they are not macOS rebuild
or complete transfer success evidence.

The complete real candidate and producer source pair must also pass
bind_consumer.py check-sources at the exact published head. Actual macOS
runtime rebuilding and Linux App compilation remain separate workflow jobs.

## Protected integration

Use the existing protected integration/razr60-r9-20261107 path. Its checks are
not changed by this patch. A draft consolidation PR may include the current
App ancestry; it must report that inherited scope and obtain fresh exact-head
and prospective-merge checks. Neither a historical green run nor this source
adapter authorizes merging, Android installation or release.
