# Unbound next-generation preparer candidate

This package prepares reviewable source and an explicit future-binding format.
It cannot prepare, freeze, admit, reserve, dispatch, install, or run a component.
The generated Python module rejects before its first import. Filling the JSON
template, changing a `state` field, or passing a structurally complete original
set cannot enable execution.

## Preserved source and new identity

The retained original is the exact 27,261-byte R10 preparer with SHA-256
`8e4bb7e8034dd09fde1cb93867f38f59f1487a6e06e4504eb8c201ee1df27b10`.
Its actual Mac source was read back from
`followthrough-fc33-runtime-r10-review01/prepare_native_bound_components_r10_fc33.py`
and matched the published PR115 source checkpoint.

`candidate/preparer_binding.py` is a new pure source deriver and structural
review helper. `derive_unbound_preparer` requires those exact original bytes,
clears only the five top-level generation assignments `FROZEN`, `LABELS`,
`BOOT`, `FROZEN_INPUTS`, and `ADMISSION_SOURCE_PINS`, and prefixes an unconditional
UNBOUND rejection. It retains every original function/class body. Its recorded
inverse recovers every original byte; the new source has its own hash.

The original preparer, historical runtime, existing freeze, and previously
published candidates are not edited. The retained generation-specific function
bodies are inert review material. They do not become a new executable contract
merely because the five global assignments are empty.

## A concrete existing data prerequisite

The production R10 preparer is bound to the old R10 freeze:

- `FREEZE-RESULT.json`: 1,613,295 bytes,
  `651b4dd0f4f1c32b1928d58480e1adc3f2fcf104884db44b4eac52a0c625ba6d`.
- Actual freezer source: 32,010 bytes,
  `7db072079c16ca6485d3ea6083eec5adf1054ebe0e6850d6eabf352745603b36`.
- Controller originals: 8,823 bytes,
  `d7a4f0aaa6bfd2852ba5395db3296a0b50abfb16fb6fba7c8661d05d422ad881`.

Its NEG-01 label is `root-r10-neg01-fc33-r10-bound01`. That output directory
already existed in the read-only Mac observation. The exact old helper
(`4708d037d58fd5b40e2a15210887ce58d9e7d0857ef27057855031591ee7faf9`)
rejects an existing input/output namespace or retained sender identity.
The R10 NEG-02 label is also reserved to that old generation; this package does
not claim that NEG-02 ran or that its namespace was consumed.

These are concrete reasons that the existing preparer cannot be reused for a
new candidate. They do not prevent writing or testing new unbound code.

## Future binding is a review format

`FUTURE-BINDING-UNBOUND.json` leaves every future descriptor and case label as
`null`. No future hash, controller terminal, phone observation, or disposition
has been fabricated. The format names the required inputs:

- A new actual freeze, its actual freezer source, and complete controller originals.
- The six inherited admission source roles, each linked to the supplied new
  freeze, plus a separately identified new admission-policy implementation.
- Retained R10 failure originals and a new original-attempt admission object
  that will need a new semantic verifier.
- Distinct, unused NEG-01/NEG-02 labels and their exact namespace-observation
  originals. The observations still require fresh live/CAS verification.

`validate_binding_structure` accepts only in-memory bytes supplied by its
caller. It never opens the descriptor paths. It rejects missing members,
missing bytes, digest/size differences, ambiguous JSON, old frozen namespaces,
old freeze/freezer/controller identities, consumed labels, old-generation
labels, and missing or mismatched six-source links.

Even when these structural checks pass, the result is explicitly
`STRUCTURAL_REVIEW_ONLY_EXECUTION_DISABLED`. It reports controller semantics,
retained R10 failure semantics, complete freeze validation, namespace freshness,
runtime admission, and production adoption as **false**. In particular,
byte-pinned arbitrary controller or disposition bytes are not treated as a
successful real controller terminal or a valid original admission.

## Remaining implementation and real-data work

The following work is still required before an executable preparer can exist.
It is not reduced to obtaining an approval:

1. Implement and test the new freeze/controller semantic binding. The retained
   old logic contains the R10 controller idempotency key, fixed paths, manifest
   cardinalities and historical accounting. A future generation must bind its
   own actual source, controller request, completed terminal and full readback.
2. Implement a new admission-policy closure that accepts only the genuine
   retained R10 failure facts and preserves all failure/UNKNOWN/call-accounting
   meanings. The six inherited modules currently cover earlier dispositions;
   their presence does not supply an R10 failure verifier.
3. Bind actual R10 failure originals and the new original-attempt admission
   object to that implementation. Merely supplying a descriptor or labeling a
   JSON object as R10 is insufficient.
4. Bind the new predecessor, consumed nonces, current boot/profile and exact
   labels. The old preparer still contains an exact three-nonce prior set and
   earlier predecessor rules in its preserved function bodies.
5. Implement the production consumption of the new source-parent result
   envelope, the selected runtime source closure and its new identities. The
   existing R10 runtime is not modified by this package.
6. Obtain a genuinely new freeze/controller result, current dependency and
   phone observations, unused namespaces, fresh input/preview, required CAS and
   one reservation. Recheck the real 90-second production I/O budget separately.

No activation switch or partially permissive execution path is provided here.
`prepare(...)` rejects before it examines caller bindings or effect callbacks;
the generated module independently rejects before importing the inert old body.

## Reproduce the source and negative gates

```sh
python3 -B tools/build_candidate.py --check
python3 -B tests/test_unbound_preparer.py
```

Without `--check`, the builder creates only absent deterministic source/review
products and rejects an existing different product. Test reports are written
only when an explicit new `--report PATH` is supplied, using exclusive creation.

The tests use clearly labeled synthetic byte/shape fixtures. They verify the
actual unconditional module guard with import/read/nonce/write/phone sentinels,
the always-disabled API, inverse source reconstruction, frozen-identity and
label rejection, every missing or altered supplied original, six-source links,
and JSON/path/type rejection. The zero-effect counters apply specifically to
the disabled preparer entry; ordinary static builder/test file reads are not
claimed to be absent.

The original preparer and freezer are never executed. No phone/native request,
new nonce, current fixed19 credit, install qualification, or production adoption
is supplied by this package.
