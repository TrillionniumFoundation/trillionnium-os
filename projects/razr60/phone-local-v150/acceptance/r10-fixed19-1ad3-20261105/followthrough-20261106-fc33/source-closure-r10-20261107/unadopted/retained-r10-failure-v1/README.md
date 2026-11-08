# Exact retained R10 failure reader — unadopted source candidate

This is an implemented, byte-bound verifier for the actual retained R10 host
failure. It is not an executable preparer, a retirement receipt, a new source
adoption, or a fresh-admission grant. The existing frozen runtime and all old
requests remain unchanged.

## What it now verifies

`candidate/retained_r10_failure.py` accepts exactly the 13 byte roles in
`EXPECTED-ORIGINALS.json`. That manifest itself has an exact size and SHA-256
inside the implementation. `candidate/bound_loader.py` compiles only the exact
implementation bytes, assigns a new module/file identity, and supplies those
same bytes to the implementation's declaration guard. A declaration for a
different implementation is rejected before any provider callback.

The real fixture is the retained failure of:

- Label: `root-r10-neg01-fc33-r10-bound01`.
- Nonce: `4e5480a8952443bd18fa603b81f8efe9` (already consumed).
- Original host job: `1a1b7ef6a3a-12894-cbf`.
- Runtime manifest: 87,655 bytes,
  `94e945e55f4cda2c9d2c4bd473f6fdb8ec6eca425610db4fd59af1814f5fca02`.
- Original plan: 5,194 bytes,
  `523aa7ce5eb64732ca40fcfba7d78fc30c93689b6acc0c25620ed2972b4d5366`.

The main entry does substantive checks rather than trusting a status string:

1. It binds the retained collector inputs, original collector source bytes,
   export result, complete index, archive and original controller/worker
   request, launch, started, terminal, publication witness and full logs.
2. It validates all five fixed roots, 141 original census entries and their
   complete parent/child topology. It verifies all 125 file descriptors and
   all nine metadata integers in their original `dev/ino/mode/uid/gid/nlink/
   size/mtime_ns/ctime_ns` order. The metadata is historical retained data,
   not a newly observed live filesystem state.
3. It reads all 126 unique regular tar members in memory: the 125 original
   files plus the identical embedded index. Every member is checked for an
   exact name, type, size and hash. The original file total is 13,283,382 bytes.
   Nothing is extracted to a filesystem and no retained Python is executed.
4. It checks the original controller's actual executable, argv, plan hash,
   job, durable request digest and launch nonce. It binds the exit witness to
   the exact exit bytes and verifies both complete durable logs. The original
   outer exit is `1`; it is not an outer timeout or cancellation.
5. It verifies all seven original host phases, their once-only intents,
   original child PIDs, intent hashes, joined results, complete captures,
   stream bytes and full9 relations. These host children returned `0`; that
   fact is kept separate from the failed phone actor result.
6. It verifies the two material pushes and two create-only copies against
   their actual retained sizes, hashes, target paths and metadata. A copy's
   original `effects=0` field is explicitly not a claim of zero file writes.
   The archive and stage script were copied. The verifier does not relabel
   those operations as business actions or native submissions.
7. It validates all 38 material runtime files and the identical copied
   manifest, plus the actual root driver source pin in its source manifest.
   It does not claim that every external runtime dependency is reverified.
8. It verifies the original inner actor `TimeoutError`, `actor_rc=1`,
   `failed_or_unknown_no_retry`, measured `90.29949793312699` seconds, and the
   unchanged 90-second phone request budget. The original expiry is retained;
   it is not refreshed or treated as currently valid.

The public API returns a new
`hepta.UNADOPTED.r10-retained-host-failure-verification.v1` fact record with an
actual implementation pin. This is not presented as an execution receipt
emitted by the old R10 code.

## Exact meaning of the result

The original host terminal is known. The original phone terminal,
phone-stage producer terminal, phone-stage writes, historical failure
callsite and global unknown effect count remain `null` where applicable.
`remote_terminal_or_cleanup_proven` stays false.

The result also preserves:

- `original_nonce_consumed=true` and `original_replay_allowed=false`.
- `retirement_accepted=false`, `fresh_execution_eligible=false` and
  `nonce_creation_authorized=false`.
- `component_qualified=false`, `business_qualified=false`,
  `native_case_credit=0` and `production_adopted=false`.
- `complete_current_phone_scope_verified=false`.
- `separate_operator_wrapper_original_bytes_verified=false`: the exact host
  stdout contains and pins the reported wrapper object/hash, but this package
  does not pretend to have separately consumed the original Pocket4 operator
  result file as another input role.

`reader_effects` describes the pure verifier call only. It does not erase the
five historical phone operator phases or infer their internal wire-call count.
The retained collector's own zero-effect fields likewise remain local to that
collector; they are never promoted to global historical absence of effects.

## Entry points and the provider boundary

```python
module = bound_loader.load(actual_implementation_bytes)
facts = module.verify_retained_r10_failure(
    exact_expectation_bytes,
    originals_by_role,
    implementation_source=actual_implementation_bytes,
)
```

The main entry uses only supplied immutable bytes. It performs no file reads,
writes, process launches, signals, phone calls, native submissions or nonce
generation.

`verify_with_reader` is an optional explicit provider wrapper. It reads the
13 exact descriptors in deterministic order, runs the full verifier, then
requests each descriptor again. Both passes must return actual `bytes`; all
second-pass pins and byte values must match. Its 26 callbacks are accounted
separately. The provider implementation and live metadata are **not** attested
by this interface. A preloaded fixture callback is a fixture callback. A
production consumer must bind its real full9 reader and its surrounding
freshness/CAS contract separately.

The internal review found and fixed a concrete second-pass contract issue:
an equality-only comparison would have accepted a mutable or custom equality
object. The implementation now hashes and type-checks the second return before
comparing it. Negative tests retain both regressions. Strict integer checks
also reject boolean substitutions in metadata, controller log counts,
publication protocol, phase starts and signals.

## Verification and reproduction

Portable CI:

```sh
python3 -B tests/test_retained_r10_failure.py
python3 -B tools/verify_candidate.py
```

Portable tests run six tests and 49 rejection cases. The class requiring the
private original archive is explicitly skipped; CI does not claim to replay
unavailable originals.

The complete retained fixture run passed 14 tests and 120 distinct rejection
cases, with no skips. The actual complete result also matched between the
direct and 26-callback entry points. Reports identify the exact implementation
bytes. The tests distinguish byte-pin rejection, internal semantic rejection,
and synthetic parsing/type fixtures; synthetic values never become an accepted
original execution record.

With the real private inputs already available locally:

```sh
python3 -B tests/test_retained_r10_failure.py --fixture /absolute/private-fixture
python3 -B tools/replay_retained_fixture.py \
  --fixture /absolute/private-fixture --report /new/real-replay.json
```

The replay harness and tests do not execute any original worker, collector,
stage, preparer, actor or frozen admission implementation. Local test timing is
not a phone performance result and does not establish the stage's 90-second
production budget.

The public delivery contains only implementation, explicit pins, test/replay
code, bounded result reports and internal review. `private-evidence/`, copied
frozen source, transfer chunks, previous intermediate reports and the entire
retained archive remain outside the Git delivery.

## What is still genuinely required

This reader supplies the missing complete host-retention/failure semantics. It
does not supply a current phone preservation inventory, a producer/namespace
fence disposition, a new predecessor/nonce binding, an accepted policy/source
adoption, a new freeze/controller result, or a fresh reservation. A new
admission consumer must validate those actual originals alongside the retained
R6/R7/R8/R9 chain and this R10 result. It must not accept this fact record alone
as permission to continue.

The old runtime, freeze, source contracts, 90-second stage budget, requests,
nonces and original UNKNOWN records are not modified by this candidate.
