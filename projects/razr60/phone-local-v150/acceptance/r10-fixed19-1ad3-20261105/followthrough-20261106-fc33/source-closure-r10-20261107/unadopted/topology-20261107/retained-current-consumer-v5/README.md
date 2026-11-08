# Complete current retained-consumer candidate v5

This independent package connects the v2 retained R7/R8/R9 readers to the actual
current consumers, on top of the sealed v4 source-parent and inventory selection.
It completes the previously missing adapter path and also replaces the separate
R7 and R8 reader selections that occur before R9. Actual complete Mac originals
now pass through the new source-parent closure, sidebranch checks, retained
R7/R8/R9 verification and effective 44→47→49 inventory selection, with exactly
the same complete historical results and original read sequence as the frozen
current implementation.

This is an unadopted reader/consumer candidate. It does not execute the production
`verify_current`, `verify_retired`, `chain_originals`, retirement probe or stage.
The actual new execution source is explicit; original publisher and adapter
identities remain historical data anchors. No old runtime, receipt or v1–v4 file
is changed.

## Exact construction and execution identities

| Role | Bytes | SHA-256 |
| --- | ---: | --- |
| Actual v5 constructor | 31905 | `88eec8400731b2131f4361ded2c5e480fa7abfca526a7f9be4463a3e48b25bde` |
| Independent v5 loader | 996 | `d3f85017792e2c6b9d1b943b8813dd85525f40e4262314ef959ceaceeef23bad` |
| Actual new current module | 260205 | `d012b0c4d7d1312190b820d3874bb697c80ae1ca8dce75ccbeb9e4872615db42` |
| Actual new retained runtime adapter | 23772 | `758fd854862d7d43098aa3772ec98120c984e9040685731af05e69f7aa2a17e2` |
| Frozen current historical source | 259866 | `f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7` |
| Frozen historical adapter source | 23623 | `eaf52438100706edb6734efea64299f6ff1b414485c2c353c9172f7c6f670857` |
| Intermediate sealed v4 source construction | 258924 | `5b7ca9884a448518e572f1e8c5f9438389f01ea315aa41ae89f5729ccc58a3e9` |

The full source manifest also pins the sealed v4 and v3 constructors/loaders, v2
selector/loader, unchanged common source, and the exact 3827-byte inventory and
8369-byte complete-scope functions. The independent loader checks actual
constructor bytes before compilation and rejects a different declared source.
The constructor repeats that actual-byte binding check.

The new current module is constructed from the exact v4 source through fifteen
specific replacements and one explicit appended helper block. The new adapter
uses five specific replacements. Both transformations verify their whole-byte
inverse. Each selected module has fresh globals, a distinct module name and an
execution filename containing its actual new source hash. No old module is
rebound to new code under an old implementation identity.

The ten selected v4 outer record, full9, generic dispatch, source-parent, tail and
inventory functions are byte-identical in the v5 current module. Its two identity
getters remain separate: frozen-current publisher data and actual newly derived
current execution. V4 is a source-construction intermediate here; its old result
envelope is not reused as evidence that the v4 current module executed in this run.

## Actual selected interfaces

| Current interface | New connection | Preserved constraints |
| --- | --- | --- |
| `retained_preaccept_reader` | Select v2 derived R7 after validating the exact embedded original source | Original bounded decompression/source pin; historical manifest/archive pins; full failure and UNKNOWN semantics |
| `retained_failed_staged_reader` | Select v2 derived R8 after the original external source read and pin | Same original source/proof reads; actual two-root failed R8 family; no invented native terminal, causal identity or qualification |
| `retained_failed_transport_adapter` | Verify the same old adapter source, then explicitly derive and instantiate the new adapter | Old proof binding and source read gate stay intact; old adapter descriptor is explicitly historical data; new execution hash is separate |
| New `Adapter.reader` | Select v2 derived R9 after the exact original reader byte pin | Actual nested R9 scope, R8 scope, R7 reader and all three inventory contexts execute under their new identities |
| R7/R8 proof and preservation consumers | Consume a typed new in-process envelope from the same actual producer instance | Full original result/schema, 47/49 roots, private subtree, absence, old native predecessor, call-accounting and UNKNOWN guards remain |
| New adapter verification/preservation | Consume the new R9 reader envelope before original adapter guards use its data | Complete old failure semantics, same retained bindings, zero added R9 roots/roles, exact 49-root inventory identity |
| `retained_failed_transport` and `effective_current_prior_inventory` | Consume the new adapter result envelope at the actual current call sites | Complete original 44→47→49 topology/full9/hash checks and original classification string remain |

The adapter's seven old `adapter_source` references are renamed to
`historical_adapter_source`. Its old observation/manifest checks still compare
historical data to the historical source descriptor. They do not claim that this
descriptor identifies the new executing adapter. The new facade's provenance
separately identifies its actual derived source and actual current consumer.

The selected reader and adapter facade classes are checked by exact in-process
type, kind and method before invocation. Their new result envelopes require the
same actual instance's complete execution provenance, exact schema/fields,
unchanged historical-result shapes and a zero-admission claim ceiling. Arbitrary
external JSON receipts cannot replace producer execution. The result envelope is
not presented as a cryptographic authenticator for externally supplied data.

Every selection creates a fresh v2 selector and new reader globals. Its inventory
and scope function pins are checked by the bound v2 selector before selected
reader execution. No previous proof result or live observation is cached.
Existing optional already-verified argument paths remain the original API; this
package introduces no new PASS reuse. The private combined replay invokes the
same full read/validation path twice and sees twenty original reads both times.

The new explicit combined entry is:

```python
reader.reviewed_historical_source_parent_inventory(
    boundary_raw,
    inventory_raw,
    closure_raw,
    original_descriptor=actual_source_parent_boundary_descriptor,
)
```

It runs `source_parent_closed_boundary_originals`, rebuilds the non-native
sidebranch checks, then calls the actual `effective_current_prior_inventory`.
It returns a new envelope containing the original effective inventory tuple.
This is real current-consumer execution; it does not manufacture a PASS wrapper
around a saved historical result.

The interface exposes eleven pure reader/consumer entries. Publication, live
current inventory, whole-chain I/O, retirement and production entrypoints are
removed from the selected module; the adapter facade has no fresh-observation or
external-originals method. These removals are not a security sandbox against an
arbitrary Python caller using private introspection. They define the reviewable
candidate API and keep the completed scope explicit.

## Complete real-original Mac replay

The exact 29-file source-parent readset from v3 is combined with nine further
retained Mac source/archive/manifest reads: **38 actual original files**, each
read with bounded no-follow access and exact byte/hash/full9 bookends. Three
host-to-phone manifest representations are explicitly checked: only the fixed
archive path differs. These are representations of retained originals, not new
phone publication or current phone observations.

The authoritative job is `1a1b8ea394d-12894-1134`, using the single idempotency key
`fixed19-retained-current-v5-complete-offline-differential-20261108-01`.
It succeeded with exit 0, no cancellation, no timeout and no automatic retry.
Terminal publication, output completeness and durability are true. Stdout is
122389 bytes and stderr is empty; both streams were read through EOF.

| Exact retained output | Bytes | SHA-256 |
| --- | ---: | --- |
| Full original stdout JSONL | 122389 | `9bc64521776acb1d893c4a3d217f5a33659a20e585cbb9fb5cb2d2c2bfdad04c` |
| Complete final result line | 120050 | `8ec4aad907745c94f9cca2351f3a36b7b9206b6599d1cd332faab24c0f39acaf` |

The original UTF-8 bytes were reconstructed from complete controller byte-hex
pages and checked against the authoritative stored size. All JSON containing
nanosecond/full9 integers is handled in Python without JavaScript number
rounding. Original logs, complete private results and fixtures stay outside the
public package. The public safe report contains exact pins, case outcomes,
selected-code receipts, safe counts and the original failure scalars.

The replay passed six complete positives:

1. Actual standalone retained R7 verification: two original reads.
2. Actual standalone retained R8 verification: four original reads.
3. Actual current R9 adapter verification: eight original reads.
4. Actual current effective source-parent inventory, 44→47→49: eighteen reads.
5. Complete source-parent closure through current retained49: twenty reads.
6. Repeat of the same complete combined entry: the same twenty reads, all revalidated.

Fourteen negative cases preserve original exception type, message and read
sequence. They alter R7/R8/R9 archive, reader and manifest bytes, the adapter
source, nested prior archives and rejection priority. The altered outer full9
descriptor rejects before invalid inventory and retained proof reads. Twelve
additional faults exercise the actual new adapter result envelope and reject
wrong schema, kind, method, actual code identity, historical data identity,
claimed adoption/admission/credit/budget, or wrong historical-result shape.

Every complete historical return and every explicit original-provider descriptor,
read order and returned byte identity matches the frozen current implementation.
All source/archive bookends remain unchanged. The final effective inventory is
49 roots and 3991 entries, 1403290 bytes, SHA-256
`bb8cfb6dd2f108046e8296956e514f7b3eec0ea5aaac5794ad86c70174478609`,
with the original classification
`exact_source_parent44_plus_retained_failed_r7_r8_r9_49`.

The actual selected R9 execution receipt contains R9 reader/scope, R8
reader/scope, R7 reader, and inventory selections for `r7-readers`, `r8-payload`
and `r9-scope`. Separate actual receipts confirm standalone R7 and R8 selection.
These are actual executed construction paths, not inferred from names or a plan.

Historical `global_unknown_effect_count` and `native_terminal` remain null;
`remote_cleanup_proven`, `retirement_accepted` and `new_nonce_authorized` remain
false. The original first-launch receipt gap remains true. Native case credit is
zero. No later observation is promoted into an original terminal or retirement.

## Timing boundary

The complete positive calls recorded these single-case Mac wall times:

| Complete current call | Frozen implementation | New candidate |
| --- | ---: | ---: |
| Retained R7 | 0.369276 s | 0.274523 s |
| Retained R8 | 1.944375 s | 1.035886 s |
| Retained R9 adapter | 2.586531 s | 1.596083 s |
| Effective 44→47→49 selection | 7.040058 s | 4.808735 s |
| Closure through retained49 | 9.267137 s | 6.942495 s |
| Repeated closure through retained49 | 9.495823 s | 7.076105 s |

These are individual old-then-new calls during a differential run, not repeated
alternating benchmark medians. Source/original preloading is outside them. The
calls do execute all nested validation and new envelope handling each time, but
they are not phone measurements, complete production I/O accounting, whole
`verify_current`/`verify_retired` runs, or proof that the original 90-second stage
fits. No timing budget or lease rule is changed.

## Portable checks and source closure

From the parent topology directory after import:

```sh
python3 -B retained-current-consumer-v5/tests/test_retained_current_consumer.py --base .
python3 -B retained-current-consumer-v5/tools/build_manifest.py --base . --check
```

All twelve portable tests pass. They cover ten source-binding rejections,
twelve constructor rejections, three actual newly selected R7/R8/R9 reader
rejections before any original-provider call, four wrong in-process producer
rejections, three new-envelope acceptances, seventeen envelope rejections and
two uncached outer calls. They also verify immutable v4 source identity, exact
guard bodies, separate historical adapter data, the deterministic source
transformations and original error propagation. They do not claim the private
complete Mac replay as a synthetic CI result.

The source manifest records a conservative current static closure of **84
functions and one class**, plus explicit dynamic factory, nested reader,
original-provider and stdlib filesystem edges. It is not a claim that static
name analysis enumerates every runtime I/O operation. Saved reports use exclusive
creation; CI never overwrites original validation evidence.

## Remaining production boundaries

The three located pure validation areas are now selected in an actual current
consumer candidate: current inventory, complete source-parent reader, and
standalone/nested retained R7/R8/R9 readers. The existing production runtime has
not selected this candidate. The following work remains concrete and separate:

- New source adoption must bind the exact selected current/adapter/constructor
  closure and required source review to a genuinely new runtime identity. Old
  R10 package `94e945...fca02` can be a diagnostic historical data context; it
  cannot attest adoption of this new code.
- The independent retained R10 failure verifier and new freeze/controller/
  preparer semantic bindings must be integrated without inventing R10 original
  phone terminal, write/effect counts, absence, cleanup or retirement facts.
- A fresh production read provider must meter actual source, archive and
  original reads plus C helpers and stdlib filesystem observations, with
  actual bookends, within the unchanged stage budget. Preloaded immutable Mac
  evidence and these callback sequences are insufficient proof of that gate.
- Whole `chain_originals`, `retired_originals`, `verify_current`, live inventory
  and retirement/probe paths are outside this public consumer API. Their
  complete original/read sets and production call sequence have not been run
  by this package. A separately identified read-only prefix diagnostic must
  state its precise entry and stopping point if it is prepared.
- There is no successful new-current-prefix fixture. Actual dependency/phone
  observations, fresh input/preview, live CAS and one new reservation still
  need real evidence and the established admission rules. Old requests and
  consumed labels/nonces cannot be replayed.

No phone, native submission, stage, nonce, install, CURRENT mutation, independent
owner review or runtime admission is supplied by this package. Source readiness
and successful historical validation do not supply current fixed19, release,
health, daily-running or rollback qualification.
