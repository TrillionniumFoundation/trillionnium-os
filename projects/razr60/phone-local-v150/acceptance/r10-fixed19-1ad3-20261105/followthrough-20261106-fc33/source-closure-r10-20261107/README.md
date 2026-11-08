# R10 source closure and unadopted source preparation

This checkpoint publishes the current R10 source bytes after PR #112. **The original R10 attempt failed and remains unqualified.** It grants no fresh admission, NEG-01/NEG-02 completion, BUILD, installation, READY, health, fixed19, business, or daily-use credit.

The source ancestor is `22e6105c2effe102c0f120a906752003aedfb37d` from [PR #112](https://github.com/TrillionniumFoundation/trillionnium-os/pull/112). The intended target is the existing protected `integration/razr60-r9-20261107` branch. Each changed Git head requires its own source checks and independent GitHub approval. Local review JSON files are historical source-review records, not submitted GitHub reviews.

## Included source and identities

| Directory | Contents and boundary |
| --- | --- |
| `frozen/native/runtime` | All 38 members from the original R10 runtime manifest: 31 Python source files and 7 historical reference commitment/topology JSON members, byte for byte. |
| `frozen/native/root-chain` | All three exact root-chain members and their original manifest. |
| `frozen/native/dependencies` | The selected Mac/Pocket4 helpers, admission/disposition readers, the retained-transport adapter, fresh-input helper, selected configuration and unchanged budgets. All twelve explicitly selected external dependencies are checked against the original manifest. |
| `frozen/native/shared` | The frozen provider sources, source/material manifests and configuration references. Credential files and model/binary payloads are absent. |
| `preparation/r10` | Exact bound/unbound preparer, freezer, fresh-input helper and source-review/binding records. |
| `release/reviewed`, `release/derived`, `release/consumer` | Source constructors and the actual bound/derived release builders, installer, readiness/retention verifiers, consumer, activation fragment and service source. |
| `external-source` | Additional pinned source dependencies resolved from actual retained files or exact source bytes already in the ancestor repository. |
| `unadopted/topology-20261107` | Separate current/source-parent inventory and R8-scope fragments, reversible patches, constructors, differential tests and offline reports. It is not applied to `frozen/native`. |

The immutable runtime manifest SHA-256 is
`94e945e55f4cda2c9d2c4bd473f6fdb8ec6eca425610db4fd59af1814f5fca02`.
The root-chain manifest is
`43bbc6ac86758d31ed03d55a5cac0e24db5a021b161d2161a4f52a58980d8da2`.
The frozen `late_boundary.py` remains
`f9a19df8a2a1d8b6a09a8c75eec118f4304ad1db5f40fc005fd7d59fb02837b7`.
Publishing the candidate does not replace any of these identities.

[MANIFEST.json](MANIFEST.json) enumerates every public member with byte length, SHA-256 and its exact/generated classification. [EXTERNAL-SOURCE-BINDINGS.json](EXTERNAL-SOURCE-BINDINGS.json) binds the source dependencies and records every unresolved development ancestor, including its exact referring JSON field.

## Reconstruct and check the source tree

From a clean checkout:

```sh
python3 tools/verify_razr60_r10_source_closure.py
python3 -m unittest tools.tests.test_razr60_r10_source_closure -v
python3 tools/verify_razr60_r10_source_closure.py --materialize /tmp/razr60-r10-source-new
```

The materializer requires an absent output directory. It verifies all members before creating output, recreates the current frozen/preparation/release/external source tree, then reads every output byte back. Its receipt is explicitly source-only. It never imports the runtime, invokes SSH/ADB, executes a freezer, selects a nonce, or admits a plan.

The tests reject missing native members, missing selected or transitive external dependencies (even after a membership-row deletion), altered source bytes, reassigned frozen identities, ambiguous JSON, path traversal, symlinks and binary/private archive members. All 518 dependency bindings are checked against their original JSON pointers or static Python assignment fields; only the exact twelve recorded ancestry exemptions are allowed. Stable full9 file identity checks exclude access time and preserve nanosecond mutation timestamps. They reconstruct the source tree and compare every copied member. The existing G1 exact-head and synthetic-merge workflows already discover the new `tools/tests/test_razr60_r10_source_closure.py`; no workflow or branch-protection gate is relaxed.

### Twelve unresolved development ancestors

Twelve pre-binding development bodies remain unavailable in this publication. Their references occur only in the original source plan, independent source-review metadata, or the release source-selection record. They are not runtime members and are not referenced as paths by the copied executable sources. Their precise descriptors and JSON pointers remain visible in the external-source binding index.

The current frozen source is reconstructed from its complete retained bytes; this operation does not evaluate those twelve ancestors. **Re-execution of the historical assembly process is not established.** Running the original freezer or a real release still requires the separately preserved private inputs and authoritative current admission. The source materializer does not replace that process or certify its missing prerequisites.

## Failed runtime state and performance boundary

[STATUS.json](STATUS.json) binds the original private reconciliation index by SHA-256 without publishing its packet. The R10 stage attempt remains failed/unqualified. An independent, uninstrumented read-only pre-stage baseline stopped at its own 80-second deadline after 80.046890 seconds and 79.211763 CPU seconds, before current inventory or stage writes. That observation is distinct from the original 90-second stage execution.

The separate topology candidate replaces a quadratic root-overlap predicate with strict `Path.parts` prefix membership after the unchanged canonical-path checks. The original error text, rejection ordering, other validation rules and source bytes are retained. Published offline differential results cover 801 whole-inventory comparisons and 1,754 root-topology comparisons with zero mismatches. These retained results are not CI for this new Git head.

The portable G1 tests rebuild the exact current and derived fragments in a temporary directory and independently run 788 generated whole-inventory comparisons and 1,754 root-topology comparisons for both inventory versions, plus 285 synthetic R8-scope subgraph comparisons. The full retained-fixture suites additionally require the private, hash-pinned fixture bytes; CI explicitly skips those cases. A separate retained Mac report compared the complete original/derived R8 scope with identical full returns and six rejection cases, measuring a host median 0.983766 to 0.254996 seconds (3.858x). These are offline function measurements, not a whole-stage 90-second result. No production selector, historical reader substitution or new runtime admission is provided.

## v2 offline selector milestone

The second public increment is [SELECTOR-CANDIDATE-MANIFEST.json](unadopted/topology-20261107/SELECTOR-CANDIDATE-MANIFEST.json), with the design in [SELECTOR-DESIGN.md](unadopted/topology-20261107/reports/SELECTOR-DESIGN.md). The earlier v1 README and coverage report remain unchanged milestone records; this increment supplies the separately identified **offline** R9 → R8 → R7 reader/scope selector.

A bound loader verifies the actual selector source pin before compilation and requires the declared implementation source to be those exact bytes. Five derived modules have fresh globals and their own implementation identities; their original reference bytes are checked and retained. The historical response is a data projection, with new validator provenance recorded separately.

The additional portable suite runs 11 tests with one explicit private-fixture skip, five module constructors, 36 source/binding rejection cases and 30 complete-inventory outcome comparisons. Its deterministic constructor manifest must reproduce byte for byte. Original requests, full private reports/readsets and archived inventories remain outside this repository; the public [safe summary](unadopted/topology-20261107/reports/selector-full-safe-summary.json) binds their exact retained originals.

At the v2 milestone, the complete source-parent boundary reader was not yet composed. The v3 section below records the completed offline extension. Production policy remains **HOLD**: no new runtime policy/freeze is supplied, and the whole-stage 90-second budget remains unverified. Neither increment adds runtime admission or case credit.

## v3 complete offline source-parent reader

The separately identified [source-parent v3 package](unadopted/topology-20261107/source-parent-v3/README.md) now constructs all three source-parent entries: boundary reading, complete boundary/inventory/closure validation, and complete failed-ancestor-tail validation. The original static closure has 55 functions and one class; the derivative has 56 functions and one class. The entire derived source has a verified whole-byte inverse. The constructor and independently pinned loader bind the declared implementation to the actual compiled bytes.

Historical publisher identities remain data anchors. The new reader, result envelope, property-reader composition and sidebranch composition carry distinct derived identities/schemas. Historical values remain under the new envelope's historical_result; this projection does not attest execution of the old implementation. The original outer full-descriptor/full9 binding remains required and unchanged.

A retained Mac run checked 29 exact original files before and after validation, with 12 complete positive cases, 17 rejection cases, two constructor-binding rejections and three unprofiled timing rounds. Historical returns/errors and callback descriptor/order/bytes matched. The original UNKNOWN_UNCHANGED state and historical final04 credit remain historical; current native case credit is zero. Full current verify_retired, production I/O metering and the stage/transport 90-second gate were not executed or verified. The [safe report](unadopted/topology-20261107/source-parent-v3/reports/FULL-REPLAY-SAFE-v3.json) binds the private original output without publishing its readset/body.

Portable CI rebuilds the exact v3 manifest and runs 14 tests with two explicit private-fixture skips, 788 generated inventory comparisons, 1,754 root-topology comparisons, ten source-binding rejections, three dependency/constructor rejections and two envelope unit cases. It does not claim to rerun the complete private fixture suite. The 35 v1 and eleven v2 public files retain every original hash.

## Unbound next-generation preparer

The [preparer scaffold](unadopted/preparer-next-generation/README.md) retains all 15 reviewed function/class bodies from the exact 27,261-byte R10 preparer. Its five generation slots are None and an unconditional rejection precedes every import. The future-binding template contains no fabricated hashes or selected labels. Neither a completed JSON draft nor successful structural checks can enable execution.

Its eleven portable tests cover 79 rejection cases, including the consumed R10 NEG-01 label, old-generation labels, old freeze/controller identities, missing/changed originals, six-source freeze links and invalid paths including NUL. Entry sentinels observe zero import/read/nonce/write/phone effects. Static test/build file reads are outside that entry-effect count.

This is an inert preparation artifact, not a completed production preparer. Concrete implementation still includes production consumption of the new envelope, a new R10-failure admission verifier, complete new freeze/controller semantics, predecessor/consumed-nonce bindings and fresh namespace/boot/profile/CAS/reservation checks. Genuine new freeze/controller and retained-failure/admission originals remain necessary inputs. Independent GitHub review is a separate requirement; it does not replace this code or data work.

## Publication, compatibility and rollback

This is a D5 source-custody/evidence-boundary change for MOD-ANDROID and MOD-EVIDENCE, plus an unadopted D3 algorithm candidate. No production API, state schema, ordering, cancellation, nonce reservation, source seal, budget or deployed runtime is changed. Existing failures and UNKNOWN originals remain preserved. A later adopted implementation needs its own source derivation, complete proof-reader coverage, full original-budget validation, new freeze/admission and independent review.

Source rollback is reverting this source checkpoint commit. That does not perform or qualify device rollback. Private phone drafts, raw private evidence archives, credential contents, compiled binaries and model weights are absent. Historical commitment metadata and source-bound encoded code/projections remain marked as source inputs, with the publication review in [PUBLICATION-REVIEW.json](PUBLICATION-REVIEW.json).
