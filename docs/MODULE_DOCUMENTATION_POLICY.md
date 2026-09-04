# Module Documentation Policy

This policy makes detailed module documentation a fail-closed, machine-verifiable part of the Trillionnium OS G1 source qualification. It supplements `docs/MODULE_DEVELOPMENT_STANDARD.md` and does not raise any implementation or evidence claim.

## 1. Authority and scope

The authoritative module inventory and engineering contracts remain in `docs/machine/module-catalog.v1.json`. The authoritative documentation mapping is `docs/machine/module-document-index.v1.json`. Provisional resource ceilings and their measurement status are recorded in `docs/machine/resource-budget-provenance.v1.json`.

Every module present in the machine catalog must have exactly one detailed document under `docs/modules/`. Every Cargo default workspace member must have a colocated `README.md`. The documentation index must match catalog identity, ownership, source paths, maturity, API schema, state schema and evidence ceiling exactly.

A document is explanatory evidence for source review. It is not installed-target, physical-device, destructive-fault, signing or release evidence.

## 2. Required document structure

Each module document contains these headings exactly once and in this order:

- `## 1. Identity and maturity`
- `## 2. Responsibilities`
- `## 3. Non-goals and authority boundary`
- `## 4. Context, dependencies and data flow`
- `## 5. API and protocol contract`
- `## 6. State model and ownership`
- `## 7. Ordering, concurrency and backpressure`
- `## 8. Effect, cancellation and uncertainty semantics`
- `## 9. Resource budget and SLO status`
- `## 10. Persistence, recovery and reconciliation`
- `## 11. Security and trust boundaries`
- `## 12. Failure matrix and degraded behavior`
- `## 13. Compatibility, migration and rollback`
- `## 14. Observability`
- `## 15. Verification and evidence`
- `## 16. Deployment and runbook`
- `## 17. Open gaps and exit criteria`

The document must identify:

- module ID, version, name, plane, primary and backup owner;
- every source ownership path;
- direct dependencies;
- API schema and concrete input, output and error type names;
- state schema, authority, partition, durability and retention;
- ordering key, admission budget, concurrency, timeout and backpressure;
- cancellation, duplicate, conflict and uncertain-effect semantics;
- provisional resource and SLO values with an explicit unmeasured label;
- persistence, startup recovery, reconciliation and rollback behavior;
- trust boundaries, observability, tests, evidence ceiling and runbook;
- every open gap and its evidence-level exit criteria.

The minimum byte count is intentionally enforced only as a coarse truncation guard. Passing the byte count does not compensate for a missing required section or a mismatch with machine truth.

## 3. Claim discipline

Every document must state:

- `Automatic redispatch: **forbidden**.`
- `Measurement status: **unmeasured until qualified evidence**.`
- the exact catalog evidence ceiling;
- all open gap IDs, or `Open machine gaps: none.` when the catalog assigns none.

Source documentation cannot close an L2–L6 gap. It may make implementation and qualification instructions complete, but the gap state changes only after the evidence intake path validates an immutable current package at or above the declared exit level.

A finite resource value is one of the following:

1. a source admission ceiling used to prevent unbounded allocation;
2. a provisional objective awaiting measurement;
3. a measured result bound to workload, environment, samples and evidence.

The current G1 values are class 1 and class 2 only. The provenance object therefore remains `PROVISIONAL_SOURCE_CEILINGS_UNMEASURED`, `measured=false`, `sample_count=0`, `evidence_id=null` and `activation_mode=OBSERVE_ONLY`.

## 4. Physical component mapping

The documentation index repeats each module's source paths and is checked against the catalog. A path must be relative, normalized, inside the repository and present in the exact checkout. Overlapping logical ownership continues to be governed by the catalog verifier.

Every directory in Cargo `workspace.default-members` must contain a `README.md`. A component README names the logical module or modules implemented by that component, links to the formal module documents and states its local build/test boundary. Existing component READMEs remain useful implementation guides; the formal module document is the canonical cross-component contract.

## 5. Validation

`tools/docs/verify_module_documentation.py` performs these checks:

- strict JSON decoding with duplicate-member and non-finite-number rejection;
- exact module-set equality among catalog, index, documents and budget provenance;
- safe normalized paths and no symlinked documentation targets;
- exact ownership, path, maturity, API/state schema and evidence-ceiling binding;
- required headings exactly once and in order;
- source path, dependency, gap and contract markers present in each document;
- no unresolved editorial markers;
- all new documentation registered in `docs/machine/doc-set.v1.json`;
- every Cargo default member has a colocated README;
- budget and SLO snapshots equal the catalog and remain explicitly unmeasured.

`tools/tests/test_owner_open_broker_module_documentation.py` adds hostile regressions. Its filename intentionally matches the existing required `test_owner_open_broker*.py` discovery in the protected G1 documentation job, so documentation completeness cannot silently fall outside the existing required check family.

## 6. Change protocol

A module change that alters identity, path, owner, dependency, API, state, maturity, budget, SLO, migration, rollback, evidence ceiling or gap list must update the machine authority first and then update its detailed document, index and provenance snapshot in the same exact-head change.

A documentation-only edit must not alter machine state or evidence status. If machine truth and prose disagree, qualification fails; prose never overrides machine authority.

The source must stop moving before an eligible non-author review and detached attestation are bound. Any base, head, tree, ordered merge or relevant artifact movement invalidates those decisions.

## 7. External boundary

This policy closes only the repository's ability to prove that every catalog module has a detailed, current, machine-bound technical document. It does not claim:

- installed Root Linux/provider identity;
- compiled Soong or SELinux policy;
- target-files or installed Android composition;
- physical-device shell, job or ADB effects;
- destructive fault recovery;
- production signing custody, AVB, OTA or public release authority.

Those statements remain governed by `docs/QUALIFICATION_AND_EVIDENCE.md`, the gap register and independently administered evidence packages.

## 8. Value binding and implementation navigation

The verifier compares visible, section-local identity, catalog API labels,
state ownership/durability/retention, dependency lists, concurrency fields,
every documented resource/SLO number and gap lists to the machine catalog.
Required headings or values hidden in a code example or HTML comment do not
satisfy the contract. Documentation/provenance program revisions must agree.

Every detailed module document resolves at least one named implementation
declaration and one test source. Python declarations are inspected with the
AST without executing code; Rust declaration navigation is checked statically.
These links prove discoverability only, not field-level codec compatibility.
Actual build, codec, concurrency and lifecycle tests remain required.
Every default Cargo member links a detailed module contract and carries its
exact locked package-test command. Source checks never prove target resource
enforcement or turn provisional SLOs into measured results.
