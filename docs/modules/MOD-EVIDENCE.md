# MOD-EVIDENCE — qualification and release evidence

This document is the detailed source-development, integration and qualification contract for `MOD-EVIDENCE`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-EVIDENCE`
- Module version: `1.0.0`
- Name: **qualification and release evidence**
- Plane: `evidence`
- Primary owner: `team-evidence`
- Backup owner: `team-security-release`
- Maturity: `L1_SOURCE`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `docs/machine/evidence-index.v1.json`

- `tools/owner_source_provenance.py`
- `tools/owner_source_surface.py`
- `tools/owner_bom_bounded_process.py`
- `tools/collect_owner_source_vector.py`
- `tools/android_release_ota.py`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- L0-L6 evidence schemas.

Operationally, the required flow is:

A verifier binds a package to the exact repository, base, head, tree, ordered merge, run, artifact and role subject; downloads and hashes retained artifacts; validates detached signatures and trust roots when required; and proposes only evidence-supported transitions.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

## 3. Non-goals and authority boundary

Explicit non-goals:

- synthetic target evidence.

A self-hash is integrity metadata, not external authorization. Repository writers cannot mint independent review, installed-target facts, destructive-fault results, signing custody or release authority.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-PROTOCOL`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_evidence.api.v1`
- Catalog input labels: `evidence_package_v1`
- Catalog output labels: `evidence_index_v1`
- Catalog error labels: `evidence_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `tools/verify-g1-evidence.py` — `main`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

The CLI delegates to strict package verification; `verify-g1-evidence-live.py` binds current external objects. The checked-in evidence index is navigation, not a durable runtime journal or signer. A source fixture is never a substitute for an independent operator, reviewer, detached attestation or release decision.

### Owner provenance inputs and signed-output custody

The owner source producer, bounded Git subprocess helper and original-vector
collector belong to `MOD-EVIDENCE`; Android owns the build-time META writer and
target-files consumer. Their `owner-open-whole-control-v3` profile is separate
from the retained legacy P0 source-BOM profile. It has a content identifier and
complete measured input closure, with local provenance authority only. A
self-consistent JSON receipt is not an authenticated builder, a signature,
independent review, an installed target or permission to release. See the
[Android producer contract](MOD-ANDROID.md#owner-source-provenance-and-build-time-meta)
for its graph and build inputs.

The v3 profile binds exactly 16 private projects and the remaining 1153 original
projects in the 1170-project graph. All producer and consumer versions advance
together; v2 inputs and BOMs cannot qualify this composition. A Git query
failure preserves the actual exit code, affected project and a finite escaped
stderr excerpt with the original length and digest. Diagnostic output remains
a failed observation; it cannot qualify a partial vector or source inventory.
All three Git observation paths use explicit 32 MiB pack windows and a
128 MiB packed-window cache limit. These command-local settings leave source
configuration unchanged and complement the process address-space ceiling;
they are not a hard RSS or cgroup memory quota. A successful limited replay
does not replace the required whole-graph before/after measurements.

Inventory v3 separates gitlink commit references from blob payloads. Each
unmaterialized reference binds its parent tree/index and two identical physical
missing/empty observations; no synthetic size, content SHA or LFS proof is
assigned to it. Indexed project metadata retains the references, while source
shards contain measured blobs. The namespace observer independently checks the
selected view and rejects materialized, aliased, special or changed gitlinks.
An exact worktree-only ` D` status is allowed solely for a committed gitlink
whose two physical observations prove the same missing state. Ordinary blob
deletion, staged changes, and deletion reports for an empty present directory
remain holds; original-vector status must match the complete inventory status.
There are at most 1024 references per project, 40 path components per reference
and 2 MiB of reference metadata. Older inventory v2 records do not qualify this
producer. The outer whole-control v3 BOM remains bound to each complete inventory
digest and raw evidence descriptor; its local authority does not establish
submodule commit content availability, installed behavior or release approval.

Source measurement uses bounded project records and indexed shards rather than
one whole-graph JSON allocation. The admission ceilings are 250000 rows and
128 MiB metadata per project, 32 MiB raw Git tree, 4096 rows and 8 MiB per shard,
5 million graph rows, 2 GiB unique raw evidence, 128 GiB tracked Git source bytes,
100000 descriptors and 32 MiB descriptor-path bytes. Retained cross-project
metadata is bounded at 500000 files and 128 MiB. Each of the two Motorola
non-Git inputs has a separate 16 GiB and 250000-entry ceiling. These are rejection
ceilings, not measured production resource use. Core collection defaults to a
3600-second whole-operation deadline; the original-vector CLI defaults to
1800 seconds. Both default to a 1024 MiB address-space limit; requested ceilings
are at most 7200 seconds and 4096 MiB. Build META publication has a separate
120-second default and 600-second maximum. Child output, process-group
termination and deadline checks remain finite. Partial or timed-out evidence
cannot be promoted by an empty stdout or a later successful shell marker.

The `collect-git` subcommand and original-vector CLI accept
`--git-query-seconds`, defaulting to 30 seconds with a finite 1..300-second
range. Library entry points enforce the same range, rejecting booleans and
non-numeric values before querying Git. Each query receives the lesser of
that limit and the remaining whole-operation deadline; completing one query
does not renew the whole deadline. The option belongs to `collect-git`, after
the subcommand, and does not change the 30-second manifest-projection queries.
Selecting 120 seconds for a slow full-source collection requires retaining
the actual invocation and terminal receipt. Existing output, filter, memory,
cleanup and source-content checks still apply. There is no receipt-schema
migration, automatic retry or qualification from a partial collection.

`tools/android_release_ota.py` consumes owner provenance only with
`--require-owner-source-bom-binding`, `--owner-source-bom` and
`--owner-build-source-inputs`. The legacy and owner modes are mutually
exclusive. Owner admission validates exact source modules, raw inputs and
whole target ZIP before material validation or signing. It verifies the same
binding on the actual signed target-files; an optional legacy member cannot
substitute. Its typed receipt links both actual ZIP digests to one owner
binding and retains all host-only negative claims. Existing timestamp bytecode
caches cannot override either provenance checker.

Signed target-files, OTA and metadata are measured before validation and
published as one checked set. After each rename and after the complete output
scan, the original provenance inputs, original target-files and every host
tool must still match their admitted baselines. Each published member must
match its verified bytes, digest and inode. A mismatch retracts every promoted
member to its partial path and returns a failure receipt; incomplete rollback
is reported as failure. Consumers must require successful terminal execution,
recheck the three actual artifacts against the receipt and retain the source
inputs. Publication consists of sequential filesystem operations, not a global
transaction against concurrent hostile writers. A receipt describes that
observed subject and cannot be reused after its inputs or artifacts change.

Reproduction covers actual temporary Git/LFS trees, projections, GNU Make META
packaging, tiny ZIP signing fixtures, timestamp-cache substitutions, input
movement during publication and whole-output retraction. Test fixture host
tools and mocked cryptography cannot qualify real signing, Kati/Soong, a full
Android image, performance or a physical device. Run the focused test modules
from the current repository; portable fixtures use the registered source
checkers and owned Makefile directly and do not require an external audit
workspace. Full graph, built artifact, independent review and release evidence
must bind the newly changed candidate rather than inherit an older green run.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_evidence.state.v1`
- State authority: **authoritative**
- Partition key: `evidence_id`
- State owned: `evidence index; promotion records`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `evidence_id`
- Maximum declared concurrency: `16`
- Admission resource: `resource_contract.queue_items`
- Lease source: `local_bounded_budget`
- Lock scope: `module-local per-key metadata guard`
- Backpressure: `reject_at_capacity`
- Timeout ceiling: `30000` milliseconds
- Lease expiry: `stop_new_admission_and_fence_authoritative_writes`
- Duplicate/conflict rule: `idempotent_duplicate_or_explicit_conflict`

Per-key operations are linearized while unrelated keys may progress concurrently. Process spawn, external I/O, fsync and provider waits are slow paths and must not execute under a global registry lock. At capacity, admission is rejected before starting a process or publishing an accepted effect.

## 8. Effect, cancellation and uncertainty semantics

Automatic redispatch: **forbidden**.

Cancellation is targeted by exact request, call, job, turn, connection or module identity as appropriate. Cancellation requests and terminal completion races are serialized through the authoritative lifecycle transition. Cleanup frees resources but does not authorize a replacement effect.

An accepted operation lacking authoritative terminal evidence is `unknown` or reconciliation-required. A timeout, disconnect, restart, missing journal entry or process-leader exit is not proof that an external effect did not occur.

## 9. Resource budget and SLO status

Resource budget authority: `docs/machine/resource-budget-provenance.v1.json`.

| Contract item | Current source ceiling |
|---|---:|
| CPU weight | 100 |
| Memory | 67108864 bytes |
| File descriptors | 256 |
| Processes | 16 |
| Threads | 64 |
| I/O rate | 10485760 bytes/s |
| Queue items | 4096 |
| Queue bytes | 67108864 |
| Store bytes | 536870912 |
| Operation timeout | 30000 ms |
| Recovery target | 60000 ms |
| Provisional P99 target | 1000 ms |
| Provisional throughput target | 100/s |
| Provisional availability target | 99.0% |
| SLO recovery target | 60000 ms |
| SLO measurement window | 60 s |

Measurement status: **unmeasured until qualified evidence**.

These values are finite source-admission ceilings and provisional objectives, not benchmark results. They remain observe-only until workload profiles `WL-01` through `WL-12`, environment identity, samples, percentiles and resource observations are retained in a qualifying L2 package.

## 10. Persistence, recovery and reconciliation

Evidence is immutable. Revocation, expiry, subject movement or ambiguous external observation invalidates promotion and leaves the gap open. Reconciliation adds a new signed record rather than altering history.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.

### Immutable intake implementation

`tools/evidence/g1_evidence_core.py::_verify_evidence_snapshot` owns the single
package/gap snapshot. `tools/evidence/g1_evidence.py::verify_evidence_directory`
uses that same snapshot for retention and continuous-lineage checks, without
reopening package files after signature verification. The original report API
and v2 evidence/attestation schemas are unchanged.

`load_trusted_attestation` retains digest-bound raw bytes. Signature verification
uses sealed Linux memfds for key/signature input and sends the retained receipt
to OpenSSL over stdin, from a neutral working directory and finite environment.
Original paths are provenance only, not verification inputs. Missing memfd,
sealing, procfs or the system OpenSSL fails closed. Input size ceilings and
single-link/no-symlink rules are defined in
`docs/QUALIFICATION_AND_EVIDENCE.md`, section 2.3; they do not assert target RSS.

## 11. Security and trust boundaries

A self-hash is integrity metadata, not external authorization. Repository writers cannot mint independent review, installed-target facts, destructive-fault results, signing custody or release authority.

Peer identity, process identity, executable or artifact digest, epoch, namespace and target identity are retained where relevant. Secrets and command content are redacted by default. Emergency inhibit is independent of provider health and prevents new admission without fabricating terminal outcomes.

## 12. Failure matrix and degraded behavior

| Failure | Required classification | Required behavior |
|---|---|---|
| Invalid or unsupported input | rejected-before-accept | no state mutation and no external start |
| Capacity exhausted | rejected-at-admission | no spawn, forward or durable accepted record |
| Timeout or disconnect before terminal proof | unknown/reconciliation-required | stop blind progress; preserve exact identity |
| Process or dependency exit | explicit failure or unknown | converge descendants and fence the epoch |
| Storage I/O or fsync ambiguity | degraded/fail-closed | stop authoritative writes; retain ambiguity |
| Corrupt state | quarantined or fail-closed | no automatic replay |
| Stale writer or lease | fenced | reject the write and emit an audit observation |
| Duplicate identity with changed content | conflict | never deliver the old terminal as the new result |

The degraded state is `fail_closed`. Recovery is `reconcile_before_resume`, and uncertain effects remain `no_automatic_redispatch`.

## 13. Compatibility, migration and rollback

Rolling compatibility is supported under the explicit compatibility and fencing contract. Read/write compatibility currently accepts `v1` and writes `v1` unless the module-specific migration below states otherwise.

Evidence schemas are append-only and versioned. A new verifier may accept older packages only through an explicit compatibility matrix; signed subjects are never rewritten.

Executable module-contract compatibility reads a base migration packet from
the exact ancestor Git commit. Its path and content digest must agree; the Git
entry must be a regular blob of at most 64 KiB; module identity and the reviewed
target schema must match the base version. Diagnostic labels do not change the
module ID. A missing, replaced or retired current-tree copy cannot substitute
for that historical object. Current migration packets retain the separate
descriptor-bound working-tree checks. Unchanged schemas require `NO_CHANGE`,
and a further semantic change needs a new exact packet. Neither the base packet
nor source metadata can assert independent approval of the current head.

EventStore's tighter process-shared memory admission can refuse a previously
accepted history without changing its bytes. A source behavior probe built the
exact EventStore sources from `723b718937f0503c44054b1e28d478cab8f81575` and the
sources from `3bca589c5b8febf9a3420e568eaa872ec478aaf7` in one independent Cargo
harness. A plain 12 MiB JSON string appended and reopened with the earlier
source, while both current default v1 and v2 readers returned
`CapacityExhausted`; the v1 WAL and v2 segment/sidecar bytes stayed unchanged.
That harness used its own retained dependency lock and local Rust 1.95, not the
earlier release binaries, repository lock or canonical Rust 1.93 build. It
demonstrates a source admission boundary, not a release compatibility matrix.
Before rollout, preflight actual retained histories against the selected
reader and memory configuration. A refusal leaves admission inhibited; retain
the original history and compatible reader until an explicitly reviewed
migration or rollback path is proven. Passing bounded streaming tests does not
establish that all histories accepted by an earlier reader will reopen.

Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

## 14. Observability

Record verifier version, exact subject, API object identities, artifact digests and retention, signer and trust-root identity, authorization role, expiry, revocation and every rejected claim.

Every metric and log record is bounded and versioned. Required common dimensions are module ID, instance or service epoch, ordering-key digest, operation class and outcome. High-cardinality raw identifiers are hashed or retained only in access-controlled evidence. Readiness means the module can safely admit work; liveness alone is insufficient.

### Worktree and graph-integrity checks

Every workflow worktree assertion must address the intended checkout explicitly:
`GITHUB_WORKSPACE` for the source checkout, the separately constructed merge
directory for a synthetic merge. A step that changes to `RUNNER_TEMP` must still
check the source checkout. Required path variables must be non-empty. Capture
`git --no-replace-objects ... status` in a separately tested command and reject
both a nonzero Git exit and nonempty porcelain output. Never nest that command
inside `test -z`: an empty output after a Git failure is not proof of cleanliness.
Keep untracked files and submodule changes visible to the assertion.

`tools/tests/test_owner_open_workflow_exact_head.py` executes the actual workflow
guards against temporary repositories, dirty indexes/worktrees, wrong working
directories and failing Git commands. These are L1 tests only. The global graph
verifier additionally requires the complete bidirectional module/open-gap
projection, including external holds. Neither check grants integration authority.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

Source-control archive validation checks members incrementally, retaining names
for duplicate detection without accumulating decoded TarInfo objects. The
compressed archive limit is 64 MiB, with at most 100,000 members, 512 MiB of
ordinary file content and 64 MiB of headers/extension/name metadata. Before
tarfile decodes extensions, each payload is limited to 64 KiB and nesting to 16.
Decoded local/global PAX state permits at most 1,024 fields and 64 KiB of UTF-8
key/value text. Sparse records, links, special files and global size overrides
are rejected. After the tar end marker, only one 10,240-byte zero-padding record
is allowed; reading to gzip EOF also checks the compressed footer. These are
input and parser-state bounds, not an installed or whole-process RSS claim.
Real compressed metadata and limited-address-space regressions exercise early
rejection; canonical Git source packages and bounded PAX/GNU long names remain
supported. Manifest hashes still provide integrity rather than independent
source or builder authorization.

### Source and device command capture

The cross-repository BOM collector, Android smoke and P0.1 collectors use the
same host-only `tools/owner_open_bounded_process.py` implementation. It requires
Linux WNOWAIT, default SIGCHLD and exclusive direct-child reaping before spawn.
All pipe, selector and nonblocking setup is inside the cleanup guard. stdout
and stderr share one byte ceiling, including the BOM collector's declared
maximum; this tightens its former independent per-stream ceilings. Capture
stops while reading at overflow and keeps only bounded partial output.

The new session leader stays unreaped until all possible group signals finish.
A normal leader exit is insufficient for success when a same-group worker is
still live, even if that worker closed its output pipes. Cleanup requires two
complete same-namespace procfs observations of an exited leader and no live
group members; it bounds scans to 65,536 entries, 4,096 bytes per stat record
and a one-second cleanup deadline. Every matching TGID also requires a complete
task-directory scan, with at most 65,536 task entries under the same deadline.
A zombie process leader can still have live sibling threads; its `Z` state
alone never proves group quiescence. The source regression uses a real pthread
member whose leader is zombie while its worker remains alive after closing
output pipes, and refuses a successful normal-leader receipt. Incomplete
process/task observations, setup failures,
cleanup failures and nonfinite timeouts cannot produce a successful receipt.
The collectors map failures to their existing evidence-error classifications.
Cleanup retries an interrupted owned wait or close once within its finite
budget, attempts the remaining resources and propagates the first interruption.
Persistent interruption or close/reaper failure does not prove resources closed.

The retained R5 target-harness collector also uses this helper to enforce its
combined 64 MiB capture limit while reading. Its R5-GAP vocabulary is separate
from current G1 gap intake; repairing it does not qualify a G1 target. Real
process tests cover setup failures, early leader exit, held and closed pipes,
output overflow and refusal before spawn. These bounds describe captured bytes
and local owned-group observation, not total interpreter RSS, escaped sessions,
uninterruptible I/O, a protected operator or installed/release qualification.

### Product workload implementation admission

The selected-product performance harness captures a closed manifest of 16
repository Python files. This includes the broker entrypoint and all ten of its
transitive sibling implementations. The host reproducibility verifier captures
19 files, including that complete nested performance manifest. Nested verifier
and cleanup execution uses admitted snapshots; broker sibling imports execute
from the captured owner-only, single-link private copies only for broker
workloads. Missing, modified, symlinked, multiply linked or additional broker
custody files, or a nonprivate custody directory, stop startup before process
creation. The custody is checked again before reporting. There is no repository
import fallback or added `PYTHONPATH`. The manifest does not separately attest
the system Python standard library or a hostile same-UID execution environment.

The original wrapper-only private copy failed startup with
`ModuleNotFoundError`. Regression tests exercise actual private-copy startup,
source mutation after capture, incomplete manifests and custody rejection,
plus all eight workloads through the complete private execution path using
selected debug Host/Core binaries. These local behavior tests do not qualify
an installed target or authenticate the origin of caller-selected binaries.
Adding the omitted broker implementations changes the manifest digest and
requires a new baseline; an artifact with the previous manifest cannot provide
a comparison pass. Canonical compiler/build receipts, exact-head source CI,
protected runner authorization and target evidence remain separate requirements.

Product collection and broker startup require Linux WNOWAIT and default
SIGCHLD before spawn, with this runner as the exclusive direct-child reaper.
Their original session leader remains unreaped through TERM/KILL and bounded
same-namespace procfs observations; the authenticated facade preserves its
execution descriptors and delegates to that common cleanup path before final
anchor reaping. stdin writes share the nonblocking stdout/stderr selector and
operation deadline. Membership checks retain the observable anchor and bound
entries, stat bytes and scan time; incomplete or unreadable observations fail
closed, and a partial deadline scan cannot supply terminal proof. Real local
process fixtures exercise held stdout after leader exit, TERM refusal, output
flooding, small-pipe input backpressure, complete partial writes, normal cleanup
and pre-spawn SIGCHLD-ignore rejection, with exact descendant pidfd and FD checks.
A terminal-process reaper-failure fixture verifies that pipes close while the
error and retained anchor remain available for reconciliation.
These tests do not establish cleanup for escaped sessions/groups, a hostile
external reaper or an uninterruptible kernel syscall. They do not qualify a
protected runner or installed process graph. The revised harness needs a fresh
manifest and baseline. Earlier direct-core cleanup probes are source/API
fixtures: the earlier authenticated facade already had a retained-anchor cleanup
override, so those probes do not establish the same failure in that entrypoint.

Product baseline comparisons also bind the effective scratch mount through
its opened directory descriptor, kernel mount ID and complete mount-record
digest, device/filesystem identity, boot and mount namespace. Ordinary
directories on one mount remain comparable; other mounts, overlay backing
options, boots or namespaces differ. Incomplete metadata, zero filesystem IDs
or an unsupported native statfs ABI remain unavailable and reject comparisons
while permitting an explicitly unqualified baseline observation. The supported
layout is Linux LP64 x86-64/aarch64. Top-level environment, configuration and
Python/shell/harness observations must exactly match the closed comparison
projection; resealing contradictory metadata cannot make it admissible.
Sampling counts may differ only with complete raw samples on each side.

These start/end snapshots describe observable same-boot mount/filesystem
identity. They do not prove physical storage topology, detect a change restored
between snapshots or prevent device-mapper remapping or same-ID cloned media.
Independent storage custody, protected-runner approval and controlled installed
workload/resource evidence remain holds. Adding this identity changes the
harness manifest and requires a fresh baseline; earlier filesystem-type-only
reports cannot establish a comparison against it.

### Reproduction entrypoint

- Verification source: `tools/tests/test_g1_evidence.py`

Run from the repository root in an isolated host source-test environment:

```sh
python3 -m unittest tools.tests.test_g1_evidence -v
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

### Complete Python source validation and prerequisite observations

Both exact-source-head `docs-graph` and synthetic-merge qualification run the
complete `tools/tests/test*.py` Python discovery set, not only a hand-picked
regression subset. Each job explicitly selects Python 3.13 and Rust/Cargo 1.93.0.
The Rust identity is required by the Python performance-harness tests as well as
by locked source metadata; the runner image's moving default is not the pin.

The synthetic-merge job declares job-level `cache-mode: none`. A manual dispatch
may run a selected fork while its run is scoped to `main`; `contents: read` and
disabled checkout credential persistence do not restrict the separate Actions
cache token. The cache service denies restores and saves for this job. Verify
the effective mode from the runner's `Set up job` observation `Cache mode: none`.
The runner exposes `ACTIONS_CACHE_MODE` to Node actions, not Bash `run` steps;
absence in a shell is not a failure of the native restriction. Never substitute
a workflow environment variable for job-level token enforcement. This
observation grants no target or release evidence.

Before candidate checkout, each lane installs the distribution `acl` package
using fixed absolute system commands from `RUNNER_TEMP`. This privileged step
executes no repository script. Repository tests run as the ordinary hosted user,
never under sudo. The package repository remains the hosted environment's
configured distribution source; its observed package version is retained, not
misrepresented as a fully pinned package/image supply-chain attestation.

A separate unprivileged prerequisite step runs outside the candidate checkout.
It requires real `python3`, `rustc`, `cargo`, `setfacl` and `getfacl`, checks the
selected Python/Rust/Cargo versions, and writes then reads a named-user ACL on
its own disposable file in `RUNNER_TEMP`. The file is removed on success or
handled failure. Missing tools, wrong versions, root execution or nonfunctional
ACL support stop the lane; they do not convert required tests into skips.

Verbose discovery output and prerequisite observations are uploaded even after
failure as diagnostic artifacts bound by their workflow run and source head.
`pipefail` preserves a nonzero unittest status through `tee`. A diagnostic upload
or successful prerequisite probe is not a qualification receipt: the existing
aggregate still requires every job and workflow family at the exact subject.
No worktree, source/merge identity, independent-review or target gate is relaxed.

Local execution needs the same real dependencies, an owner-controlled checkout
and suitable HOME. A sandbox without Rust or ACL cannot claim complete green
validation. Guard tests use clearly test-only command doubles solely to verify
rejection and exit-code propagation; these are not substitute tools for the
complete source suite. Report successful methods, failed/error methods, skipped
methods and class-setup skips separately; a skipped class setup is not included
in unittest's `testsRun`. Installed performance and L2-L6 claims still require
independent, level-correct evidence and are never inferred from these probes.

### Test-fixture signing material isolation

The core and live evidence tests use a private, per-invocation temporary root.
Only its `packages` child is scanned as candidate evidence; detached receipts,
signatures and test-only keys remain outside that child but inside the same
cleanup scope. Successful verification, expected rejection and signing errors
all remove that invocation's material. Overlapping invocations do not reuse a
fixed filename under the shared temporary-directory root. The regression forces
two real fixture signatures to coexist before verification; it does not replace
signature checks, create trusted target evidence or grant promotion authority.

### Bounded PR-aggregate HTTP and JSON intake

`tools/g1_pr_aggregate_api.py::GitHubApi` is the read-only transport used by
`verify-g1-pr-aggregate.py`; it does not run or rerun workflows. JSON responses
are limited to 16 MiB and artifact downloads to the existing 256 MiB archive
ceiling while reading, not after an unbounded download. Reads use at most 64 KiB
or remaining capacity plus one overflow sentinel. Artifact metadata exceeding
the archive ceiling is rejected before any download. The existing exact-size,
SHA-256, ZIP member, source/run identity and final-currentness checks still apply.

A declared Content-Length must be unique, well-formed, within the selected bound
and equal the captured length. Conflicting length/transfer headers, unsupported
encodings, partial HTTP status and duplicate redirect locations fail closed.
The transport requests identity encoding; the standard HTTP layer handles
chunked framing while the same capture ceiling applies to resulting body bytes.
This does not add archive decompression formats or weaken ZIP expansion limits.

Redirect handling is iterative, limited to five hops, rejects repeated URLs and
closes each HTTP error response before following its location. URLs are bounded
to 8,192 ASCII bytes and must remain HTTPS without userinfo, control characters,
fragments or invalid ports. JSON requests remain on the configured API origin;
artifact requests may follow HTTPS storage redirects. API credentials are sent
only to the initial same-origin request, never restored after any redirect,
even one returning to that origin. HTTP errors close without consuming their
bodies. Diagnostics do not echo response bodies, signed URL queries or network
exception text. Successful aggregate reports also exclude the initial and final
transport URLs: a capability can occur in a URL path as well as its query. The
artifact diagnostic field `download_url` is replaced by `archive_api_path`, a
repository-relative `repos/<owner>/<repo>/actions/artifacts/<id>/zip` locator
constructed from the validated repository and numeric artifact ID, not copied
from a response. Artifact ID, name, byte count, SHA-256, expiry and semantic
bindings remain unchanged. This is a report-diagnostic compatibility change,
not a receipt-schema change or a weaker verification rule. Consumers of the old
download field must use the repository-scoped locator with their own API access;
reports do not retain a capability for unauthenticated artifact access. Holding
all evidence and observation inputs fixed, redirect-URL rotation alone no longer
changes the aggregate report hash. Low-level `ApiResponse.url` remains transient
transport state and must not be logged or serialized by other callers.
No network failure authorizes retries, source promotion or target dispatch.

Each HTTP operation has a shared monotonic deadline across redirects and body
reads. Its timeout defaults to 30 seconds and accepts only finite numeric values
within 0.001..300 seconds. Checkpoints around open/read calls reject a completed
response that arrives after expiry. These checks do not preempt synchronous
DNS, TLS, HTTP-header parsing or blocked kernel I/O; the enclosing job timeout
remains the outer execution bound. Body buffering and JSON parsing have finite
limits but can consume more memory than the raw-byte ceiling; no measured RSS,
throughput or installed SLO is claimed.

The shared aggregate JSON decoder enforces the 16 MiB member limit and nesting
of at most 64 before invoking the recursive decoder, preserves brackets inside
quoted strings, and rejects duplicate members, nonfinite constants and floating
point overflow. Integer-conversion/recursion failures are reported as aggregate
errors, not unhandled decoder exceptions. These stricter admission rules do not
change receipt schemas or make self-hashes into signatures.

The existing `tools.tests.test_g1_pr_aggregate` suite exercises bounded/short reads,
Content-Length errors, real standard-library chunked-response decoding, redirect
loops and hop limits, close ordering, credential stripping, deadlines and strict
JSON. Success-path regressions also exercise a signed storage redirect, query
and path capability omission from all four workflow-family reports and persisted
JSON, and report-hash stability under redirect-URL rotation. They retain exact
archive-byte/digest checks and initial-request-only token behavior. Its in-memory
transports contain test-only bytes, not live GitHub results.
Run it with `python3 -m unittest tools.tests.test_g1_pr_aggregate -v`; existing
exact-head and synthetic-merge complete discovery includes this suite. Local
success cannot replace terminal hosted CI, independent approval or L2-L6 evidence.

## 16. Deployment and runbook

On evidence mismatch, stop promotion, preserve packages and detached material, re-fetch authoritative objects, verify currentness and revocation, and require a new independently administered attestation for a changed subject.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

Signature observations accept both GitHub REST commit envelopes and Git
Database commit envelopes only when their top-level `sha` equals the expected
head. A strict `verified: false` is observed-but-unsatisfied; missing identity,
malformed booleans or contradictory envelope representations are unobserved,
never successful. This normalization grants no integration or release authority.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-DOC-SINGLE-TRUTH-001`, `GAP-GOVERNANCE-001`, `GAP-FAULT-MATRIX-001`, `GAP-RELEASE-001`.

### GAP-DOC-SINGLE-TRUTH-001 — exit L1

One machine truth generates every current-state and traceability view.

Exit evidence must demonstrate:
- legacy global documents are absent from the working tree.
- generated views match machine truth.
- exact-head CI and an eligible independent review pass.

### GAP-GOVERNANCE-001 — exit L1

Protected integration binds exact-head checks and a non-author approval.

Exit evidence must demonstrate:
- required checks pass on the exact integration head.
- approval is bound to that same head.
- there is no direct unreviewed integration.

### GAP-FAULT-MATRIX-001 — exit L5

Destructive crash, storage, disconnect, USB, reboot and power-loss cuts are executed.

Exit evidence must demonstrate:
- pre-cut durable state is bound.
- fault method is independently controlled.
- post-restart reconciliation is retained.
- redispatch count is zero.

### GAP-RELEASE-001 — exit L6

Signing, transparency, AVB, rollback, OTA, key custody and human authorization are bound.

Exit evidence must demonstrate:
- cryptographic verification passes.
- independent release authorization exists.
- all other gaps are closed.
- public release is explicitly enabled.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
