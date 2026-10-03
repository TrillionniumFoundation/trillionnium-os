# MOD-ANDROID — Android product and SELinux integration

This document is the detailed source-development, integration and qualification contract for `MOD-ANDROID`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-ANDROID`
- Module version: `1.0.0`
- Name: **Android product and SELinux integration**
- Plane: `platform`
- Primary owner: `team-android`
- Backup owner: `team-rootlinux`
- Maturity: `SOURCE_OVERLAY_L3_PENDING`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `android-integration/working-tree/vendor/trillionnium/owner-open`
- `android-integration/working-tree/packages/modules/adb/daemon/restart_service.cpp`
- `android-integration/working-tree/vendor/trillionnium/config/common_owner_open.mk`
- `android-integration/working-tree/vendor/trillionnium/config/common_owner_open_base.mk`
- `tools/generate-owner-open-common-base.py`
- `android-integration/working-tree/vendor/trillionnium/config/common_mobile.mk`
- `android-integration/working-tree/vendor/trillionnium/config/common_mobile_full.mk`
- `android-integration/working-tree/vendor/trillionnium/config/common_full_phone.mk`
- `android-integration/working-tree/vendor/trillionnium/config/common_owner_open_mobile.mk`
- `android-integration/working-tree/vendor/trillionnium/config/common_owner_open_mobile_full.mk`
- `android-integration/working-tree/vendor/trillionnium/config/common_owner_open_full_phone.mk`
- `tools/generate-owner-open-phone-config.py`
- `tools/owner-open-phone-chain.v1.json`
- `android-integration/owner-open-profile/profile-v2.json`
- `tools/verify-owner-open-android-source-closure.py`
- `tools/verify-owner-open-android-source-closure-v2.py`
- `android-integration/working-tree/trillionnium-sdk/Android.bp`
- `android-integration/working-tree/trillionnium-sdk/owner-open/res/values/config.xml`
- `tools/verify-owner-open-sdk-selection.py`

- `android-integration/working-tree/build/make/core/Makefile`
- `tools/verify_owner_target_files_binding.py`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- Soong graph.

Operationally, the required flow is:

The dogfood or userdebug product graph explicitly selects owner-open packages and policy, compiles the service graph, records target-files inventory, boots an authorized image and verifies installed identities. User/release variants fail closed unless separately authorized.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

The native ADB restart-service overlay returns an explicit failure when its
optional root service is missing or fails. It grants no root access. Its frozen
upstream baseline must match before application; the isolated diagnostic view
does not qualify a dirty Android source tree or installed target.

## 3. Non-goals and authority boundary

Explicit non-goals:

- second semantic authority.

Android services and SELinux domains remain mechanical. No Binder service becomes a second semantic authority. Privileged properties, service-manager access and writable paths require explicit build-variant gates and compiled-policy evidence.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-ROOTLINUX`, `MOD-BROKER`, `MOD-TRANSPORT`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_android.api.v1`
- Catalog input labels: `android_product_request_v1`
- Catalog output labels: `android_graph_state_v1`
- Catalog error labels: `android_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `tools/verify-owner-open-android-source-closure-v2.py` — `verify`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

`product.mk`, `Android.bp`, the init rc and the SELinux domain/context files under the owned Android overlay are the composition inputs. This verifier checks source selection only. Real Soong/policy compilation, target-files inventory and installed image binding remain distinct L3 operations.

Android defers `inherit-product` expansion until it has evaluated each product
node. A local `filter-out` cannot remove a sibling's inherited packages.
`common_owner_open.mk` therefore inherits the generated
`config/common_owner_open_base.mk` and the owner-open product node. Run
`python3 tools/generate-owner-open-common-base.py --check` before composition.
The generator preserves shared Android configuration from the sealed
`config/common.mk`, removes its complete legacy Agent/RootFS/P01/debug-ADB
section and excludes the old init module before inheritance. Sealed products
retain their original common input. The owner-open init separately preserves
TERMINFO and the ordinary bugreport key chord; it does not select the six old
runtime control services. Same-source regression tests execute pinned Android
inheritance macros under GNU Make for all variant/adb-root combinations. These
tests use empty unrelated audio/version fixture includes with SDK disabled and
cannot qualify a complete Android product. Rebuild target-files and inspect
actual packages, init, SELinux and selected artifact identities after this
graph change; an older image is not a compatible evidence substitute.
Generator reads use bounded regular-file descriptors with identity checks;
publication rejects a preexisting output symlink and replaces its directory
entry with a completed private temporary inode. Publication is not a
compare-and-swap against concurrent hostile writers. A late error can leave a
complete output visible, so admission requires a successful standalone exit
and a subsequent `--check`. Raw directory closure gets one attempt; unknown
closure or asynchronous interruption requires the generator process to exit.

The shared SDK library is also part of the product closure. Its sealed
`required` feature XML, platform resource array and SystemServer dispatch can
select the old Direct System API service even when no legacy runtime package
appears in the local product list. The owner-open product exports the build
boolean `trillionnium_owner_open.enabled`. The guarded SDK module definitions
then remove the Agent identity/Binder static edges, the System API feature XML
and the old Agent/Capability Lease/Open URI/plugin implementation sources.
Unset or false uses the original sealed module inputs. The SDK's owner resource
directory overlays only the external service array, retaining seven ordinary
profile, hardware, display, trust, settings, global-action and health services.
Ordinary shared SDK types and services can retain their platform namespace;
that namespace alone is not proof of a legacy semantic service.

Run `python3 tools/verify-owner-open-sdk-selection.py` with the other source
gates. The constrained Blueprint/source regression is not a Soong evaluator.
It checks typed literal properties and a restricted owned-product Make grammar,
including one unconditional registered bool export. Dynamic setters, unknown
conditional bodies, definitions and other namespace writes are rejected.
Licensed upstream macro fixtures exercise the actual GNU Make export; the
complete inherited Kati product and Soong configuration remain build gates.
Full compilation must validate all remaining Java dependencies and prove the
installed platform jar excludes the old implementation class definitions,
the compiled resource array contains exactly the seven ordinary services,
and the legacy feature XML is absent. Source tests, a stubbed Java startup
fixture and package-name filtering do not qualify those built artifacts.

The empty `android-integration/.find-ignore` is a registered Soong Finder
template boundary. If this control repository is present inside an Android
checkout, Finder prunes only this release-input mirror; apply its working-tree
files to their declared Android project paths before building. The actual SDK,
Authority, Shell and owner-open module directories remain discoverable. Do not
place the marker at the control-repository root or an actual Android project
root. This build rule does not qualify a source BOM or an installed image.

### Owner source provenance and build-time META

`tools/owner_source_provenance.py` produces the distinct
`org.trillionnium.owner-source-bom.v2` receipt for
`owner-open-whole-control-v2`. Its candidate includes the exact control commit,
tree, source-archive digest and actual regular-file count. A new control tree
must supply a newly measured count; a prior candidate count is not reusable.
The current profile covers exactly 1170 resolved projects, with 15 explicitly
bound private project generations and one whole control repository. This is a
local measured composition. It does not migrate the canonical public manifest
or assert that an unapproved private composition is a clean public source.

Graph qualification requires all twelve exact input descriptors: resolved
manifest, control archive, inventory index, canonical custody, original
before/after vectors, manifest repository inventory, Motorola blob trees,
generated source delta, owner source selection, manifest projections and
private composition. `collect_owner_source_vector.py` measures the 1154
original project work trees with Git filters, hooks and fsmonitor disabled.
The raw status remains evidence: a hydrated LFS payload may appear modified
under this policy. The content verifier must prove its canonical committed LFS
pointer, committed attributes and complete actual payload size/SHA. Ordinary
index or source modifications, uncommitted attributes, unhydrated pointers and
missing projects reject the graph. No external filter or network hydration is
run to make a checkout appear clean.

The measured graph also binds the complete two Motorola non-Git trees, each
manifest copy/link projection and actual destination bytes or directory
closure, private/control generations and the complete selected source inputs.
The current generated-delta contract accepts only a proved empty delta; a
nonempty delta needs a new generator/input contract. Observations are
sequential and explicitly do not claim a globally atomic snapshot.

`tools/verify_owner_target_files_binding.py` materializes the distinct
`org.trillionnium.owner-android-source-bom-binding.v2` projection from the exact
BOM and `org.trillionnium.owner-android-build-source-inputs.v1`. Build inputs
bind the same candidate, resolved manifest, raw BOM digest and finite ASCII
stage ID. The owned `build/make/core/Makefile` overlay selects this path only
when merged `PRODUCT_SYSTEM_EXT_PROPERTIES` contains
`ro.trillionnium.owner_open.enabled=true`. It requires three explicit build
inputs:

```text
TRILLINNIUM_OWNER_SOURCE_BOM_JSON
TRILLINNIUM_OWNER_SOURCE_BUILD_INPUTS_JSON
TRILLINNIUM_OWNER_SOURCE_BOM_BINDING_JSON
```

The target-files rule depends on these files and the three observer modules.
Immediately after creating its private META directory, it runs
`stage-binding-env` with a 120-second budget. The writer verifies the expected
projection, rejects unsafe existing entries and publishes one new regular
`META/trillionnium-owner-source-bom-binding.json` through its held directory
descriptor. It runs before the META member list and final ZIP are generated.
Failure terminates the rule. An existing target-files ZIP may not be patched
afterward to claim this build provenance. Sealed products retain their existing
rule and require no owner inputs.

The ZIP reader checks the entire current ZIP digest on one stable descriptor,
canonical unique members, finite central-directory allocation and the exact
owner META bytes. A missing, duplicated or spliced projection rejects the
artifact. This check does not prove every image entry's semantics, executable
ART behavior, compiled SELinux policy, release signature or installed identity.
Those remain separate Android and physical-target gates. The old P0 member and
schema remain available only through their separate legacy mode.

Observer code is executed from the same bounded FD-stable source bytes that
were checked against its source contract. Existing Python bytecode caches and
ambient modules cannot supply the executed implementation. Missing code,
changed source or deadlines fail closed, including a late deadline after an
otherwise complete observation.


The phone entrypoint must inherit `config/common_owner_open_full_phone.mk`,
which retains the ordinary full-phone and mobile configuration through
`common_owner_open_mobile_full.mk` and `common_owner_open_mobile.mk`. Only
its final common edge selects `common_owner_open.mk`. The three sealed
mobile/full/phone snapshots remain byte-for-byte unchanged. Run
`python3 tools/generate-owner-open-phone-config.py --check`; its fixed
`tools/owner-open-phone-chain.v1.json` rules bind each snapshot to its
project/head/tree/blob, byte count and SHA-256. Each owner output rewrites
exactly one inherit edge. The generator bounds each source at 128 KiB,
metadata at 16 KiB and the whole check at 15 seconds, rejects aliases,
multiple links, changed inputs and duplicate metadata, and verifies every
output and the unchanged inputs before returning success. A failed write
is not a qualified source generation; rerun the check on all three outputs.

For the declared private Fogos entrypoint, source composition must replace
its sealed full-phone edge and remove its known appended owner product
suffix, retaining every other byte, including its userdebug ADB opt-in.
The closed before/after rule rejects unknown or already rewritten inputs.
Importing the generic owner node in isolation cannot prove this actual
phone entrypoint. The source fixture exercises the retained Android
inherit macros across user/userdebug/eng, with unrelated hardware/core/audio
inputs stubbed and SDK disabled; it does not qualify full Kati or Soong.
Before image batches, inspect the actual generated product selection with
the active main/debug/eng package fields: require the nine owner product
modules, retain ordinary phone/SDK modules, and reject the complete retired
runtime/P01/init selection. A typed owner boolean alone is insufficient.

The source profile lists all three sealed baselines, owner outputs and
phone generator/rules as required inputs; the source-closure check also
runs the exact phone generator check. A source-only success keeps the
actual phone entrypoint and compiled graph qualification false.
The profile's implementation-path catalog covers the full module source,
including those baseline inputs. Listing a baseline there does not select
its sealed Make product edge; the generated owner phone wrappers determine
the actual inheritance edges, which require a fresh compiled graph check.

The source-closure verifier executes its common generator, phone generator and SDK checker
from pinned raw source bytes, and its v2 facade admits the core verifier
in the same way. Each single-link helper is bounded at 1 MiB with a five
second whole binding deadline; every parent is opened without following
symlinks, and the held descriptor, directory entry, SHA-256 and file
identity are checked before and after execution. Bytecode caches supply
no code to these entries. The facade registers only the admitted core
namespace for dataclass annotation resolution and restores any prior
namespace if admission fails. The cache regression includes an actual
retired init in the source fixture: stale helper code must not turn that
source rejection into success. These are source checks, and cannot replace
the actual product graph, compiled SDK, target-files or installed tests.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_android.state.v1`
- State authority: **authoritative**
- Partition key: `boot_id`
- State owned: `Android service graph; SELinux policy projection`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `boot_id`
- Maximum declared concurrency: `16`
- Admission resource: `resource_contract.queue_items`
- Lease source: `module_instance_lease`
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

Boot and service epochs bind observations. Failed policy or package composition stops qualification; it is not repaired by host-side text checks. Rollback uses an authorized image with compatible state and anti-rollback rules.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.

## 11. Security and trust boundaries

Android services and SELinux domains remain mechanical. No Binder service becomes a second semantic authority. Privileged properties, service-manager access and writable paths require explicit build-variant gates and compiled-policy evidence.

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

Rolling compatibility is not supported across a live mixed-version boundary. Read/write compatibility currently accepts `v1` and writes `v1` unless the module-specific migration below states otherwise.

Android integration moves through a clean pinned source checkout, evaluated product graph, compiled Soong and SELinux outputs, target-files inspection and installed-image qualification. Source overlays alone do not migrate a device.

Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

## 14. Observability

Retain manifest commits, lunch target, variant flags, Soong graph, policy hashes, target-files package/service contexts, boot ID, SELinux enforcing state and installed process identities.

Every metric and log record is bounded and versioned. Required common dimensions are module ID, instance or service epoch, ordering-key digest, operation class and outcome. High-cardinality raw identifiers are hashed or retained only in access-controlled evidence. Readiness means the module can safely admit work; liveness alone is insufficient.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

### Reproduction entrypoint

- Verification source: `tools/tests/test_verify_owner_open_android_source_closure.py`

Run from the repository root in an isolated host source-test environment:

```sh
python3 -m unittest tools.tests.test_verify_owner_open_android_source_closure -v
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

## 16. Deployment and runbook

On graph or policy mismatch, halt image promotion, preserve out and target-files metadata, compare against the pinned manifest and negative variant matrix, and rebuild from a clean checkout.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-PRODUCT-ENTRYPOINT-001`, `GAP-ANDROID-GRAPH-001`, `GAP-PHYSICAL-ADB-001`, `GAP-RELEASE-001`.

### GAP-PRODUCT-ENTRYPOINT-001 — exit L3

One install manifest selects the product entrypoint and internal children.

Exit evidence must demonstrate:
- source entrypoint is unambiguous.
- target-files contain the exact selected binaries.
- foundation stubs are absent from product inventory.

### GAP-ANDROID-GRAPH-001 — exit L3

A clean Android graph contains selected owner-open components and no legacy semantic nodes.

Exit evidence must demonstrate:
- clean source and target-files are retained.
- Soong, init, SELinux and package inventory agree.
- installed manifest identities match.

### GAP-PHYSICAL-ADB-001 — exit L4

Ordinary ADB and visible effects are proven on an authorized physical device.

Exit evidence must demonstrate:
- device enumeration and explicit target operation are retained.
- raw unauthorized, offline and failure output is retained.
- visible mutation and continued turn are observed.

### GAP-RELEASE-001 — exit L6

Signing, transparency, AVB, rollback, OTA, key custody and human authorization are bound.

Exit evidence must demonstrate:
- cryptographic verification passes.
- independent release authorization exists.
- all other gaps are closed.
- public release is explicitly enabled.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
