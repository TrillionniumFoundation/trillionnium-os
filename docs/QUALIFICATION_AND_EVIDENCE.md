# Trillionnium OS Qualification and Evidence

Status: **NORMATIVE**

## 1. Evidence ladder

| Level | Meaning |
| --- | --- |
| L0 | parsed contracts, graph and source-shape checks |
| L1 | exact-checkout unit, property, concurrency, process and benchmark tests |
| L2 | installed Root Linux broker, host, provider, modules and lifecycle |
| L3 | clean Android source, Soong, init, SELinux, target-files and image |
| L4 | authorized physical same-turn shell, job and ordinary ADB |
| L5 | destructive crash, storage, disconnect, USB, reboot and power-loss recovery |
| L6 | signed release, transparency, AVB, rollback, OTA and independent authorization |

A lower level never implies a higher one.

## 2. Canonical evidence object

Every evidence package binds:

```text
evidence schema and level
program, architecture, protocol and module versions
repository, branch, source commit and tree
lockfile and toolchain identity
environment and hardware identity
commands and finite environment allowlist
test and benchmark counts
raw observations
artifact name, size and digest
claim ceiling and negative claims
producer, operator, reviewer and authorization state
timestamps and retention
```

Missing or contradictory fields fail closed.

### 2.1 Checked-in evidence index records

`machine/evidence-index.v1.json` is an index of evidence identities and claim
ceilings, not a substitute for the complete evidence package.  Every index
record carries the `evidence-package.v1` and `evidence-binding.v1` schemas.
Fields that are not retained in the checkout are represented explicitly as
`null` with a `NOT_OBSERVED` hold and a reason; an omitted field, an unexplained
null, or a contradictory hold is invalid.  The complete command manifest,
raw observations, artifacts, environment/target/device identity, and review
bindings remain in the producing CI or qualification artifact.  An index row
alone never promotes a claim or closes a higher-level gap.

### 2.2 Protected L1 pull-request aggregate

The server-required `L1 exact-source-head aggregate candidate` context is the
repository-controlled L1 integration gate.  On a pull request it must not pass
from its own source jobs alone.  It also reads the live pull request and
protected integration branch, selects the newest exact-subject run of each
ordered-merge, Android evaluated-matrix, and strict evidence-intake workflow,
and requires every declared job to finish successfully.

The aggregate downloads every retained artifact, compares its byte count and
GitHub SHA-256 metadata with the downloaded archive, rejects unsafe or ambiguous
ZIP members, and validates the embedded base/head/parent order, merge tree,
Android claim ceiling, evidence source identity, and no-redispatch/no-release
boundaries.  It then re-reads the pull request, branch protection, and newest
workflow-run identities.  Movement, retargeting, a newer run, an older green
run, a digest mismatch, or a widened claim fails the required context.

This transitive source gate is not an external signature and cannot promote a
gap.  A current complete-subject attestation still requires a detached signature
under an independently administered out-of-repository trust root.

### 2.3 Immutable input snapshots

Offline intake reads each package and the gap definitions once. Structural,
signature, retention and lineage validation operate on the same in-memory
snapshot; a later pathname edit, removal or new package is not incorporated
into that report. A report identifies the observed snapshot, not an ongoing
watch of the input directory. Re-run verification for any intentionally changed
input set and never apply a report to a different source or gap register.

The report and non-mutating promotion plan carry `gap_specs_sha256`: SHA-256
of canonical JSON `{schema: org.trillionnium.g1.gap-definition-snapshot.v1,
gaps: [...]}` with entries sorted by ID, each containing `id`, `status`,
`exit_level` and `evidence_class`. Planning checks these same normalized inputs
before deriving transitions. Missing or changed bindings fail closed. Prose and
acceptance rules remain bound by the source tree, not this normalized digest.
The aggregate requires report/plan digest, unresolved set and closure flags to
agree. Existing report/plan schema identifiers are retained with this additional
binding; older reports without it must be regenerated before planning or intake
aggregation. This digest is not a signature or independent authorization.

The detached receipt retains the exact raw bytes checked by its out-of-band
SHA-256. OpenSSL verifies those bytes from stdin and reads the pinned public key
and detached signature from immutable, sealed descriptors. It never reopens
their original paths. The parsed receipt must equal the retained signed bytes.
The Linux verifier requires `memfd_create`, file sealing, `/proc/self/fd` and
an independently installed `/usr/bin/openssl`; absence fails closed, with no
mutable-path fallback. It runs from `/` with a finite environment and disables
inherited loader/provider/config search settings. This is RSA-SHA256 input
binding, not a claim of production key custody or FIPS qualification.

Inputs are regular single-link files opened component-by-component without
following symlinks. FIFOs/devices, noncanonical paths, changing files and oversized
inputs are rejected before verification. Limits are 1 MiB per receipt/package,
64 KiB per public key, 16 KiB per signature, 4096 packages and 64 MiB aggregate
package input. These are parser ceilings, not measured resident-memory limits.

`tools/tests/test_g1_evidence.py::G1EvidenceByteBindingTest` exercises replacement
of key/receipt/signature, inter-layer package and gap changes, a newly inserted
L2 fixture with only an L1 signature, descriptor sealing/cleanup, unsafe paths
and finite inputs. Keys and observations in those tests are ephemeral fixtures;
no test receipt supplies an independent approval or promotes a real gap.

## 3. Module evidence

Each module supplies evidence for:

- API and validation;
- state-machine and duplicate/conflict behavior;
- concurrency and ordering;
- resource bounds and performance;
- migration and rollback;
- degraded state and recovery;
- installed identity where applicable;
- destructive fault families where applicable.

System capability evidence additionally proves interactions across module
boundaries.

## 4. Performance evidence

Performance artifacts bind workload ID, warmup, repetitions, environment,
durability class, resource policy, control mode and raw samples.

A summary without raw data and exact source identity is not a regression gate.
A local improvement must include system-objective impact.

## 5. Fault evidence

Every fault record includes:

```text
precondition
last durable state before cut
fault injection method
independent control identity
observed process/storage/transport/device result
post-restart reconciliation
redispatch count
cleanup result
last and next cursor
negative claims
```

Required L5 families include provider, core, transport, broker, client,
job descendant, backpressure, ENOSPC, fsync ambiguity, corruption, USB loss,
ADB server loss, device reboot, power loss and emergency stop during fault.

## 6. Review independence

Source mechanics may be authored and tested by the implementing team.
Promotion of protected integration, target/image/device/fault evidence and
release claims requires the independent roles defined by the level.

A stale review, self-review, synthetic target output or manually edited status
cannot close a gap.

## 7. Gap transitions

```text
OPEN
 -> SOURCE_CLOSED_PENDING_EVIDENCE
 -> CLOSED
```

`EXTERNAL_HOLD` is used when required authority, target, device, fault
infrastructure or signing material is absent.

`zero_gap=true` is legal only when every gap is CLOSED at its declared level.
`public_release=true` additionally requires the release gap, all other gaps and
explicit human authorization.

## 8. Current boundary

The canonical G1 pull request retains separate exact-source, ordered-merge,
Android evaluated-graph, and evidence-intake packets.  The protected L1
aggregate binds those repository-controlled packets to one unchanged live
base/head subject, while independent review and detached-attestation rules bind
human and signing authority.

Passing that aggregate proves neither installed Root Linux/Codex nor compiled
Soong/SELinux, target-files, a physical device, destructive recovery, signing
custody, or public release.  Those L2–L6 facts remain external until genuine
independently reviewed packages satisfy their declared exits.
