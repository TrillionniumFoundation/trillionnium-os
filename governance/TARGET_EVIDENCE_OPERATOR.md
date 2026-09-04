# Owner-Open R5 / G1 target-evidence operator contract

Status: **repository route only; external admission and target execution required**.

The tracked workflow `.github/workflows/owner-open-r5-target-evidence-capture.yml`
no longer allocates a self-hosted runner and never checks out or executes the
selected source commit. It performs read-only lineage checks on a GitHub-hosted
runner and emits a non-authorizing admission request. Target contact occurs only
outside repository-controlled workflow execution, after an independently
administered admission service validates that request and the target custodian
accepts it.

## 1. Fixed evidence lanes

| Evidence kind | Level | External lane | Purpose |
|---|---:|---|---|
| `installed_root_linux_process_matrix` | L2 | `owner-open-r5-l2` | Installed UID/GID, namespaces, cgroups, mounts, limits, restart and emergency inhibit |
| `installed_codex_same_turn` | L2 | `owner-open-r5-l2` | Installed Codex identity, authenticated provider session, same-turn shell/job observations and no hidden retry |
| `clean_android_target_files` | L3 | `owner-open-r5-l3` | Clean manifest, Soong/init/SELinux/package graph, target-files and installed identity agreement |
| `physical_android_adb` | L4 | `owner-open-r5-l4` | Authorized physical target, ordinary ADB, raw error modes, visible mutation and continued turn |
| `destructive_fault_matrix` | L5 | `owner-open-r5-l5` | Process, storage, USB, reboot and power-loss cuts with bound pre-state and post-restart reconciliation |
| `signed_public_release` | L6 | `owner-open-r5-l6` | Signing custody, transparency, AVB, OTA, anti-rollback and explicit human release authorization |

No repository workflow may select or execute these external lanes. Runner groups,
targets, harnesses, admission state and signing boundaries remain independently
administered.

## 2. Repository route request

The route workflow accepts an exact evidence kind, source commit, source tree,
merged promotion PR, authorization ticket, bounded UTC expiry and one-use nonce.
Before emitting a request it verifies:

- execution is from the repository default branch;
- the source commit and tree exist and the commit is signature verified;
- the source commit is in protected-main ancestry;
- the named PR is merged to the default branch and binds the exact merge commit;
- at least one non-author approval is bound to the promoted PR head and there is
  no exact-head change request;
- the promoted commit has a successful exact-source aggregate check;
- the route nonce has not appeared in an earlier request run;
- L5 and L6 tickets use their required authorization prefixes and expire within
  24 hours.

The emitted object must retain all of these negative claims:

```json
{
  "status": "ROUTE_ONLY_PENDING_EXTERNAL_ADMISSION",
  "candidate_checkout_performed": false,
  "candidate_code_executed": false,
  "external_runner_allocated": false,
  "capture_scheduled": false,
  "promotion_authorized": false,
  "public_release": false
}
```

The request is not target evidence, admission, promotion or release authority.
A correctly prefixed ticket is only a routing fact.

## 3. Independent admission

An external admission service must consume immutable request bytes and verify a
detached authorization under a trust root that is not writable by the source
author or repository workflow. The signed admission record binds, at minimum:

```text
repository
source_commit
source_tree
promotion_pr_number
promotion_pr_head
evidence_kind
evidence_level
external_lane
request_artifact_digest
requester
operator/custodian
authorization_ticket
authorization_expiry
one-use nonce
issued_at
issuer and key identity
```

The admission service rejects expired, replayed, revoked, cross-spliced,
unsigned, non-main-lineage, stale-review, failed-check or actor-mismatched
requests. It persists nonce consumption before target contact. Repository
environment approval alone is insufficient.

## 4. Fixed target inputs

For evidence kind `<kind>`, the independently administered target provides:

```text
/opt/owner-open-r5/harnesses/<kind>
/etc/owner-open-r5/attestations/<kind>.json
```

Every path component and leaf is descriptor-validated. The leaf is a regular,
non-symlink, single-link file owned by root and not writable by group or other.
The harness is executable; the attestation is not. Its bytes and metadata match
the detached admission. Candidate checkout content never supplies an executable,
Python module, shell library, configuration file, target identity or output path.

The trusted executor starts in an independently owned empty working directory,
uses a fixed non-inheriting environment, clears language and loader search paths,
and invokes the fixed harness by descriptor-bound identity. The candidate source
is inert content-addressed data only and is never the interpreter working
directory.

## 5. Evidence production

The harness writes a new private bundle with strict JSON manifests, raw bounded
observations, content digests, source/tree identity, target identity, timestamps,
command or operation identity, stdout/stderr or structured results, and explicit
negative claims. Capture does not promote its own result.

The lane-specific minimum observations remain:

- **L2 Root Linux:** installed executable and signer hashes, UID/GID, namespace,
  mount and cgroup identity, finite limits, process tree, restart epoch,
  emergency inhibit and absence of legacy product nodes.
- **L2 Codex:** authenticated provider session, successful and failed same-turn
  tool calls, continued execution, exact correlation, cancellation and zero
  hidden retry or automatic redispatch.
- **L3 Android:** pinned resolved manifest, clean-state decision, Soong graph,
  init, SELinux, package inventory, target-files and image digests, and installed
  identity agreement.
- **L4 ADB:** authorized physical serial and transport, explicit target selection,
  ordinary success, unauthorized/offline/disconnect output, one bounded visible
  mutation and same-turn continuation.
- **L5 faults:** bound pre-cut durable state, independently controlled process,
  storage, corruption, USB, reboot and real power-loss cuts, post-restart
  reconciliation, explicit unknown states and redispatch count zero.
- **L6 release:** production key custody without key export, signer and
  certificate lineage, transparency, complete AVB chain, rollback indices,
  signed target-files/OTA identities, install/update observations and explicit
  independent public-release authorization.

## 6. Review and gap transition

A separate independent verifier downloads immutable bundle bytes, validates the
admission chain, source, target, harness and artifact digests, rejects synthetic
or incomplete evidence, and issues a detached review attestation. A protected
PR may then propose a gap transition. Capture, route, repository administration
or source authorship never changes gap state by itself.

Any movement in source commit, tree, promotion PR, target image, harness,
attestation, authorization, reviewer, trust root or evidence bytes invalidates
the chain and requires a new request and capture.

### Verifier byte-identity requirement

The independent verifier must verify the exact bytes that it digest-checked,
not reopen a mutable key, signature or receipt pathname afterward. Repository
intake implements this with retained receipt bytes and sealed Linux descriptors;
its structural and live-retention layers share one package/gap snapshot.
The required backend and finite parser ceilings are specified in
`docs/QUALIFICATION_AND_EVIDENCE.md` section 2.3. Fixture signatures test these
mechanics only and cannot establish the external trust root or operator identity.

A custodian intentionally replacing a key, receipt, signature, evidence package
or target object must restart intake with the new independently bound subject.
It must not mix an old structural report with a newly read directory, nor treat
an input snapshot as evidence of later filesystem or device state.
