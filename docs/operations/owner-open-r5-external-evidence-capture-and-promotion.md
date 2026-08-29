# Owner-Open R5 external evidence capture and promotion

Status: **ACTIVE — plan revision `2026-08-29-r6`**

This runbook is the only supported route from repository source closure to an
L1 governance or L2–L6 target closure. It does not allow a fixture, handwritten
digest, bot identity, status edit or workflow name to manufacture a pass.

## 1. Two immutable identities

Every external bundle binds:

```text
source_commit / source_tree
    exact source that passed the permanent L1 gate

promotion_head
    later branch head that adds reviewed evidence and machine-state changes
```

The bundle always names the source identity. A later evidence-only promotion
commit does not silently become a new qualified source identity. Any change to
code, contracts, tools, workflows or active plan requires a new L1 source run.

## 2. Evidence kinds

| Kind | Level | Canonical gap coverage | Runner class |
| --- | ---: | --- | --- |
| `repository_governance_controls` | L1 | governance | GitHub repository control plane |
| `installed_root_linux_process_matrix` | L2 | process, stream, broker, Root Linux placement | `owner-open-r5-l2` |
| `installed_codex_same_turn` | L2 | installed Codex | `owner-open-r5-l2` |
| `clean_android_target_files` | L3 | product entrypoint, Android graph | `owner-open-r5-l3` |
| `physical_android_adb` | L4 | physical ordinary ADB | `owner-open-r5-l4` |
| `destructive_fault_matrix` | L5 | journal convergence, destructive fault matrix | `owner-open-r5-l5` |
| `signed_public_release` | L6 | public release | `owner-open-r5-l6` |

A higher numbered level is not automatically interchangeable with another
kind. The manifest policy declares exactly which gaps each kind may close and
which raw roles and observations are mandatory.

## 3. Target-owned inputs

L2–L6 runners must provision two reviewed, non-writable, single-link files:

```text
/etc/owner-open-r5/attestations/<kind>.json
/opt/owner-open-r5/harnesses/<kind>
```

The attestation must be derived from
`owner-open-r5-target-attestation-template.json`, but the template itself is
intentionally invalid. A real attestation replaces every `UNSET`/zero value,
sets `template=false`, `synthetic=false`, binds the exact source commit/tree,
and has a finite validity window.

The harness is invoked with fixed argv:

```text
<kind> \
  --raw-dir <new-private-directory>/raw \
  --artifact-index <bundle>/artifact-index.json \
  --observations <bundle>/observations.json \
  --source-commit <40-hex> \
  --source-tree <40-hex>
```

It must emit a closed artifact index and the exact required observation
booleans. It must never write credentials, bearer tokens, private keys or
secret-shaped filenames into evidence.

## 4. Capture-only bundle

The target workflow runs
`capture-owner-open-r5-target-evidence.py`. The driver:

1. measures the fixed harness and attestation through stable file descriptors;
2. starts a new process session with a finite timeout;
3. records exact argv, stdout/stderr bytes and harness identity;
4. rejects undeclared, missing, symlinked, multiply linked or mutated files;
5. scans bounded artifacts for credential and private-key shapes;
6. finalizes `manifest.json` with `promotable=false` and canonical false review;
7. revalidates every byte before upload.

An uploaded capture artifact is not gap evidence. It is a review candidate.

## 5. Independent review

An independent human reviewer who is neither capture producer nor target
operator validates the unpacked capture, raw logs, negative claims and target
boundary. The reviewer creates a document from
`owner-open-r5-evidence-review-template.json` with:

```text
approved=true
exact source commit/tree
exact evidence kind and level
exact ordered gap_ids
non-bot reviewer login
positive review_id
reviewed_at inside target-attestation validity
explicit negative claims
```

The reviewer or an independently controlled promotion lane reruns the finalizer
with `--replace-existing-capture --promotable --review-attestation ...`.
Existing capture artifacts must remain byte-identical. The only new ordinary
artifact is the review attestation (and, for L6, release authorization).

## 6. L6 additional authorization

A signed-release bundle also requires a distinct human authorizer and a file
derived from `owner-open-r5-release-authorization-template.json`. It must state:

```text
authorized=true
public_release=true
authorization_id=<non-empty custody record>
authorized_at=<UTC time>
```

Producer, target operator, evidence reviewer and release authorizer must be
separate identities. Technical signing output without this authorization is
not promotable L6 evidence.

## 7. Repository import

Place the reviewed bundle below:

```text
evidence/owner-open-r5/<kind>/<capture-id>/manifest.json
```

Run, without `--apply`, to inspect the exact state transition:

```text
python3 tools/promote-owner-open-r5-evidence.py \
  --bundle-manifest evidence/owner-open-r5/<kind>/<capture-id>/manifest.json \
  --json
```

Then run with `--apply`, review the diff, and execute both canonical verifiers:

```text
python3 tools/promote-owner-open-r5-evidence.py \
  --bundle-manifest evidence/owner-open-r5/<kind>/<capture-id>/manifest.json \
  --apply --json
python3 tools/verify-owner-open-r5.py --json
python3 tools/verify-owner-open-r5-gap-evidence.py --json
```

Promotion fails when the bundle is capture-only, the source commit/tree differs,
the kind is not allowed to close a gap, the evidence level is below the exit,
raw bytes drifted, reviewer boundaries fail, or L6 is attempted before every
prior gap is closed.

## 8. Exact-head integration

The evidence PR must pass the permanent exact-head L1/document/evidence checks.
For an external closure, the final PR head also requires an independent
non-author, non-bot approval bound to that exact head. A new push invalidates the
approval. Main protection, required checks, review count, direct-push block and
force-push block are separately measured by the governance readiness workflow.

The implementer never merges their own evidence PR and never changes
production activation or public-release truth by inference.

## 9. Retention

Every bundle records artifact expiry, immutable retention location,
reproduction instructions and whether the target environment remains
available. Expired workflow storage cannot be the sole permanent basis for a
closed gap. The checked-in bundle must retain all bounded textual identity,
manifest, trace and review files required for revalidation; large binaries are
represented by independently verified identity reports, not copied secrets or
mutable links.
