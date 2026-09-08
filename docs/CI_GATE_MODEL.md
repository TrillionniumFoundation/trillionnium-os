# CI gate model

Status: **NORMATIVE FOR PULL-REQUEST, PROMOTION AND RELEASE GATING**

This policy separates direct source correctness from promotion evidence and
release authorization. It removes recursive receipt machinery from ordinary
pull requests without weakening the exact canonical synthetic-merge source
test.

## 1. Source correctness — blocking for ordinary pull requests

The protected-branch source gate blocks on checks that directly evaluate the
proposed source change:

- build, compile and dependency resolution;
- unit, integration, property and focused regression tests;
- formatting and linting;
- static and security analysis attributable to the proposed source;
- protocol, schema and API compatibility checks;
- deterministic generated-file and lockfile consistency;
- exact checkout identity and fail-closed clean-worktree inspection;
- exact base-to-head ancestry;
- a real conflict-checked merge of the live base and head, followed by the
  applicable source, documentation, protocol and compatibility checks on one
  canonical two-parent synthetic commit.

The canonical synthetic commit is a source/integration correctness property. Its
identity is produced from the exact merge tree and ordered base/head parents
with fixed author and committer names, email addresses, timestamps, timezone,
message and Git configuration. Recomputing the same tuple must produce the same
commit SHA. GitHub's hidden pull-request merge ref is a mutable service-side
observation and is not the canonical decision object.

The server-required `L1 exact-source-head aggregate candidate` context is owned
by a dependent job in `G1 synthetic-merge qualification`. It cannot complete
until the exact live base/head synthetic job succeeds. The separately named
exact-head direct-source aggregate consumes that same workflow attempt, both
job identities and its commit-bound source receipt. A rerun of the synthetic job
therefore requeues its dependent required context; a failed attempt makes that
context fail without requiring a source push. This is source/integration
evidence, not target, device or release evidence. A failed merge, changed
ordered parent, changed merge tree, changed canonical commit, rerun-attempt
movement or artifact movement invalidates the aggregate.

A source gate must report the failing source property directly. It must not
require unrelated workflows to manufacture receipts merely to prove that those
workflows ran.

## 2. Governance and evidence — scoped, not transitive ordinary-PR prerequisites

Governance and evidence jobs validate provenance, retained artifacts,
independent review, installed targets, devices, destructive faults, signatures
or gap transitions. They run when a change modifies those governance surfaces or
when a promotion workflow explicitly requests them.

Ordinary application/source PR admission does not depend on:

- a closed-world review inventory for every changed path;
- review-index receipt pairs;
- Android evaluated-matrix receipts when Android source is unaffected;
- evidence-intake artifacts whose purpose is promotion;
- downloading unrelated CI artifacts solely to prove another workflow ran;
- repository-controlled evidence manifests presented as independent authority;
- GitHub metadata checks that do not represent a source or integration defect.

CODEOWNERS and review routing remain useful, while actual integration approval
must still be a non-author decision on the exact current head under branch
protection. Documentation or an automatically generated ownership map is not an
approval.

## 3. Promotion gate — blocking for L2 through L5 transitions

A promotion gate binds one exact source, build, target and evidence subject. It
requires the evidence level declared by the affected gap, including installed
identity, target or device observations, fault execution, role separation,
retention, expiry and independent review.

Promotion workflows must:

- accept only a lowercase 40-hex commit that exists in this repository;
- prove that the selected commit is reachable from protected `main`;
- verify the exact evidence and promotion-plan schemas;
- reject a failed Git/worktree inspection as well as a dirty worktree;
- retain `automatic_redispatch=false` and `public_release=false` unless the
  independently authorized level permits a later transition;
- never convert source-test success into installed-target, device or destructive
  fault evidence.

## 4. Release gate — blocking for L6

Installed-target, Android/device, destructive recovery, signing, transparency,
AVB, OTA, rollback, key custody and independent human authorization remain hard
release gates. Moving them out of the ordinary PR gate does not weaken them.

A release must bind the exact promoted source and artifact chain. It is invoked
by the release workflow, not recursively by every source pull request.

## 5. Context migration

A required-check context name must describe the guarantee it actually provides.
Do not retain an old “synthetic merge” or “receipt binding” name for an
identity-only shim. When branch-protection administration is unavailable, keep
the existing required exact-head aggregate and make it consume the real
canonical synthetic-merge result. Non-required legacy receipt workflows must be
renamed, made manual-only or retired.

The existing required context is continuously coupled to the synthetic workflow
by its dependent admission job. The exact-head workflow must not emit the same
name; duplicate job names across workflows would make protection ambiguous. A
post-success rerun of the synthetic job and its dependants must make the required
context pending and then success or failure for that new attempt.

Any future context-name or branch-protection migration must remain atomic: the
new source guarantee becomes enforceable before the old context is removed.

## 6. Design rule

**CI tests the product and its prospective integration. Evidence qualifies a
promotion claim. Release governance authorizes distribution. None of these
layers becomes a second semantic principal or a recursive source-control
consensus system.**
