# CI gate model

Status: **NORMATIVE FOR PULL-REQUEST GATING**

This policy supersedes repository prose that makes evidence receipts, review indexes, synthetic-merge receipts, device qualification, or release evidence transitive prerequisites for an ordinary pull request.

## 1. Source correctness — blocking for ordinary pull requests

The default protected-branch gate may block on checks that directly evaluate the proposed source change:

- build/compile and dependency resolution;
- unit, integration, property and focused regression tests;
- formatting and linting;
- static/security analysis whose finding is attributable to the proposed source;
- protocol/schema/API compatibility checks;
- deterministic generated-file or lockfile consistency;
- exact checkout identity and clean-worktree sanity.

A source gate must report the failing source property directly. It must not require another workflow to manufacture a receipt proving that workflow ran.

## 2. Governance and evidence — scoped, not a transitive PR prerequisite

Governance/evidence jobs may validate provenance, retained artifacts, independent review, device observations, external operator evidence, or gap records. They run when a change modifies those governance surfaces or when a promotion workflow explicitly requests them.

They are not recursive prerequisites for unrelated application/source PRs. In particular, ordinary PR admission must not depend on:

- review-index inventories of every changed path;
- exact-head/synthetic-merge receipt pairs;
- cross-workflow aggregate polling;
- downloading CI artifacts solely to prove another CI workflow succeeded;
- evidence manifests whose only authority is repository-controlled CI;
- fail-closed checks on GitHub metadata that do not represent a source defect.

These mechanisms may remain as advisory diagnostics during migration, but they carry no independent authorization merely because they are elaborate.

## 3. Promotion and release — blocking only on promotion/release paths

Installed-target, Android/device, destructive recovery, signing, transparency, independent authorization, production evidence and release qualification remain hard gates when promoting or releasing an artifact. Moving them out of the ordinary PR gate does **not** weaken those release requirements.

Release qualification must bind the exact artifact/source being promoted, but it should be invoked by the promotion/release workflow rather than recursively gate every source PR.

## 4. Compatibility migration

Existing required-check context names may temporarily be retained as compatibility shims so branch protection does not deadlock while configuration is migrated. A compatibility shim must do only bounded source-subject sanity and must state that it is not an evidence or release authority.

Once branch-protection administration is available, obsolete receipt/index/aggregate context names should be removed from required checks and the shims deleted.

## 5. Design rule

**CI tests the product; CI does not qualify CI. Evidence qualifies a promotion claim; it does not become a second source-control consensus system.**
