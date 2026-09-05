# G1 governance and external-evidence boundaries

This directory contains repository-controlled policy that is intentionally
separate from installed-target evidence.

- [`component-lifecycle.v1.json`](component-lifecycle.v1.json) classifies every
  root Cargo workspace member that is not part of the selected G1 default
  source closure.  A non-default member is never implicitly active merely
  because it still compiles.
- [`TARGET_EVIDENCE_OPERATOR.md`](TARGET_EVIDENCE_OPERATOR.md) defines the
  fixed independently administered L2–L6 runner, harness, target-attestation,
  authorization and output contract used by
  `.github/workflows/owner-open-r5-target-evidence-capture.yml`.

The machine module authority remains `docs/machine/module-catalog.v1.json` and
the evidence authority remains the G1 evidence schemas and intake verifier.
Nothing in this directory can approve a pull request, sign an attestation,
close a target gap, merge protected `main`, authorize a destructive test or
enable public release.

Repository-controlled source qualification ends at L1.  L2 installed runtime,
L3 Android image, L4 physical-device effect, L5 destructive recovery and L6
release claims require observations produced by their real custodians and then
independently reviewed against the exact unchanged source subject.
