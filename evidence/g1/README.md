# G1 evidence receipts

`candidates/` contains immutable, strict-JSON receipts for observations made
outside the source tree.  A receipt may be structurally complete while no
longer promotable because its retained artifacts expired or because it is bound
to another exact source commit.

Validate without mutating machine truth:

```sh
python3 tools/verify-g1-evidence.py \
  --current-source-commit "$(git rev-parse HEAD)" \
  --report /tmp/g1-evidence-report.json \
  --promotion-plan /tmp/g1-promotion-plan.json
```

The network-facing reconciliation is a separate, read-only step.  Run it from
an independently reviewed checkout and provide the protected integration base
branch; it emits an unsigned receipt for the external signing step:

```sh
GITHUB_TOKEN="$(cat /secure/intake/github-token)" \
python3 tools/verify-g1-evidence-live.py \
  --repo TrillionniumFoundation/trillionnium-os \
  --pr 34 \
  --source-commit "$(git rev-parse HEAD)" \
  --evidence-dir evidence/g1/candidates \
  --base-branch codex/global-modular-docs-g1-20260831 \
  --output /secure/intake/g1-attestation.json \
  --report /secure/intake/g1-live-report.json
```

The verifier fails closed if any unexpired `COMPLETE` package for the current
source could promote a gap without an out-of-band trusted receipt.  Supply the
receipt path and its raw-byte SHA-256 from an independently administered
attestation channel:

```sh
python3 tools/verify-g1-evidence.py \
  --current-source-commit "$(git rev-parse HEAD)" \
  --attestation /secure/intake/g1-attestation.json \
  --attestation-sha256 "$(cat /secure/intake/g1-attestation.sha256)" \
  --attestation-signature /secure/intake/g1-attestation.sig \
  --attestation-public-key /secure/trust/g1-attestation-root.pem \
  --attestation-public-key-sha256 "$(cat /secure/trust/g1-attestation-root.sha256)" \
  --report /tmp/g1-evidence-report.json \
  --promotion-plan /tmp/g1-promotion-plan.json
```

`schemas/g1-evidence-attestation.v1.schema.json` defines the strict receipt.
The receipt must bind the exact set of current `COMPLETE` package IDs and
source commit, declare the configured `g1-attestation-root-20260902` trust-root
identifier and `rsa-sha256` algorithm, and be accompanied by a detached
signature.  The receipt, signature and public-key paths must be outside both
the repository and evidence directory; the public-key bytes are pinned by an
out-of-band digest.  The core verifier does not contact GitHub or any other
network.  Use `tools/verify-g1-evidence-live.py` to obtain and reconcile live
GitHub review/check/artifact objects before an authorized operator signs the
receipt.  Historical/stale and `HOLD` packages remain auditable without an
attestation but never produce a promotion.

The verifier cannot create an installed target, physical-device observation,
destructive-fault authorization, independent review, signature, or release
authority.  It only checks receipts that already bind those facts.

Before signing a receipt, run `tools/verify-g1-evidence-live.py` from a
reviewed, pinned verifier checkout (not an unreviewed pull-request worktree):
it validates the package contract, exact PR head/base/repository/branch, live
independent approval, exact `Cargo.lock`, every workflow run, and every package
artifact archive.  Its CLI requires `--base-branch` and writes new outputs only
to pre-existing external directories.  The live tool is intentionally
read-only and currently emits attestations for L1 source-qualification
packages only.

The live CLI deliberately accepts only the official `https://api.github.com`
endpoint when a token is present; custom GitHub Enterprise endpoints require a
separately reviewed implementation rather than forwarding credentials to an
arbitrary `--api-base` host.

The public-key file and its SHA-256 pin are an operations trust boundary.  They
must come from an independently protected trust store or secret, and the
signing operator must review the live report and pin the verifier revision;
the `trust_root` string and a key supplied by the evidence checkout are not a
trust root.  Detached signatures prevent repository-only forgery but do not
replace this independent key-custody step.

An attestation is a signed point-in-time snapshot, not a live GitHub
revocation lock.  A later review dismissal or `CHANGES_REQUESTED` event, or
artifact deletion/expiry after signing, is not visible to the offline core
until the attestation expires.  Promotion therefore requires a fresh run of
the live verifier (or an independently maintained revocation/status service)
within the receipt validity window; a signature alone must never be treated as
continuous approval.
