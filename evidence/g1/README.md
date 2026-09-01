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

The verifier cannot create an installed target, physical-device observation,
destructive-fault authorization, independent review, signature, or release
authority.  It only checks receipts that already bind those facts.
