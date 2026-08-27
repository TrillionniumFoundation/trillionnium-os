# Production allocator ↔ Android ACK/replay source audit (2026-08-23)

## Result

The daemon allocator now has a source-only, non-serializable correlation seam
for an exact `AdapterPrepared` commit receipt and one Android outer-journal
evidence item.  `DirectToolCallAllocator::verify_commit_for_android_ack`:

- revalidates the live locked allocator file and reconstructs the receipt from
  the persisted record;
- rejects a caller-supplied receipt that differs in binding, invocation,
  adapter, token, generation, record digest, envelope digest, or PREPARED ACK;
- retains the canonical request, provider-attempt identity, adapter ordinal,
  journal sequence, and backend request digest needed for ACK/replay
  correlation; and
- rechecks the persisted record before accepting outer evidence, including
  structural evidence validation, attempt, ordinal, journal sequence,
  canonical digest, and backend request identity.

The proof is borrowed and cannot be serialized or constructed from a path,
generation, digest, or boolean.  It is deliberately not product admission: it
does not create a delivery, contact Android, grant effect authority, or bypass
the allocator transport/high-water contract.  The product admission flags
remain `false`, so production allocator opening still returns the existing
stable HOLD code.

## Regression coverage

`android_ack_replay_proof_binds_exact_commit_and_outer_evidence` exercises:

1. durable delivery → envelope → PREPARED ACK → commit receipt;
2. exact evidence correlation;
3. fail-closed ordinal, journal-sequence, and backend-request tampering; and
4. allocator restart with byte-identical receipt and successful replay
   correlation.

`DirectOperationOuterEvidence::validate_for_adapter` is a read-only public
wrapper around the existing snapshot structural validator so this seam does
not fabricate a complete journal snapshot.

## Remaining HOLD

The daemon listener/provider delivery path, OS-owned Android transport,
first-use authority, rollback-resistant high-water, KeyMint/Accessibility
adapters, and device evidence are still absent.  No device operation or
product flag was enabled by this change.
