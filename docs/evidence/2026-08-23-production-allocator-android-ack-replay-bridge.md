# Production allocator ↔ Android ACK/replay bridge seam (2026-08-23)

## Implemented source slice

`apps/trillionniumd/src/android_ack_replay_bridge.rs` adds a source-only,
move-only custody seam:

- `AndroidAckReplayProductCustody::bind_product` accepts only the existing
  `ProductBoundDirectToolCallListener` and
  `VerifiedAllocatorCommitForAndroidAck` proof types.  It has no path,
  generation, digest, boolean, or serialized-proof constructor.
- `validate_for_handoff` rechecks the allocator proof's persisted
  `AdapterPrepared` record and outer evidence before a future adapter could
  consume a receipt.
- `require_product_handoff` returns the stable
  `direct_tool_call_android_ack_replay_product_custody_unavailable` HOLD while
  the shared transport contract or the independent Android handoff bit is
  false.

`main.rs` only declares the module.  It does not bind a listener, instantiate
the custody type, contact Android, or grant effect authority.

## Regression checks

The module tests assert the stable HOLD and verify that daemon `main` contains
no bridge/listener instantiation.  Existing allocator coverage remains the
authoritative proof test:
`android_ack_replay_proof_binds_exact_commit_and_outer_evidence`.

Host-only command (no device, key, ADB, OTA, or release action):

```text
cargo test -p trillionniumd --bin trillionniumd android_ack_replay_bridge
```

## Remaining HOLD

The Android adapter connector, operation-epoch/first-use authority,
rollback-resistant replay high-water, KeyMint/Accessibility evidence, and
device/product custody are absent.  All product authority flags remain false;
the bridge intentionally cannot produce a successful handoff.
