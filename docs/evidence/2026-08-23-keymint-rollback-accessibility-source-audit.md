# KeyMint/rollback and Accessibility phase-2 source audit

Date: 2026-08-23

Scope: canonical source checkout
`/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-release-sources/p0-agent-native-integration-20260731`.
This audit is host/source-only. It did not open a private-key path, call a
physical device, write an input, install an APK, flash an image, or enable a
lease.

## Result

The phase-2 decision remains **HOLD**.

The pre-existing
`crates/trillionnium-os-types/src/capability_lease_activation_gate.rs` and
`contracts/capability-lease-activation-gate-v1.json` expose three independent
fail-closed components:

1. root-authenticated issuer/consumer binding and lease epoch high-water;
2. KeyMint/Verified-Boot and persistent AVB rollback evidence; and
3. Accessibility service ownership, protocol/replay and receipt/ACK closure.

All product constructor, enablement-token and effect-authority flags are
false. A complete test fixture still returns `HOLD` and cannot mint a permit.
The existing `risk_guard` also denies sensitive Accessibility actions with
`TrustedLeaseIssuerUnavailable`, while `TrustedAdapterContext` rejects product
effect custody/journal activation until kernel custody and external replay
authority exist.

## Additional source guard

`crates/trillionnium-os-types/src/capability_lease_android_evidence.rs` and
`contracts/capability-lease-android-evidence-gate-v1.json` add a detached
evidence-shape gate. It binds, without authorizing:

- `user` + exactly `release-keys` target metadata and non-empty OTA keys;
- non-zero issuer/consumer and lease high-water proof digests;
- KeyMint attestation-chain digest, `STRONGBOX`/`TRUSTED_ENVIRONMENT`,
  `VERIFIED` boot state, non-zero rollback high-water and persistence proof;
- Accessibility protocol `org.trillionnium.agent-accessibility.v2`, the
  generated tool/replay-sync SELinux domains, service/replay/receipt-ACK
  digests, and a runtime consumer bit.

The detached type contains no private-key field and has no conversion to an
effect capability. Even a complete synthetic record returns
`capability_lease_android_product_authority_unavailable`.

## Target-files observations

Read-only inspection of the current v28 target-files tree at
`out/target/trillionnium-userdebug-v28-standard-relative-20260814.9YHOOi`
observed:

- `META/misc_info.txt`: `build_type=userdebug`, AVB rollback index `28`,
  `vbmeta_system_rollback_index_location=2`, and AOSP test-key AVB key paths;
- `SYSTEM/build.prop`: `ro.build.type=userdebug`,
  `ro.build.tags=test-keys`, fingerprint ending in `userdebug/test-keys`;
- `META/otakeys.txt`: one newline only (no OTA key material);
- `SYSTEM_EXT/etc/trillionnium/capability-lease-trust.v1.json`: `enabled=false`,
  `status=foundation_config_only_product_hold`, empty pins, null rollback
  state, and `verifier.present=false`;
- `META/apkcerts.txt`: `TrillionniumCapabilityLeaseIssuer.apk` and the
  `TrillionniumCapabilityLeaseKeyMintEvidenceProbe.apk` are test-key signed;
- no production Accessibility service ownership/replay/ACK evidence is
  present in the target-files metadata.

These are static host observations only. Presence of generic KeyMint/Keystore
libraries or a test probe is not KeyMint attestation, hardware rollback proof,
or a production Accessibility adapter.

## Tests

Using an isolated temporary Cargo target directory (the shared workspace
target was concurrently locked), the following passed:

```text
cargo test -p trillionnium-os-types capability_lease_android_evidence --lib
5 passed; 0 failed

cargo test -p trillionnium-os-types --lib
197 passed; 0 failed
```

The tests cover contract SHA-256, exact target/key/Verified-Boot rejection,
exact Accessibility protocol/domain binding, unknown-field/private-key
rejection, and the invariant that complete evidence remains non-authorizing.

## Hard blockers before activation

The next phase still needs an OS-owned issuer/consumer transport, real locked
device KeyMint attestation and rollback persistence/high-water evidence, a
measured production Accessibility service with operation-epoch/replay and
receipt/ACK closure, then the current-source `user`/`release-keys` rebuild,
OTA/rollback evidence and release gate. No source-only fixture can substitute
for those device and signing proofs.
