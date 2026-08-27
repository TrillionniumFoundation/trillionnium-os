# Production material audit (read-only)

Date: 2026-08-23 (Asia/Shanghai)

This audit inspected only bounded filenames, file metadata, and public build
configuration in the canonical Android estate. It did not open private-key
contents, invoke a signer, create a key, write an output, or modify the device.

## Findings

- The canonical tree has no configured production release-key directory or
  release-key environment input.
- The only Trillionnium-named certificate found at the expected product
  security path is a public `trillionnium.x509.pem`; its subject/issuer is the
  LineageOS development certificate, not a production release authority.
- The Android source contains the normal AOSP development/test signing
  material (`testkey.pk8` and matching public certificates). No corresponding
  production AVB private-key set or OTA signing set is present in the bounded
  canonical paths.
- The active target-files archive is 3,311,305,066 bytes and its metadata is
  already held as `userdebug`/`test-keys`, with an AOSP test AVB key marker and
  empty OTA keys. A full archive hash is not required to establish this hold.

## Decision

No legitimate user/release-keys rebuild or signed OTA can be performed from
the material currently present. Supplying production public-key pins,
OS-controlled signing access, and the corresponding signed metadata/rollback
attestation is an external prerequisite. Renaming or reusing development keys
would not clear the release gate and is forbidden by the verifier.
