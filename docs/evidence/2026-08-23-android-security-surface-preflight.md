# Android security-surface preflight (2026-08-23)

The canonical Android tree now contains a source-only, fail-closed contract
and guard:

```text
trillionnium-sdk/contracts/android-security-surface-v1.json
trillionnium-sdk/tools/verify_android_security_surfaces.py
trillionnium-sdk/tests/android_security_surface_contract_test.py
```

The guard reads only fixed source/contract paths. It never invokes ADB,
fastboot, an installer, a reboot, or a signing tool, and it never opens key,
certificate, blob, or `out` artifacts. `Android.bp` and `TEST_MAPPING` register
the host contract test as `TrillionniumAndroidSecuritySurfaceContractTest`.

## Host/source result

The test passed:

```text
PASS: Android security surfaces audit HOLD and source drift fails closed
```

The actual canonical-tree guard returned a structurally valid `HOLD` with
these reasons:

```text
accessibility_live_service_binding_unverified
keymint_default_is_software_not_hardware_backed
keymint_device_manifest_owner_missing
keymint_live_hardware_attestation_unavailable
proprietary_keymaster_firmware_is_not_attestation_evidence
rollback_live_counter_attestation_unavailable
rollback_os_owned_monotonic_producer_unavailable
```

The positive source checks are useful (KeyMint AIDL/default service shape,
AVB index presence, rollback-proof source shape, Accessibility product owner,
and explicit user-authorization gate), but they are not hardware or runtime
authority. The guard's `--require-ready` mode remains nonzero until an
independent platform evidence producer supplies the missing hardware
attestation, OS-owned monotonic rollback counter, and live Accessibility
binding/replay closure.

This preflight therefore clears source drift uncertainty while preserving the
release gate. It does not authorize signing, OTA generation, device writes, or
effect execution.
