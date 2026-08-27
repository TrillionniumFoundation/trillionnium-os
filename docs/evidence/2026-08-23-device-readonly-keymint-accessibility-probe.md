# Read-only device probe: KeyMint, rollback, and Accessibility

Date: 2026-08-23 (Asia/Shanghai)

This record is a diagnostic observation only. It does not authorize an effect,
change device state, or substitute for production evidence. The probe used the
already attached `ZY32JLVHGN` device and was followed by stopping the ADB
server. No install, input, shell write, reboot, fastboot, or flash operation
was issued, and no private key material was opened.

## Observed boot and build identity

The read-only `getprop` result reported:

```text
ro.boot.vbmeta.device_state=unlocked
ro.boot.verifiedbootstate=orange
ro.build.type=userdebug
ro.build.tags=test-keys
ro.build.fingerprint=trillionnium/trillionnium_fogos/fogos:16/BP4A.251205.006/eng.qian-q:userdebug/test-keys
ro.trillionnium.releasetype=UNOFFICIAL
ro.trillionnium.version=23.2-20260813-UNOFFICIAL-fogos
```

This is direct device evidence for the existing release HOLD: the running
system is not a `user/release-keys` production image and verified boot is not
in the locked/green state.

## KeyMint/Keystore and rollback observations

The Android service registry exposed Keystore2, remote provisioning,
attestation verification, and rollback manager services, including:

```text
android.system.keystore2.IKeystoreService/default
android.security.rkp.IRemoteProvisioning
attestation_verification
rollback
```

`init.svc.keystore2=running` and AVB metadata was present, but the read-only
`dumpsys keystore2` and `dumpsys rollback` probes did not return a hardware
KeyMint attestation, a verified-boot attestation chain, or a monotonic
rollback high-water value. A separate reversible keystore probe did succeed
in generating and deleting a temporary TEE key with hardware authorization
characteristics; that result is recorded in
`2026-08-23-device-tee-keystore-probe.md`. Service presence or a successful
temporary TEE key operation is therefore useful diagnostic evidence, but is
still not accepted as KeyMint/rollback production evidence without a verifiable
attestation chain and rollback high-water proof.

A second bounded read-only probe found that the direct AIDL
`android.hardware.security.keymint.IKeyMintDevice/default` lookup returned
`not found` from the shell context. The same probe found a running QTI legacy
`android.hardware.keymaster@4.1-service-qti` process and a vendor HIDL
`@4.1::IKeymasterDevice/default` declaration. Shell SELinux denied direct
HIDL introspection, so this is not proof that the legacy service is usable or
hardware-backed. The product verifier explicitly does not treat a legacy HIDL
Keymaster 4.1 attestation as KeyMint 4 evidence; an OS-owned, independently
verified bridge/attestation is still required.

## Accessibility observations

`dumpsys accessibility` reported `installedServiceCount=2`, but:

```text
Bound services: {}
Enabled services: {}
Binding services: {}
Crashed services: {}
```

The package itself is present as a system-ext APK and declares
`android.permission.BIND_ACCESSIBILITY_SERVICE`, but User 0 reports
`enabled=0` and no bound/enabled service. Package presence and declaration do
not constitute explicit user authorization or a live replay/ACK adapter.

No production Accessibility adapter ownership, generated SELinux-domain
closure, replay binding, or receipt/ACK closure was observed. The existing
Android evidence gate must consequently remain `HOLD`.

## Decision

The probe clears the uncertainty about the currently attached target but does
not clear the production blockers. The next admissible inputs are a real
OS-held-key ADB transport proof, KeyMint/Verified-Boot and hardware rollback
attestation, and a production Accessibility adapter/replay/ACK record. Until
those are supplied by the platform, signing and device writes remain denied.
