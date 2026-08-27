# Reversible device TEE keystore probe

Date: 2026-08-23 (Asia/Shanghai)

This is a bounded, reversible diagnostic against the already attached
`ZY32JLVHGN` device. It was not a release, authorization, or signing action.
The probe did not export or open private key material and did not issue an
install, input, reboot, fastboot, or flash operation. The ADB server was
stopped after collection.

## Procedure

Using the device's existing `keystore_cli_v2` utility, a unique temporary
alias (`trillionnium_probe_20260823_1237`) was checked, generated with
`--seclevel=tee`, queried with `get-chars`, deleted, and checked again. The
alias was absent before generation and absent after deletion.

The command reported `GenerateKey: success` and `GetCharacteristics: success`.
The returned characteristics included a `Hardware` set containing purpose,
algorithm, key size, digest, padding, RSA public exponent, origin, OS version,
OS patchlevel, vendor patchlevel, and boot patchlevel tags. A separate
`Software` set contained creation datetime and user ID. The utility reported
`Successfully deleted key` and the final existence check reported `no`.

## What this establishes

The attached build has a usable TEE-backed Keymaster/keystore generation path
for a temporary key. This is stronger than merely observing that a keystore or
legacy HAL service is registered, and it is now recorded as real device
evidence.

## What it does not establish

The probe did not produce a verifiable attestation certificate chain or prove
the attestation root is production-trusted. It did not prove a locked/green
Verified Boot state, a hardware rollback high-water value, production key
custody, or a KeyMint 4 (400/400) interface. The device still reports
`userdebug/test-keys`, `UNOFFICIAL`, and `unlocked/orange`; the source verifier
also deliberately rejects legacy HIDL Keymaster 4.1 as a substitute for
KeyMint 4 attestation. Therefore this evidence narrows the KeyMint blocker but
does not authorize signing, release, or device writes.
