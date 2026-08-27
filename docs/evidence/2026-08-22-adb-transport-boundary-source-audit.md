# ADB OS-owned transport boundary — source audit

Date: 2026-08-22

Status: **SOURCE-ONLY CONTRACT PASS; PRODUCTION TRANSPORT HOLD**

The canonical Rust source now has an explicit authority boundary above the
inert ADB wire state machine in
`crates/trillionnium-agent-direct-tools/src/adb_transport_boundary.rs` (public
as `adb_wire::transport_boundary`). This is an engineering contract and does
not enable ADB, fastboot, a device listener, or a product package.

## What is covered

- `OsOwnedAdbTransport` accepts only an `AdmittedAdbRequest`; it cannot receive
  model JSON, a serial/host/port selector, a raw command string, or key bytes.
- `AdbAdmissionPolicy` re-validates the typed request, binds the fixed
  OS-selected `DeviceBinding`, checks the finite `KeyRotationPolicy`, enforces
  the expiring `AndroidAdbPermissionGrant` tier, and denies confirmation
  requirements when no issuer receipt is present.
- `AdbTransportBroker` performs bounded in-memory request-ID replay and
  conflict rejection. An indeterminate transport result is retained and
  replayed rather than blindly retried. The ledger is explicitly ephemeral;
  it is not a reboot/ power-loss exactly-once authority.
- Key rotation advances both key and device-binding generations and retains
  the previous generation only through the policy's bounded boot overlap.
  Admission requires `AdbKeyCustody::OsOwned`; unavailable/external custody is
  not silently promoted to a product grant. The same check is repeated on a
  live rotation, so an already-enrolled broker cannot be switched to an
  external signer or unavailable custody after construction.
- A completed transport outcome must carry an explicit process exit code. A
  response body without a terminal status is rejected instead of being treated
  as a successful effect.
- The UDS contract is only a bounded length-prefixed JSON codec plus exact
  request/response envelope verification. Tests use `UnixStream::pair()` and
  never bind a filesystem/abstract listener.
- `ProductionAdbTransport::new()` always returns the stable HOLD marker:
  `HOLD: production Android ADB transport/key custody is not wired`.

## Negative boundary

The source contains no production `TcpStream`, adb CLI/process launch,
fastboot invocation, key-file reader, or private-key field in the model-facing
request. `parse_android_adb_model_request` remains the first JSON boundary and
recursively rejects private-key material before typed deserialization. A valid
wire `CNXN/AUTH/OPEN/...` session therefore remains insufficient to obtain an
OS admission.

## Required promotion evidence (still missing)

Promotion requires a product-owned same-device transport and authenticated
listener, non-agent-writable key enrollment with hardware/rollback binding,
measured adapter and peer identity, durable PREPARED/terminal/outer-ACK replay
authority, restart/power-loss/timeout cleanup evidence, and a signed device
build proof. No real device, reboot, fastboot, flash, or private-key path was
used for this source slice.

## Verification

The module unit tests cover typed admission, tier/binding/confirmation
denials, monotonic rotation, duplicate and conflicting IDs, indeterminate
replay, exact UDS frames, forged envelope rejection, private-key rejection,
and the production HOLD constructor. Run:

```sh
cargo test -p trillionnium-agent-direct-tools --lib adb_wire::transport_boundary::tests
```

The broader direct-tools suite remains the authoritative regression gate; any
failure caused by an unavailable external build target is an infrastructure
condition, not evidence that production transport is enabled.
