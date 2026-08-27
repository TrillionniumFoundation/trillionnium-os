# Capability-Lease Root Route and Coordinator P0 Evidence

Date: 2026-07-23

## Frozen contract

- Canonical contract: `crates/trillionnium-os-types/contracts/capability-lease-root-route-coordinator-v1.json`
- Schema: `org.trillionnium.capabilitylease.root-route-coordinator.contract.v1`
- SHA-256: `2d443deb647e4c3d41f6dc768306395f954f34fcf7b10c5f2d5cbee1c25e27c3`
- Root kernel custody dependency: `4d1fef7a3bc0ab7e66ef51d6cfb6ad478fffcf3b5484530fc379ced413ce0009`
- Root socket/result custody dependency: `78556032618fc9e246a56e7978812a5859b9c08d9c71672c6e94f9232d85c0ed`
- Root listener/correlation dependency: `2cde8a3875dcefcb02d066138c37cf4af8c8f5666f693f90669436873eb81656`

## Single internal broker route

The privilege broker now contains exactly one crate-internal, source-disabled
root publisher route. It accepts one already validated root task publication,
derives the fixed launch specification, enters the concrete P0.8 kernel
custody path, delivers the P0.7 proof through the fixed P0.9 socket and returns
only the exact P0.9 completion commitments. It has no loop, retry, alternate
carrier or partial result.

The route is absent from `main`, the public privilege-broker request enum and
the live dispatch table. Therefore this source closure does not create a
callable product ABI or route.

## Dual-listener terminal coordinator

The SDK now contains a source-only coordinator with one owned proof listener,
one owned publication listener and one asynchronous route-completion custody
handle. The Android-only binding helper creates the publication listener
first, then the proof listener, and only returns a coordinator after both fixed
abstract sockets are bound. No route can start before that constructor
returns.

One coordinator starts the route once, accepts and closes one authenticated
proof connection, converts the proof into the P0.10 single-use correlation,
then accepts one publication. The same concrete correlation object must be
used by the publication peer authenticator and backend root-journal
authenticator. The listener now returns immutable ACK commitments; the
coordinator requires exact equality across proof authentication, publication,
registration, token record, root record, root proof, ACK and broker completion.
Success or any error clears the correlation, closes both listeners and closes
the route custody handle before becoming terminal. A second run is denied.

## Product HOLD

The public broker protocol is unchanged. Broker main wiring, listener
coordinator wiring, runtime/service construction, publisher packaging, live
socket availability, product token mutation, ACK authority, lease trust and
effect authority all remain false. No Android syscall or socket path was
executed.

## Validation

- `trillionnium-os-types`: 62 passed.
- `trillionnium-agent-privilege-broker`: 120 passed, 1 ignored; integration
  tests: 3 passed.
- `trillionniumd`: 276 passed, 2 ignored; capability conformance: 8 passed,
  1 ignored.
- `trillionnium-agent-api-uds`: 9 passed.
- `trillionnium-agent-direct-tools`: 121 passed; MCP integration: 2 passed.
- SDK current-source host JUnit: 91 passed; the Android-only proof,
  publication and dual-listener constructors compile against the current
  hidden framework header.
- SDK capability-lease source gate passed.
- Vendor same-ABI: 11 passed; capability trust: 8 passed; Direct and OpenClaw
  product gates passed.
- AiShell security contract passed; existing Soong host artifacts ran 88
  current test methods successfully.
- SELinux broker, issuer and replay-sync policy contracts: 7, 5 and 7 passed.
- Canonical, SDK and vendor contract mirrors are byte-identical at SHA-256
  `2d443deb647e4c3d41f6dc768306395f954f34fcf7b10c5f2d5cbee1c25e27c3`.
- `cargo fmt --all -- --check`, source gates and affected repository
  `git diff --check` runs passed.
