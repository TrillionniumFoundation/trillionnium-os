# Capability-Lease Root Listener and Correlation P0 Evidence

Date: 2026-07-23

## Frozen contract

- Canonical contract: `crates/trillionnium-os-types/contracts/capability-lease-root-listener-correlation-v1.json`
- Schema: `org.trillionnium.capabilitylease.root-listener-correlation.contract.v1`
- SHA-256: `2cde8a3875dcefcb02d066138c37cf4af8c8f5666f693f90669436873eb81656`
- Root publication dependency: `2a23182e8778f51086ab66f93dd39a51b0fc56f5b5a62947e7fd340e736e1a74`
- Root authenticator dependency: `eadb86b31c7927c5b16cda4d94553db8cc534584fa30b05c76338e69e26630c3`
- Root proof carrier dependency: `30dd53fc52e139dee108d6eb51ea5958e8c43a7fb45f496b47f145b0f68d2a35`
- Root socket/result custody dependency: `78556032618fc9e246a56e7978812a5859b9c08d9c71672c6e94f9232d85c0ed`

## Publication listener custody

The SDK contains a source-disabled constructor for exactly one abstract
root-publication server socket and one accepted connection. The adapter reads
PID/UID/GID from kernel credentials, requires enforced SELinux and the peer
context from the accepted descriptor, and parses the peer's positive procfs
starttime. The listener takes the complete kernel snapshot before and after one
bounded canonical publication frame plus exact EOF, applies one fixed
15-second read timeout, writes one exact commitment-only ACK and then closes.

The constructor is absent from the runtime factory, System API service,
coordinator and manifest. It owns no token registry, broker route, Binder
surface or effect call.

## Proof-to-authenticator correlation

The proof carrier now recomputes the complete P0.6 authentication binding
before admitting a delivery. A valid delivery is immediately converted from
mutable JSON into a closed immutable scalar snapshot. One non-replaceable
correlation object implements both the publication-listener peer
authentication interface and the backend publisher root-journal
authentication interface. The listener constructor rejects a different object
from the authenticator retained by the ingress publisher.

The only accepted order is proof admission, exact publication match, replay-
sync peer authentication, publisher epoch authentication and one registration-
record authentication. Registration success or any mismatch, replay,
out-of-order method, second publication or root-ACK request clears all retained
snapshot state and becomes terminal. There is no queue, persistence, alternate
carrier, replacement proof or retry in one correlation object.

## Product HOLD

All broker-route, product-constructor, proof-listener wiring, publication-
listener wiring, runtime-consumer, product token-mutation, ACK-authority,
lease-trust and effect-authority flags remain false. No publisher binary is
packaged, no listener coordinator exists and no concrete socket or syscall path
was executed on Android hardware.

## Validation

- `trillionnium-os-types`: 62 passed.
- `trillionnium-agent-privilege-broker`: 118 passed, 1 ignored; integration
  tests: 3 passed.
- `trillionniumd`: 276 passed, 2 ignored; capability conformance: 8 passed,
  1 ignored.
- `trillionnium-agent-api-uds`: 9 passed.
- `trillionnium-agent-direct-tools`: 121 passed; MCP integration: 2 passed.
- SDK current-source host JUnit: 89 passed; the Android-only proof and
  publication constructors also compile against the current framework header.
- SDK capability-lease broker, System API and Open URI source gates passed.
- Vendor same-ABI: 11 passed; capability trust: 8 passed; Direct and OpenClaw
  product gates passed.
- AiShell current-source host JUnit: 28 passed; its security contract passed.
- SELinux broker, issuer and replay-sync policy contracts: 7, 5 and 7 passed.
- Canonical, SDK and vendor mirrors are byte-identical at SHA-256
  `2cde8a3875dcefcb02d066138c37cf4af8c8f5666f693f90669436873eb81656`.
- All generated-source checks, `cargo fmt --all -- --check` and affected
  repository `git diff --check` runs passed.
