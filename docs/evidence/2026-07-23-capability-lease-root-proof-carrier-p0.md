# Capability-Lease Root Proof Carrier P0 Evidence

Date: 2026-07-23

## Frozen contract

- Canonical contract: `crates/trillionnium-os-types/contracts/capability-lease-root-proof-carrier-v1.json`
- Schema: `org.trillionnium.capabilitylease.root-proof-carrier.contract.v1`
- SHA-256: `30dd53fc52e139dee108d6eb51ea5958e8c43a7fb45f496b47f145b0f68d2a35`
- Authenticator dependency: `eadb86b31c7927c5b16cda4d94553db8cc534584fa30b05c76338e69e26630c3`
- Protocol: `trillionnium.capability-lease-root-proof.uds.v1`
- Fixed abstract socket: `trillionnium_capability_lease_root_proof`

The delivery binding commits the exact immutable P0.6 authentication binding,
agentd UID/GID/SELinux identity, system_server UID/GID/SELinux identity,
protocol and operation. Framing is one canonical length-prefixed JSON value
plus exact EOF, with no ACK frame.

## Why a separate carrier

P0.5 freezes the publisher child to stdin/stdout only with all other file
descriptors closed. Passing a sealed memfd or hidden environment/argument
would violate that contract. P0.7 therefore adds one independent,
kernel-authenticated agentd-to-system_server carrier and does not change the
publisher launch ABI.

## Source seams

The broker transport validates system_server kernel identity twice, writes one
exact frame, shuts down the write side and requires EOF. It has no socket
constructor or broker route.

The SDK ingress validates agentd PID/UID/GID/SELinux twice around exact frame
reading, rejects duplicate/noncanonical/unknown JSON and validates the closed
nested authentication shape plus delivery binding. It returns an immutable
delivery object only; it owns no listener, registry, authenticator constructor
or service.

## Product HOLD

All authority flags are false: broker publisher, listener, runtime consumer,
ACK authority and effect authority. SDK runtime factories/services/coordinators
and manifests cannot reference the carrier, vendor runtime manifests cannot
contain it, and no product package or SELinux socket wiring was added.

## Validation

- `trillionnium-os-types`: 62 passed.
- `trillionnium-agent-privilege-broker`: 111 passed, 1 ignored; integration
  tests: 3 passed.
- `trillionniumd`: 276 passed, 2 ignored; capability conformance: 8 passed,
  1 ignored.
- `trillionnium-agent-api-uds`: 9 passed.
- `trillionnium-agent-direct-tools`: 119 passed; MCP integration: 2 passed.
- SDK host JUnit: 85 passed, including proof-carrier canonical framing,
  identity drift and binding rejection; SDK source gate passed.
- Vendor same-ABI: 11 passed; trust gate: 8 passed; Direct and OpenClaw
  product gates passed.
- Replay-sync SELinux policy: 7 passed.
- Canonical, SDK and vendor contract mirrors are byte-identical at SHA-256
  `30dd53fc52e139dee108d6eb51ea5958e8c43a7fb45f496b47f145b0f68d2a35`.
- Four generators, `cargo fmt --all -- --check` and all affected repository
  `git diff --check` runs passed.
