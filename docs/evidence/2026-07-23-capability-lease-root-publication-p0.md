# Capability-Lease Root Publication P0 Evidence

Date: 2026-07-23

## Scope

This checkpoint freezes a source-only publication envelope between the durable
root Direct journal and Android's durable capability-token registry. It adds a
deterministic control-side frame, separates the represented Agent from the
OS-owned replay-sync transport process, and adds an injection-only strict SDK
ingress. It does not add a listener, publisher process or Android effect.

## Frozen Contract

- Canonical contract:
  `crates/trillionnium-os-types/contracts/capability-lease-root-publication-v1.json`
- Contract SHA-256:
  `2a23182e8778f51086ab66f93dd39a51b0fc56f5b5a62947e7fd340e736e1a74`
- Protocol: `trillionnium.capability-lease-root-publication.uds.v1`
- Operation: `register_task`
- Root-registration contract SHA-256:
  `7e71b2fd71b6dbd87ec83b5b649dba743d63846cdf1da51c42b5977959e6815a`
- Publication golden SHA-256:
  `ac58fc6425bc0989b97fa936787de7fa388a7e9bbb7e247001a3c75d5b6bae5e`
- ACK golden SHA-256:
  `e0768cd4c80f4fdc013f8e3b125388a038da5597f7c8173c7fbeab8a8463b304`

Frames are `u32be(payload length) || canonical compact UTF-8 JSON`, are capped
at 8,192 payload bytes and require exact EOF. Unknown fields, duplicate keys,
noncanonical JSON, length drift, registration drift, transport drift and
commitment drift fail closed. ACKs contain commitments only and never the raw
task-context token.

## Trust Separation

The capability subject is still the generated `AgentDescriptor`. The
publication transport is separately bound to:

- the represented Agent's exact UID and GID;
- role `system_api_replay_sync`;
- SELinux domain
  `u:r:trillionnium_agent_system_api_replay_sync:s0`;
- executable identity
  `system_ext/bin/trillionnium-system-api-replay-sync`;
- a nonzero measured executable SHA-256.

`CapabilityLeaseBackendAckPublisher` passes both identities to the injected
root authenticator. The token registry stores the represented Agent, not the
transport helper. Exact registration retry returns the commitment of the
immutable checksummed `TRCLTK02` ISSUED registration image, so a later token
consumption transition cannot change the publication ACK.

## Cross-Repository Binding

- Rust publication/ACK implementation:
  `crates/trillionnium-os-types/src/capability_lease_root_publication.rs`
- Java/mirror generator:
  `crates/trillionnium-os-types/tools/generate-capability-lease-root-publication.py`
- SDK generated binding:
  `CapabilityLeaseRootPublicationBindingV1.java`
- SDK strict protocol and injection-only ingress:
  `CapabilityLeaseRootPublicationProtocolV1.java` and
  `CapabilityLeaseRootPublicationIngressV1.java`
- Byte-identical SDK/vendor mirrors:
  `contracts/capability-lease-root-publication-v1.json`

The root journal remains the only publication durability source. No second
outbox was created, avoiding two independently mutable claims about what must
be published.

## Non-Claims

The contract fixes listener, runtime consumer and effect authority to `false`.
No socket, daemon publisher, replay-sync binary, init service, live root
authenticator, Binder registration, enabled capability trust, token disclosure,
URI effect, device operation, OTA, flash, signature, commit or release was
added. Product state remains HOLD.

## Validation

- Rust OS types: 55 passed.
- Generic Agent API UDS: 9 passed.
- Daemon main suite: 276 passed, 2 privileged-process tests ignored.
- Capability conformance: 8 passed, 1 privileged-kernel test ignored.
- SDK capability-lease host JUnit: 78 passed.
- SDK broker source contract: PASS.
- Vendor same-ABI conformance: 11 passed.
- Vendor capability trust checker: 8 passed.
- Vendor Direct and OpenClaw product contracts: PASS with effect integration
  HOLD.
- Generator check, byte-identical mirrors, Rust formatting and repository diff
  checks: PASS.
