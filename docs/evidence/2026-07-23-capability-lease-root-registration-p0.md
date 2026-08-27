# Capability-Lease Root Registration P0 Evidence

Date: 2026-07-23

## Scope

This checkpoint closes the first source-only registration boundary from a
validated root Direct-operation binding to Android's durable capability-lease
task-token registry. It does not activate a lease, transport a token, or execute
an Android effect.

## Frozen Contract

- Canonical source:
  `crates/trillionnium-os-types/contracts/capability-lease-root-registration-v1.json`
- Contract schema:
  `org.trillionnium.capabilitylease.root-registration.contract.v1`
- Payload schema:
  `org.trillionnium.capabilitylease.root-task-registration.v1`
- Contract SHA-256:
  `7e71b2fd71b6dbd87ec83b5b649dba743d63846cdf1da51c42b5977959e6815a`
- Golden opaque-token SHA-256:
  `31839495296e57aac36136f5ac3a8265b2661352e7502f01d20743331ab86a89`
- Golden registration binding SHA-256:
  `5c67053c1e83212a6ab7fb189789c421c7544353da4787d5cf459d35ec43b956`

The binding preimage has 18 ordered fields. Every field is framed as
`u32be(name length) || ASCII name || u32be(value length) || value`; strings are
UTF-8 and positive Java `long` values are encoded as eight-byte big-endian
integers. The serialized payload has exactly 17 fields and rejects unknown
fields.

## Cross-Repository Binding

- Rust producer and validator:
  `crates/trillionnium-os-types/src/capability_lease_root_registration.rs`
- Canonical generator:
  `crates/trillionnium-os-types/tools/generate-capability-lease-root-registration.py`
- SDK generated Java binding:
  `trillionnium/lib/main/java/org/trillionnium/platform/internal/CapabilityLeaseTokenBindingV1.java`
- SDK contract mirror:
  `contracts/capability-lease-root-registration-v1.json`
- Vendor contract mirror:
  `prebuilt/common/contracts/capability-lease-root-registration-v1.json`

The Rust producer resolves only the generated built-in Agent descriptor from a
valid DirectOperationBinding inbox and derives `root_direct_binding_sha256`
from that inbox. The Android root-journal publisher passes its already verified
peer, boot, epoch and record fields into the generated Java digest function.
Neither side accepts a model-authored adapter, action, subject user, replay
namespace or root Direct binding.

## Source Validation

- Generator check: canonical Rust, Java and both JSON mirrors exact.
- Generator negative check: duplicate contract fields rejected before output
  validation.
- Rust root-registration tests: 6 passed.
- Full Rust OS types: 51 passed.
- Generic Agent API UDS: 9 passed.
- Daemon capability conformance: 8 passed, 1 privileged-kernel test ignored.
- Daemon main suite: 276 passed, 2 privileged-process tests ignored.
- SDK token-registry JUnit: 7 passed.
- Full SDK capability-lease host JUnit: 75 passed.
- SDK broker source contract: PASS.
- SDK backend capability-lease source contract: PASS.
- Vendor same-ABI conformance: 11 passed; capability trust checker: 8 passed.
- Vendor Direct and OpenClaw product contracts: PASS with effect integration
  HOLD.
- AiShell Direct result, recovery and strict-frame JUnit: 28 passed; security
  source contract: PASS.
- Standalone generated-Java golden execution: exact match with the Rust/JSON
  golden binding.

The Java host suites were compiled from current source with the existing Soong
JUnit, JSON and Hamcrest artifacts. The local tree still lacks a usable
`lineage_fogos` product configuration, so this is host-equivalent source
validation rather than a new successful Soong product-build claim.

## Non-Claims

The contract sets `transport_available`, `runtime_consumer_available` and
`confers_effect_authority` to `false`. This checkpoint adds no daemon publisher,
socket, Binder service, product constructor, trust material, task-token
delivery, measured root-journal authenticator, receipt/ACK publisher, URI
effect, ADB interaction, device write, OTA, flash, signature, commit or release.
Product state remains HOLD until those independent producers and physical
evidence gates exist.
