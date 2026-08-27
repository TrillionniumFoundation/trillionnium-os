# Capability-Lease Private Root Route Session P0 Evidence

Date: 2026-07-23

## Frozen contract

- Canonical contract:
  `crates/trillionnium-os-types/contracts/capability-lease-root-route-session-v1.json`
- Schema:
  `org.trillionnium.capabilitylease.root-route-session.contract.v1`
- SHA-256:
  `3f4f5705be8e8226479b600b0d2bf7b0a9ee8545aabed5a429684609ae493485`
- P0.11 coordinator dependency:
  `2d443deb647e4c3d41f6dc768306395f954f34fcf7b10c5f2d5cbee1c25e27c3`
- P0.12 transport dependency:
  `dfa1d57396805b2c9b8c7a5c65dd0e88756966f167fa3e9d2c73e45fa73f4796`
- P0.13 socket-custody dependency:
  `8c7bced5820370ecdf26af9dac2c86267e66bfef80cf5457102a93e57052064e`

## Agentd terminal server session

The privilege broker now contains one source-disabled terminal session around
the P0.13 private route listener. Binding owns exactly one abstract-UDS
listener. Serving consumes that listener before accepting and cannot retry,
rebind or restart. Explicit pre-serve close releases the bound abstract name,
clears custody and leaves the same session terminal.

The existing one-shot route remains crate-internal and commitment-only. It is
absent from broker `main` and the public request protocol. Success returns only
the existing P0.11 served-publication commitments; failure emits no diagnostic
frame and creates no alternate route.

## System-server terminal client session

The SDK now contains one Android-only, source-disabled session constructor. It
creates the P0.13 connector-backed private route without I/O, then delegates to
the P0.11 bound-listener helper, which binds publication before proof. Only the
resulting session's single `runOnce()` may connect to agentd after all three
listeners have been externally ordered and bound.

The coordinator, private route adapter and session now implement explicit
close custody. Pre-run close shuts publication, proof and connector-route
custody, clears retained registration and correlation state, and becomes
terminal. Success and failure also close all owned resources. A second run or
close cannot restart the route.

## Product HOLD

The contract freezes the external order as system_server publication bind,
system_server proof bind, agentd private-route bind, then system_server
`runOnce()`. No cross-process startup orchestrator implements that order. The
constructors are absent from broker `main`, the public broker protocol, SDK
runtime factories, services and product manifests. Product startup, token
mutation, ACK authority, lease trust and effect authority remain false. The
publisher is not packaged and the Android socket/syscall path was not run.

## Validation

- `trillionnium-os-types`: 67 passed.
- `trillionnium-agent-privilege-broker`: 126 passed, 1 ignored; three
  integration tests passed.
- `trillionniumd`: 276 passed, 2 ignored; capability conformance: 8 passed,
  1 privileged-kernel test ignored.
- `trillionnium-agent-api-uds`: 9 passed.
- `trillionnium-agent-direct-tools`: 121 passed; MCP integration: 2 passed.
- SDK current-source host JUnit: 99 passed.
- Android hidden-framework publication, proof, bound-listener, connector and
  route-session constructor compilation passed.
- All eight SDK source/semantics gates passed.
- Vendor same-ABI tests passed 11/11; disabled-trust tests passed 8/8; Direct
  and OpenClaw product gates passed with the contract absent from runtime
  manifests.
- Capability-lease broker, issuer and replay-sync SELinux contracts passed
  7/7, 5/5 and 7/7.
- AiShell source gate and current-source host JUnit passed 28/28.
- Canonical, SDK and vendor contract mirrors are byte-identical at SHA-256
  `3f4f5705be8e8226479b600b0d2bf7b0a9ee8545aabed5a429684609ae493485`.
- Five checked-in generators, `cargo fmt --all -- --check` and affected
  repository `git diff --check` passed.
