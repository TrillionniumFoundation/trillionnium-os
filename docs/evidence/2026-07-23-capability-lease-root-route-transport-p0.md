# Capability-Lease Private Root Route Transport P0 Evidence

Date: 2026-07-23

## Frozen contract

- Canonical contract: `crates/trillionnium-os-types/contracts/capability-lease-root-route-transport-v1.json`
- Schema: `org.trillionnium.capabilitylease.root-route-transport.contract.v1`
- SHA-256: `dfa1d57396805b2c9b8c7a5c65dd0e88756966f167fa3e9d2c73e45fa73f4796`
- P0.11 dependency: `2d443deb647e4c3d41f6dc768306395f954f34fcf7b10c5f2d5cbee1c25e27c3`

## Commitment-only private transport

The new transport is separate from the public privilege-broker protocol. Its
request selects one product Agent, boot and root registration using only
commitments; it cannot carry a publication, token, task payload, root record
or effect material. Its response contains the seven immutable custody
commitments already frozen by P0.11 plus request and response bindings.

Rust and Java share exact canonical `u32be length + JSON` framing, 4096-byte
payload bounds and SHA-256 binding preimages. The fixed exchange is one request,
shutdown-write, one response and exact EOF. Kernel UID/GID/SELinux credentials
are checked before and after the exchange and drift fails closed. There is no
retry, diagnostic response or alternate carrier.

## Broker and coordinator seams

The broker owns an injected, one-exchange server seam. It authenticates
`system_server`, strictly decodes the selector, resolves exactly one
publication, requires exact Agent/boot/registration equality, runs the P0.11
crate-internal route and emits only the derived response commitments. No
listener, connector, `main` dispatch or public request operation was added.

The SDK owns a source-disabled asynchronous adapter for the P0.11 coordinator.
It starts once, owns one injected pending exchange, converts the exact response
to the existing coordinator result and closes custody on success, error or
abandonment. It contains no socket constructor, Binder surface, service,
runtime factory or token registry reference.

## Product HOLD

The public broker protocol remains unchanged. Private listener/connector,
broker main route, coordinator adapter wiring, runtime construction, token
mutation, ACK authority, lease trust and effect authority remain false. No
publisher was packaged and no Android syscall or socket path was executed.

## Validation

- `trillionnium-os-types`: 65 passed.
- `trillionnium-agent-privilege-broker`: 123 passed, 1 ignored; integration
  tests passed.
- `trillionniumd`: 276 passed, 2 ignored.
- `trillionnium-agent-api-uds`: 9 passed.
- `trillionnium-agent-direct-tools`: existing unit and MCP integration suites
  passed.
- SDK current-source host JUnit: 97 passed.
- SDK capability-lease source gate passed.
- Vendor product contract gate passed with the route transport absent from the
  runtime manifest.
- Canonical, SDK and vendor contract mirrors are byte-identical at SHA-256
  `dfa1d57396805b2c9b8c7a5c65dd0e88756966f167fa3e9d2c73e45fa73f4796`.
- `cargo fmt --all -- --check` and affected repository `git diff --check`
  passed.
