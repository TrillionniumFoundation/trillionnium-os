# Capability-Lease Private Root Route Socket Custody P0 Evidence

Date: 2026-07-23

## Frozen contract

- Canonical contract:
  `crates/trillionnium-os-types/contracts/capability-lease-root-route-socket-custody-v1.json`
- Schema:
  `org.trillionnium.capabilitylease.root-route-socket-custody.contract.v1`
- SHA-256:
  `8c7bced5820370ecdf26af9dac2c86267e66bfef80cf5457102a93e57052064e`
- P0.12 dependency:
  `dfa1d57396805b2c9b8c7a5c65dd0e88756966f167fa3e9d2c73e45fa73f4796`

## Agentd listener custody

The privilege broker now contains a concrete but source-disabled Linux/Android
abstract-UDS listener for the P0.12 private route. It creates one nonblocking,
close-on-exec stream socket, binds the exact fixed abstract name, listens with
backlog one, revalidates the same descriptor and accepts exactly one unnamed
client within one monotonic five-second deadline. The listener is consumed by
accept and cannot rebind or retry.

The accepted stream remains nonblocking. Request read, response write and exact
EOF each use one absolute deadline rather than resetting a per-syscall timeout.
Unknown poll events, peer drift, malformed framing, timeout or any transport
failure close custody without a response or alternate route. Four kernel peer
checks in the P0.12 seam require a positive PID, UID/GID 1000/1000 and the
exact `system_server` SELinux domain.

## System-server connector custody

The SDK now contains an Android-only, source-disabled one-connect adapter. It
creates one nonblocking close-on-exec AF_UNIX stream descriptor, connects only
to the fixed abstract address and resolves `EINPROGRESS` using one monotonic
five-second `poll(POLLOUT)` deadline plus exact `SO_ERROR == 0`. It then adopts
that descriptor into one `LocalSocket`.

The P0.12 exchange was split into request and pending-response custody so the
coordinator can retain exactly one terminal exchange. Response framing and EOF
share one `System.nanoTime` deadline, with the remaining timeout installed
before every blocking read. Four peer snapshots require a stable positive PID,
UID/GID 0/0 and the exact `trillionnium_agentd` SELinux domain. There is no
reconnect, queue, background thread, Binder surface, service or alternate
carrier.

## Product HOLD

The listener and connector are absent from broker `main`, the public privilege
broker request protocol, SDK runtime factories, services and product
manifests. Coordinator route wiring, token mutation, ACK authority, lease trust
and effect authority remain false. The publisher is not packaged and the
Android socket/syscall path was not executed.

## Validation

- `trillionnium-os-types`: 66 passed.
- `trillionnium-agent-privilege-broker`: 125 passed, 1 ignored; three
  integration tests passed.
- `trillionniumd`: 276 passed, 2 ignored; capability conformance: 8 passed,
  1 privileged-kernel test ignored.
- `trillionnium-agent-api-uds`: 9 passed.
- `trillionnium-agent-direct-tools`: 121 passed; MCP integration: 2 passed.
- SDK current-source host JUnit: 98 passed.
- Android hidden-framework connector compile passed against the current
  framework and libcore header jars.
- All eight SDK source/semantics gates passed.
- Vendor same-ABI tests passed 11/11; disabled-trust tests passed 8/8; Direct
  and OpenClaw product gates passed with the contract absent from the runtime
  manifest.
- Capability-lease broker, issuer and replay-sync SELinux contracts passed
  7/7, 5/5 and 7/7.
- AiShell source gate and current-source host JUnit passed 28/28.
- Canonical, SDK and vendor contract mirrors are byte-identical at SHA-256
  `8c7bced5820370ecdf26af9dac2c86267e66bfef80cf5457102a93e57052064e`.
- Five checked-in generators, `cargo fmt --all -- --check` and affected
  repository `git diff --check` passed.
