# Capability-Lease Root Publisher Launch P0 Evidence

Date: 2026-07-23

## Frozen source contract

- Canonical contract: `crates/trillionnium-os-types/contracts/capability-lease-root-publisher-launch-v1.json`
- Schema: `org.trillionnium.capabilitylease.root-publisher-launch.contract.v1`
- SHA-256: `1469b2f75f681b7224408e78e64ba6d2e7b7985e9c0d81a92e156147db89c9c2`
- Publication dependency SHA-256: `2a23182e8778f51086ab66f93dd39a51b0fc56f5b5a62947e7fd340e736e1a74`
- Fixed executable identity: `system_ext/bin/trillionnium-system-api-replay-sync`
- Fixed publisher domain: `u:r:trillionnium_agent_system_api_replay_sync:s0`
- Fixed server identity: UID/GID 1000 and `u:r:system_server:s0`
- Fixed abstract socket: `trillionnium_capability_lease_root_publication`

The contract explicitly records `product_package_available:false`,
`launcher_wired:false`, `listener_wired:false`,
`runtime_consumer_available:false` and `confers_effect_authority:false`.

## Measured launch custody

`trillionnium-agent-privilege-broker` now contains a source-only, non-copyable
custody typestate. It derives a launch only from an exact P0.4 publication and
the generated Agent descriptor, then requires:

- a fixed absolute, read-only, regular, single-link executable;
- SHA-256 measurement and `execveat(AT_EMPTY_PATH)` over the same descriptor;
- exact generated Agent UID/GID and the fixed replay-sync SELinux transition;
- one stdin publication frame and one stdout ACK frame;
- closed stderr and unrelated file descriptors, no arguments and empty env;
- `SIGKILL` parent death, no-new-privileges, non-dumpability, empty capabilities
  and no descendants;
- mandatory kill/reap on post-exec identity or custody drift.

The operations trait has no Linux implementation, broker route or product
constructor in this checkpoint.

## One-shot publisher transport

`trillionnium-agent-direct-tools` now provides the source-only
`trillionnium-system-api-replay-sync` binary. It verifies its process identity,
binds the input publication to the generated Agent descriptor and fixed
executable identity, connects once to the fixed abstract socket, authenticates
the exact `system_server` peer using `SO_PEERCRED` and `SO_PEERSEC`, sends one
bounded publication frame, receives one ACK frame plus exact EOF, and verifies
all returned commitments. Errors produce no stderr payload under the frozen
closed-stderr launch contract.

## Authenticated listener seam

The SDK adds a source-only accepted-connection handler rather than a socket
owner. It snapshots peer UID/GID/SELinux identity before and after reading the
bounded publication frame, rejects cross-Agent or domain drift, binds the
publication to the kernel peer, obtains the measured publisher-authentication
commitment and boot commitment, and only then calls the P0.4 ingress. It emits
an ACK only after durable registry acceptance.

There is no `LocalServerSocket`, runtime factory reference, manifest entry,
init service, packaged publisher, bound endpoint, live authenticator, Binder
service, enabled lease trust or effect authority.

## Validation

The final validation matrix passed:

- `trillionnium-os-types`: 56/56;
- Agent API UDS: 9/9;
- `trillionnium-agent-direct-tools`: 119/119 plus 2/2 MCP integration tests;
- privilege broker: 108 passed/1 ignored plus 3/3 integration tests;
- `trillionniumd`: 276 passed/2 ignored;
- capability conformance: 8 passed/1 ignored;
- SDK JUnit: 80/80;
- vendor same-ABI: 11/11 and trust: 8/8;
- SELinux replay-sync policy: 7/7;
- Direct and OpenClaw product gates: PASS;
- four canonical generators, formatting, byte-identical contract mirrors and
  repository diff checks: PASS.
