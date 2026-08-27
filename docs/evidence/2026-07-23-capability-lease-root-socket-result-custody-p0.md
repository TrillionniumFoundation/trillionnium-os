# Capability-Lease Root Socket and Result Custody P0 Evidence

Date: 2026-07-23

## Frozen contract

- Canonical contract: `crates/trillionnium-os-types/contracts/capability-lease-root-socket-result-custody-v1.json`
- Schema: `org.trillionnium.capabilitylease.root-socket-result-custody.contract.v1`
- SHA-256: `78556032618fc9e246a56e7978812a5859b9c08d9c71672c6e94f9232d85c0ed`
- Root publication dependency: `2a23182e38cc8a8eb5cab5e0f94190658dd6b4db09c087ed2bd5c3a23b7e1a74`
- Root proof carrier dependency: `30dd53fc52e139dee108d6eb51ea5958e8c43a7fb45f496b47f145b0f68d2a35`
- Root kernel custody dependency: `4d1fef7a3bc0ab7e66ef51d6cfb6ad478fffcf3b5484530fc379ced413ce0009`

## Fixed proof socket

The broker-side source connector opens exactly one CLOEXEC AF_UNIX stream to
the fixed abstract root-proof name. It installs finite read/write deadlines,
authenticates system_server UID/GID and SELinux domain before and after the
canonical proof frame, sends no alternate frame or retry, shuts down its write
side and requires exact EOF. The SDK's one-shot `LocalServerSocket` constructor
wraps one accepted `LocalSocket` in the P0.7 ingress interface and obtains PID,
UID, GID and peer SELinux context from the kernel on each snapshot.

## Exact publisher completion

The running typestate retains the exact publication, measured authentication,
clone-returned pidfd and child stdout pipe. Completion accepts one canonical
publication ACK only when every publication/registration/epoch/sequence/root
commitment matches, the pipe reaches exact EOF, the pidfd signals process exit,
the child exits normally with status zero and exact `waitpid` reap succeeds.
The result contains commitments only. Any malformed/trailing/drifting/timed-
out ACK or abnormal process result fails closed; an unreaped child is killed
through the retained pidfd and reaped.

## Product HOLD

The connector, one-shot listener constructor, concrete launch and completion
functions are absent from broker `main`, runtime factories, services,
coordinators and manifests. There is no broker route, packaged publisher, live
listener, publication-listener wiring, token mutation, ACK authority, enabled
lease trust or effect authority. No concrete syscall or socket path was run on
Android hardware.

## Validation

- `trillionnium-os-types`: 62 passed.
- `trillionnium-agent-privilege-broker`: 118 passed, 1 ignored; integration
  tests: 3 passed.
- `trillionniumd`: 276 passed, 2 ignored; capability conformance: 8 passed,
  1 ignored.
- `trillionnium-agent-api-uds`: 9 passed.
- `trillionnium-agent-direct-tools`: 121 passed; MCP integration: 2 passed.
- SDK current-source host JUnit: 85 passed; capability-lease broker, System API
  and Open URI source gates passed.
- Vendor same-ABI: 11 passed; capability trust: 8 passed; Direct and OpenClaw
  product gates passed.
- SELinux broker, issuer and replay-sync policy contracts: 7, 5 and 7 passed.
- Canonical, SDK and vendor mirrors are byte-identical at SHA-256
  `78556032618fc9e246a56e7978812a5859b9c08d9c71672c6e94f9232d85c0ed`.
- Five generators, `cargo fmt --all -- --check` and all affected repository
  `git diff --check` runs passed.
