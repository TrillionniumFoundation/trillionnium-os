# Capability-Lease Measured Root Authenticator P0 Evidence

Date: 2026-07-23

## Frozen contract

- Canonical contract: `crates/trillionnium-os-types/contracts/capability-lease-root-authenticator-v1.json`
- Schema: `org.trillionnium.capabilitylease.root-authenticator.contract.v1`
- SHA-256: `eadb86b31c7927c5b16cda4d94553db8cc534584fa30b05c76338e69e26630c3`
- Root-publication dependency: `2a23182e8778f51086ab66f93dd39a51b0fc56f5b5a62947e7fd340e736e1a74`
- Publisher-launch dependency: `1469b2f75f681b7224408e78e64ba6d2e7b7985e9c0d81a92e156147db89c9c2`
- Cross-language authentication golden: `b6cb97987f06f48d4f0f53af2ae2957213bf7272119ddce6075236aa11d0c65b`

The authentication preimage binds 24 ordered fields: contract dependencies,
Agent identity, boot identity, PID/starttime, UID/GID/SELinux, executable
identity/digest, pidfd identity, publication/registration bindings,
epoch/sequence, root-journal genesis and root-record proof.

All activation flags remain false: no concrete Linux kernel backend, broker
route, product constructor, listener wiring, runtime consumer or effect
authority exists.

## Linux custody seam

The P0.5 custody typestate now retains the exact encoded publication frame and
requires clone-returned pidfd identity, positive child PID/starttime, ptrace
exec-stop, stable post-exec starttime and exact stdin-frame binding before it
can derive a non-copyable authentication snapshot. Any mismatch is killed and
reaped before authority can escape.

`linux_replay_sync_publisher_ops.rs` fixes the Linux sequence and the exact
kernel operations required by a future backend: read-only same-FD ELF
measurement, `clone3(CLONE_PIDFD)`, stopped same-FD `execveat`, exact request
pipe, ptrace exec-stop observation, pidfd resume and pidfd kill/reap. It has no
concrete kernel implementation or broker route.

## SDK authenticator

The immutable source-only authenticator implements both the listener's
measured-peer source and the backend publisher's root-journal authenticator.
It accepts one broker-custody snapshot, rechecks PID/starttime twice through
the listener, boot, generated Agent UID/GID, fixed SELinux/executable identity,
executable digest, publication binding, publisher epoch and exact task
registration/root-record proof. It supports exact immutable retry and denies
contiguous root-ACK authority.

The publication decoder now retains boot identity explicitly, preventing an
old-boot publication from being rebound to a current-boot peer snapshot.

## Product HOLD

The SDK runtime factory, System API service, coordinator and manifest contain
no authenticator/listener/ingress reference. Vendor packages contain no
replay-sync publisher, and the authenticator contract is forbidden from the
runtime manifest. There is no live proof transport, concrete kernel backend,
socket owner, Binder service, enabled lease trust or effect authority.

## Validation

The final completion matrix passed:

- `trillionnium-os-types`: 59/59;
- Agent API UDS: 9/9;
- Direct tools: 119/119 plus MCP integration 2/2;
- privilege broker: 109 passed/1 ignored plus integration 3/3;
- `trillionniumd`: 276 passed/2 ignored;
- capability conformance: 8 passed/1 ignored;
- SDK JUnit: 83/83, including the Rust/Java authentication golden;
- vendor same-ABI: 11/11 and trust: 8/8;
- SELinux replay-sync policy: 7/7;
- Direct/OpenClaw product gates, SDK source gate, four canonical generators,
  three byte-identical authenticator mirrors, formatting and all repository
  diff checks: PASS.
