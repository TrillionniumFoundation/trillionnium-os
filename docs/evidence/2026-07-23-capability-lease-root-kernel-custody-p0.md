# Capability-Lease Root Kernel Custody P0 Evidence

Date: 2026-07-23

## Frozen contract

- Canonical contract: `crates/trillionnium-os-types/contracts/capability-lease-root-kernel-custody-v1.json`
- Schema: `org.trillionnium.capabilitylease.root-kernel-custody.contract.v1`
- SHA-256: `4d1fef7a3bc0ab7e66ef51d6cfb6ad478fffcf3b5484530fc379ced413ce0009`
- Root authenticator dependency: `eadb86b31c7927c5b16cda4d94553db8cc534584fa30b05c76338e69e26630c3`
- Root proof carrier dependency: `30dd53fc52e139dee108d6eb51ea5958e8c43a7fb45f496b47f145b0f68d2a35`

## Concrete source backend

The source-only backend implements fixed `openat2` resolution, same-FD ELF
measurement and `execveat(AT_EMPTY_PATH)`, `clone3(CLONE_PIDFD|SIGCHLD)`, an
initial traced stop, exact `PTRACE_EVENT_EXEC`, a measured-binary post-exec
self-hardening stop, stable `/proc` starttime, post-exec credential/SELinux/
executable/FD/environment/argument/capability/seccomp checks, pidfd resume and
pidfd SIGKILL plus exact reap.

The child hardening path installs the fixed SELinux exec transition, generated
Agent UID/GID, empty inheritable/permitted/effective/ambient capability sets,
NNP, non-dumpability, SIGKILL parent death and a seccomp filter denying
`clone`, `clone3`, `fork` and `vfork`. Only stdin and stdout survive exec.

## Proof-before-resume order

The exact canonical publication frame is written and the request pipe is
closed while the child remains at its measured post-exec hardening stop.
Kernel custody is converted into the immutable P0.6 authentication value,
which must be delivered through an injected P0.7 authenticated proof
connection before `PTRACE_DETACH`. Proof delivery failure kills and reaps the
child without resume.

## Product HOLD

The backend and source constructor are absent from broker `main`; there is no
socket constructor, broker request route, packaged publisher, live listener,
runtime authenticator constructor, token mutation, ACK authority or effect
authority. The real syscall path is compiled but not executed on this host,
because no reviewed packaged Android helper, SELinux transition or live proof
socket exists.

## Validation

- `trillionnium-os-types`: 62 passed.
- `trillionnium-agent-privilege-broker`: 116 passed, 1 ignored; integration
  tests: 3 passed.
- `trillionniumd`: 276 passed, 2 ignored; capability conformance: 8 passed,
  1 ignored.
- `trillionnium-agent-api-uds`: 9 passed.
- `trillionnium-agent-direct-tools`: 121 passed; MCP integration: 2 passed.
- SDK host JUnit: 85 passed; capability-lease source gate passed.
- Vendor same-ABI: 11 passed; capability trust: 8 passed; Direct and OpenClaw
  product gates passed.
- Replay-sync SELinux policy: 7 passed.
- Canonical, SDK and vendor custody mirrors are byte-identical at SHA-256
  `4d1fef7a3bc0ab7e66ef51d6cfb6ad478fffcf3b5484530fc379ced413ce0009`.
- Four generators, `cargo fmt --all -- --check` and all affected repository
  `git diff --check` runs passed.
