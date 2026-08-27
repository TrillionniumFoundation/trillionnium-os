# Trillionnium Agent Privilege Broker

> **Pre-r2 sealed/history only (2026-08-27):** This binary is the former
> Authority, not an owner-open substrate service. The owner-open product must
> not compile, link or start it, and must not use its
> `mutation_unavailable`/HOLD result for shell or ADB. Keep it only for an
> explicitly selected `sealed-privilege-broker` compatibility/research target.

Status: Codex-only source foundation; product mutation and effect authority are
HOLD.

The live binary accepts one OS-created `AF_UNIX/SOCK_SEQPACKET` listener and
one authenticated client. It validates `SO_PEERCRED`, `SO_PEERSEC`, executable
measurement, PID/start time, listener identity, and a closed capability
contract. Startup hardening requires an untraced single-threaded process,
`PDEATHSIG=SIGKILL`, `umask(077)`, zero core limits, non-dumpability,
`no_new_privs`, and the reviewed capability mask. Ambiguous or partial
hardening fails closed.

The production identity set is the generated Codex singleton. No wire field,
environment variable, argument, path, UID/GID, process ID, cgroup, executable,
or timeout can select another Agent identity.

The current draft protocol deliberately has no mutation backend. Credential,
install, spawn, collect, terminate, and recovery requests return
`mutation_unavailable/backend_not_installed` and produce no effect. The broker
opens no Internet socket, launches no Agent, installs no credential, and does
not grant shell, ADB, or Android effect authority.

Source-only modules retain bounded contracts for later implementation:

- measured exec and pidfd custody;
- final payload and post-exec hardening receipts;
- replay-sync publisher custody;
- authenticated broker-to-system-server proof transport;
- monotonic authority and production-effect composition;
- opt-in P0 launch-package conformance fixtures.

Those modules are not live broker routes. Test-only Linux producers and host
fixtures are evidence about contract behavior, not Android product proof.

Product promotion requires one reviewed Codex-only implementation that closes
all of the following together: init-owned listener provenance, SELinux and
cgroup installation, seccomp, capability enforcement, kernel-observed
descendant cleanup, durable reservation/recovery, measured final payload,
authenticated effect transport, reboot/replay/power-loss evidence, clean
target-files, and signed-device conformance. Until then this crate is a
fail-closed foundation, not a working privilege service.
