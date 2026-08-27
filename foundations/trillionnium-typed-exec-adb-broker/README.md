# Typed exec/ADB broker source foundation

This standalone crate freezes and host-runs the smallest safe broker core
without changing the current daemon, Direct tool crate, Android product graph,
or any device. It remains an independent Cargo workspace.

What is implemented here:

- a closed, measured catalog with one read-only typed-exec userdebug
  conformance operation;
- a second read-only typed-ADB descriptor whose live backend remains HOLD;
- typed request/response identities bound to provider, Agent, Direct binding,
  delivery attempt, operation ordinal, catalog, deadline, and output bounds;
- an OS-observation admission model for `SO_PEERCRED`, `SO_PEERSEC`, pidfd-bound
  cgroup evidence, close-on-exec file descriptors, exact artifacts, seccomp,
  and cgroup profiles;
- prepare-before-dispatch, exact terminal response replay, conflict rejection,
  and indeterminate-without-retry behavior in the broker core;
- an exclusive-writer durable replay ledger whose PREPARED transition is an
  append and whose TERMINAL transition is an exact PREPARED CAS. The ledger
  component-opens its absolute root without following symlinks, requires
  regular single-link owner-held `0600` files, and publishes through temporary
  write, file fsync, atomic rename, directory fsync, and exact readback;
- restart recovery for exact terminal response replay and PREPARED-only HOLD,
  including explicit crash-point coverage before/after file fsync, rename,
  directory fsync, and readback;
- a Unix `SOCK_SEQPACKET|SOCK_CLOEXEC` request-framing core that obtains
  `SO_PEERCRED`, binds exact PID/UID/GID to a fixed supervisor-owned
  provider/Agent allowlist, accepts one canonical length-prefixed JSON packet,
  and enforces independent frame, request-size, and boot-deadline bounds;
- exhaustive negative and replay tests.

What is intentionally not implemented:

- no bound daemon/listener socket, accept loop, MCP wiring, or product policy
  constructor;
- no Android.bp, init, SELinux, cgroup, seccomp, AVB, or OTA integration;
- no product authority or product-provisioned durable ledger path;
- no execution backend: even `/system/bin/getprop` with the fixed read-only
  `ro.build.fingerprint` argument stops after authenticated framing/admission;
- no arbitrary executable, argv, shell string, serial, host, port, or file
  descriptor supplied by an Agent;
- no install, push, pull, remount, reboot, mutation, or Windows operation;
- no live typed-ADB transport or adbd key custody.

The only descriptor accepted by the host UDS server core is the read-only
build-fingerprint getprop descriptor. Typed ADB parses as a closed protocol
value and then returns HOLD. The existing `trillionnium-agent-adb` remains an
operator-only debug adapter outside this crate; this foundation neither enables
it nor makes it an Agent capability. The accepted product direction is direct
Codex shell/ADB through OS-owned transport, but that production backend remains
HOLD.

The durable ledger and authenticated framing are real host filesystem/kernel
implementations, not in-memory claims. That does **not** make the broker a
usable OS service: no socket is installed, no product UID/SELinux/cgroup policy
is provisioned, and no backend process can be launched. Product and device
effect authority remain false.

Run the isolated checks with:

```sh
cargo test --manifest-path foundations/trillionnium-typed-exec-adb-broker/Cargo.toml
```
