# Codex packaging contract

Source presence does not mean that Codex is installed or usable on a phone.
Product integration must satisfy every condition below:

- Generate the OS-owned Codex manifest from the final packaged executable and
  install it root-owned, non-group/world-writable. The daemon must reject an
  absent, incompatible, or digest-mismatched manifest.
- Run Codex under its fixed UID/GID, SELinux domain, cgroup leaf, measured
  entrypoint, and per-request network policy from the generated descriptor.
  Registration cannot create or rotate that identity.
- Keep prompts and credentials out of argv, environment, files visible to the
  model, and Android application storage. Provider network access must use the
  OS-owned bounded egress path.
- Keep the Agent API replay store on persistent private storage with exact
  owner/mode/canonical-state checks so crash-pending and terminal records
  survive daemon restart.
- Let Android init own `/data/trillionnium/agent-tools` and expose only its
  validated bind at `/var/lib/trillionnium/agent-tools` inside Root Linux.
  Codex bindings use the fixed `codex/{system-api,accessibility}` leaves; model
  input cannot choose paths, identities, epochs, attempts, or tool-call IDs.
- Require the measured root-owned binding, kernel custody, durable operation
  allocation, backend replay synchronization, and terminal evidence before an
  effect can be reported as complete.

The checked-in Android helper binaries and rootfs must be rebuilt from the
Codex-only source graph before product admission. A source-only manifest,
launcher, or contract is not launch/effect evidence.

Direct shell and ADB are a planned OS-owned capability family. They have no
production transport or authority in the current daemon and must remain HOLD
until the ADR's authentication, SELinux, cgroup, audit, confirmation, replay,
and device-conformance gates are implemented.
