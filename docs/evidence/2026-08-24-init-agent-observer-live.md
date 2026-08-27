# Init / Agent observer — 2026-08-24

This is a read-only observer record for device `ZY32JLVHGN`.  It does not
authorize an effect, ACK, replay, mount, service start, or device write.

## Transport

- `adb get-state`: `device`.
- Gnirehtet 2.5.1 reverse tether remained active: host `192.168.0.4`, phone
  `wlan0=192.168.0.10/24`, phone `tun0=10.0.0.2/32`.
- The reverse mapping observed on the host was
  `UsbFfs localabstract:gnirehtet tcp:31416`; the relay listener is bound to
  host loopback only.

## Read-only Android observations

- `ro.build.type=userdebug`, `ro.build.tags=test-keys`.
- `ro.boot.verifiedbootstate=orange`, slot `_a`, `sys.boot_completed=1`.
- `service check android.hardware.security.keymint.IKeyMintDevice/default`:
  `not found`.
- `init.svc.trillionnium_agent_egress_guard=stopped`.
- No `trillionniumd`, `agentd`, `codex`, or `root-linux` process was present.
- Android AiAuthority/AiShell processes and the abstract sockets
  `@trillionnium_system_api`, `@trillionnium-agent-gateway-v1`, and
  `@trillionnium_system_api_replay_control` were present.  Socket presence is
  not authenticated-peer or effect-authority evidence.
- Accessibility reported the installed agent service as enabled/binding, but
  `Bound services:{}`.  This snapshot is not treated as production ownership
  or replay/ACK closure.
- Rollback manager was present, but the read-only dump contained no hardware
  rollback high-water/attestation evidence.

No shell write, `setprop`, service start, install, input, effect, ACK, replay,
reboot, or flash command was issued during this observation.  ADB remains up
only because the Gnirehtet relay requires the USB transport.

