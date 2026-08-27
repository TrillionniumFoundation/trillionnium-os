# USB reverse-tether recovery and validation (local dogfood)

**Date:** 2026-08-24 (Asia/Shanghai)  
**Device:** `ZY32JLVHGN`  
**Scope:** Restore the already-authorized Gnirehtet development network after an
ADB transport interruption. This is not OS custody, an Agent API activation, or
release authority.

## Recovery

- Host Ethernet: `enp4s0=192.168.0.4/24`.
- Device underlay Wi-Fi: `wlan0=192.168.0.10/24`, SSID `TP-LINK_1A4F`.
- At inspection time the host-side Gnirehtet relay process was alive, but the
  ADB reverse mapping was absent and the relay log showed `Client #0
  disconnected`.
- Ran the documented reversible tunnel reset:
  `gnirehtet tunnel ZY32JLVHGN` (exit 0), which restored
  `UsbFfs localabstract:gnirehtet tcp:31416`.
- Restarted only the already-authorized Gnirehtet client:
  `gnirehtet restart ZY32JLVHGN -d 192.168.0.1` (exit 0). The relay then
  reported `Client #2 connected` and resumed forwarding.

## Validation

- `adb devices -l` reports `ZY32JLVHGN device`.
- Device `tun0=10.0.0.2/32`; Android Connectivity reports
  `VPN CONNECTED`, `VPN:com.genymobile.gnirehtet`, `VALIDATED`, and underlying
  Wi-Fi network 102.
- A temporary host-local listener on `127.0.0.1:18080` was used for one probe
  and removed immediately. From the device, curl to `http://10.0.2.2:18080/`
  returned `usb-reverse-ok` (exit 0). No listener remained on port 18080.
- From the device, `curl https://example.com/` returned HTTP 200 (exit 0),
  confirming outbound forwarding through the restored relay.
- The host relay remains on loopback `127.0.0.1:31416`; no public listener was
  created.

## Boundary and risk

- The host ADB server is running because Gnirehtet requires the ADB transport;
  no shell write, install, input, mount, reboot, flash, Codex turn, effect, or
  ACK was issued.
- The host also has an unrelated `tun0` from the hide.me VPN (`10.96.0.17`);
  the device Gnirehtet interface is separately `10.0.0.2`.
- Relay logs contain intermittent `Dropping invalid packet` warnings while
  forwarding normal device traffic; the explicit local and external probes
  still passed after recovery.

