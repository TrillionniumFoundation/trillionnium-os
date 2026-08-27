# USB reverse-tether evidence (local dogfood only)

**Date:** 2026-08-23 (Asia/Shanghai)  
**Device:** `ZY32JLVHGN`  
**Scope:** temporary host-to-device networking for read-only development probes; not
an OS custody or release-authority mechanism.

## Helper provenance

- Helper: Genymobile Gnirehtet `v2.5.1`, official release asset
  `gnirehtet-rust-linux64-v2.5.1.zip`.
- Release SHA-256 (from the official `SHA256SUMS.txt`):
  `dee55499ca4fef00ce2559c767d2d8130163736d43fdbce753e923e75309c275`.
- Embedded APK SHA-256:
  `c1ac2b869a48e3c836046aac5a168f3ade510288f3304a87ddb671315c564b9a`.
- APK package/version: `com.genymobile.gnirehtet`, `2.5.1`.
- Android signature verification: v1 and v2 valid; signer certificate SHA-256
  `727ba54178803d66c2bb17c33431d19fd79b96a991462cd3c6ab489c627cdc94`.

## Observed network path

- Host Ethernet: `192.168.0.4/24`.
- Device Wi-Fi underlay: `TP-LINK_1A4F`, `192.168.0.10/24`.
- Android system VPN dialog was explicitly confirmed after the user authorized
  USB reverse tethering.
- Android `tun0`: `10.0.0.2/32`, VPN network
  `VPN:com.genymobile.gnirehtet`, validated.
- Relay log recorded a connected tunnel and TCP/DNS forwarding through the host.
- Read-only TCP checks succeeded:
  - device → host loopback mapping `http://10.0.2.2:18080/` reached a temporary
    host-local HTTP server;
  - device → `https://example.com/` returned the expected HTML response.
- The temporary host HTTP server was stopped immediately after the check. No host
  port was left listening for this probe.

## Boundary

This helper is a reversible development-network aid. It does not provide
`ProductionAdbTransport`, OS-held key custody, a Codex turn, an authenticated
Root-Linux activation receipt, or production release evidence. The relay remains
needed while probes run; stop it and revoke the Android VPN permission when the
network phase is complete.
