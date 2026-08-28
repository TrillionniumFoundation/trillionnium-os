# Owner-open ADB smart-socket relay v1

Status: **R5 source foundation; physical Android/USB evidence pending**

## 1. Selected topology

The owner-open physical ADB path uses an ordinary adb client and a
byte-transparent ADB server smart-socket relay:

```text
Codex same-turn adb.exec
  -> configured ordinary adb executable
  -> ADB_SERVER_SOCKET=tcp:127.0.0.1:<local-relay-port>
  -> owner_open_adb_relay.py
  -> configured loopback upstream port
  -> owner-host adb server through the selected reverse/forward topology
  -> physical Android target
```

The relay is transport-only. It does not parse the ADB length prefix, service
string, transport selection or command payload.

## 2. Non-negotiable transparency

The relay never:

```text
injects -s or a serial
injects host or port arguments
chooses a transport
rewrites host:transport-* services
filters unknown services
interprets shell/install/push/pull/reboot
adds privilege commands
retries an uncertain ADB operation
logs payload bytes
```

Unknown current or future adb services remain valid byte sequences.

## 3. Listener boundary

The foundation relay binds only a numeric loopback address. Non-loopback
listener or upstream addresses are rejected. This prevents the source utility
from accidentally exposing an unauthenticated ADB smart socket to a network.

Production Root Linux placement must additionally restrict the listener through
namespace, UID/GID and Android/Root Linux lifecycle policy. Loopback binding by
itself is not a multi-tenant security boundary.

## 4. Ordinary adb configuration

The configured adb client receives the owner/Codex argv unchanged. The only
transport configuration is the explicit process environment selected by the
owner profile, for example:

```text
ADB_SERVER_SOCKET=tcp:127.0.0.1:5038
```

The direct executor and relay do not silently choose a device serial. With
multiple devices and no explicit adb argv selection, ordinary adb behavior is
preserved.

## 5. Byte and half-close behavior

Each accepted TCP connection creates one upstream TCP connection. The relay
uses bounded nonblocking buffers in both directions and preserves byte order.

Client EOF is propagated as an upstream write half-close only after all queued
client bytes are written. Upstream EOF is propagated to the client in the same
way. The connection terminates after both read directions close and both
buffers drain, or after a finite error/idle/shutdown condition.

## 6. Bounds

Configured finite limits include:

```text
maximum simultaneous clients
buffer bytes per direction
upstream connect timeout
connection idle timeout
worker shutdown grace
```

Buffer exhaustion closes only the affected transport connection and records a
mechanical `resource_exhausted` observation. It does not infer whether a prior
ADB request was accepted and does not dispatch a replacement.

## 7. Descriptor and observations

The relay can write a private descriptor with schema:

```text
org.trillionnium.owner-open.adb-smart-socket-relay.v1
```

It records the selected loopback endpoints, the `ADB_SERVER_SOCKET` value,
mechanical bounds and explicit facts:

```text
byte_transparent = true
adb_protocol_parsed = false
argv_or_serial_injected = false
payload_logged = false
automatic_redispatch = false
```

The optional event log records lifecycle, connection IDs, byte counts,
terminal reason and elapsed time. It never records payload bytes, service
strings, shell commands or file contents.

## 8. Failure truth

A relay disconnect can mean many things:

```text
request not written
request partly written
ADB server accepted request
transport changed after acceptance
target rebooted
USB disappeared
server closed the connection
```

The relay reports transport facts only. The caller must use ordinary adb
inspection and higher-level effect evidence. It must not automatically repeat a
possibly accepted install, push, shell mutation or reboot.

## 9. Physical qualification

L4 qualification must bind:

- exact adb executable SHA-256 and version;
- exact relay source/binary and configuration;
- exact upstream reverse/forward command and host adb server identity;
- `adb devices -l` and authorization state;
- no-serial behavior with zero, one and multiple targets;
- unknown service/subcommand transparency;
- binary output preservation;
- shell, push, pull, install and reboot observations;
- offline, unauthorized, USB loss and server restart;
- same Codex turn continuation after adb success and failure;
- no automatic redispatch after uncertain disconnect.

## 10. Evidence boundary

Loopback echo fixtures can prove byte preservation, concurrency, finite bounds,
half-close behavior and absence of payload logging. They do not prove:

- a real adb server handshake;
- USB or target authorization;
- Android image integration;
- physical device effect;
- reboot/power-loss conformance;
- public release.

Until physical evidence exists, W4 remains `SOURCE_IMPLEMENTED / L0`.
