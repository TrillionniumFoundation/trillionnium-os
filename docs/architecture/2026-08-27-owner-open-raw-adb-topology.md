# ADR: owner-open raw ADB topology

Date: **2026-08-27**  
Status: **ACCEPTED FOR W3 DOGFOOD IMPLEMENTATION**  
Scope: owner-authorized userdebug dogfood, not public release

## Context

The r3 contract requires ordinary raw ADB argv as a first-class Codex tool. The
existing `trillionnium-agent-adb` implementation is a typed fail-closed adapter
whose product entry returns `BackendUnavailable`; it is not platform-tools adb
and must not be extended into the owner-open path.

The integrated Root Linux environment runs on the Android device. A normal adb
client expects to speak the adb server protocol, while the server owns USB/TCP
transport and authentication keys. Running a second full server inside the
phone adds USB gadget/transport complexity before the first useful dogfood
loop. The owner already has an authorized external Linux host, a USB-connected
userdebug device and a demonstrated USB reverse path.

## Decision

### W3-A dogfood topology

Use an **ordinary Linux ARM64 adb client inside Root Linux**. Connect that client
to the owner-controlled external Linux host's ordinary adb server through a
loopback-only device endpoint carried by USB reverse.

```text
Codex turn in Android-managed Root Linux
  -> adb client (ordinary platform-tools protocol, exact argv)
  -> ADB_SERVER_SOCKET=tcp:127.0.0.1:<device-loopback-port>
  -> adb reverse / owner-controlled USB tunnel
  -> owner host 127.0.0.1:<host-adb-server-port>
  -> ordinary owner-host adb server
  -> USB transport
  -> target adbd on ZY32JLVHGN (or another explicitly selected target)
```

The default port may be 5037 only when the reverse/tunnel arrangement can prove
there is no collision with another device-local service. Port selection is
owner configuration and is recorded in the effective configuration generation.
It is not an ADB command admission field.

### Process boundary

`trillionnium-owner-open-runtime::execute_adb` receives:

- configured adb executable path;
- exact argv excluding the program name;
- inherited environment delta containing the selected `ADB_SERVER_SOCKET` when
  needed;
- optional cwd/stdin/timeout;
- correlation-only target label.

The process wrapper never:

- inserts `-s` or chooses a serial;
- parses known subcommands;
- blocks unknown/future subcommands;
- inserts a host, port, transport ID, root/remount mode or privilege downgrade;
- maps real adb stderr to `operation_denied` or `HOLD`;
- silently starts a different server endpoint.

Codex or owner configuration supplies routing arguments. Ordinary adb behavior
handles zero, one or multiple attached devices.

## Why this topology

1. It reaches a real device effect with the smallest new trusted code surface.
2. The ordinary host adb server already owns USB and authentication mechanics.
3. Root Linux receives the real adb client protocol and raw result rather than
   a typed RPC subset.
4. `adb devices -l`, `adb -s ... shell`, install, push, pull, root, remount,
   reboot, forward, reverse, logcat, bugreport and future commands remain usable.
5. The phone image does not need an experimental USB host stack or a second key
   authority before owner-open dogfood is useful.
6. The topology can later be replaced by a byte-transparent on-device relay
   without changing the `adb.exec` request/observation ABI.

## ARM64 adb client supply

The Root Linux payload must contain a real Linux ARM64 adb client built or
packaged from a recorded source. Acceptable sources are:

- a reproducible AOSP platform-tools adb Linux ARM64 build; or
- a distribution package whose source, version, license, architecture and hash
  are recorded in the Root Linux BOM.

Acceptance requires:

```sh
file /usr/bin/adb
/usr/bin/adb version
sha256sum /usr/bin/adb
```

The checked-in typed `trillionnium-agent-adb` ELF is explicitly not acceptable
as this artifact.

The client version is a runtime/BOM fact. It must not be inferred from a source
module name or hard-coded as an Agent identity.

## Server endpoint and exposure

The development default is:

- device endpoint bound only to loopback;
- owner host endpoint bound only to loopback;
- tunnel lifetime controlled out of band by the owner bootstrap/recovery lane;
- no LAN/WAN listener;
- endpoint and tunnel generation recorded per turn/call;
- endpoint loss returned as a real connection observation.

The adb server protocol is not assumed to provide confidentiality or peer
identity on an exposed network. Any TCP/HTTP/LAN bridge requires a separate
explicit security decision and is outside this ADR.

## Key custody

For W3-A, adb authentication keys remain with the owner-host ordinary adb
server. The Root Linux client talks to that server and does not mint a second OS
semantic authority or receive a model-visible private key.

Key rotation, host replacement and device authorization are owner operations.
The wrapper reports `unauthorized`, missing keys and server errors exactly as
ordinary adb produces them.

A later standalone on-device server would require a separate key-custody ADR.
It is not implied by this decision.

## Target and serial semantics

`target_id` in the owner-open protocol is a routing/correlation hint. It is not
translated automatically to `adb -s`.

Examples:

```text
adb.exec(["devices", "-l"])
adb.exec(["-s", "ZY32JLVHGN", "shell", "id"])
shell.exec("adb -s ZY32JLVHGN logcat -d")
```

When no serial is supplied, ordinary adb selects or rejects according to its
own server state. A multiple-device error must not be hidden by wrapper target
selection.

## Lifecycle and failure semantics

### Before process spawn

Malformed local frame/argv is `invalid_frame`; no accepted/spawn record exists.

### Client spawn failure

Missing/non-executable ARM64 adb is `spawn_failed` with no `started` event.

### Server unavailable

The real adb client connection error, stderr and exit code are returned. The
substrate does not rename it as authorization failure.

### Target offline or unauthorized

The ordinary adb observation is returned unchanged. Codex decides whether to
wait, reauthorize, select a target or stop.

### USB/tunnel disconnect

- If the client process returns a terminal result, return it.
- If the Host can prove no request was sent, it may report `not_started`.
- If dispatch may have reached the server or target and no terminal result is
  available, record `unknown_after_disconnect`.
- Never automatically re-run the same mutating adb call.
- A retry uses a new `call_id` after Codex inspects target state.

### Phone reboot

Root Linux and the client die with the phone. The old turn is interrupted. USB
reverse/tunnel state is re-established out of band, then a new resumable turn
inspects the previous call. A new process is not proof that the previous remote
effect did not occur.

### Host adb server restart

The call returns the real client/server error or becomes unknown according to
recorded dispatch state. Server restart never authorizes automatic redispatch.

## Bootstrap sequence

The owner-host bootstrap lane will:

1. verify the exact target serial and build fingerprint;
2. verify/start the ordinary host adb server;
3. verify the host server listens only on the intended endpoint;
4. install/re-establish the USB reverse or equivalent local tunnel;
5. from Android/Root Linux, probe TCP reachability only;
6. run `/usr/bin/adb devices -l` through the configured server socket;
7. run `/usr/bin/adb -s ZY32JLVHGN shell id`;
8. record raw stdout/stderr/exit, client/server versions and endpoint binding;
9. remove or retain the tunnel according to owner recovery policy.

Bootstrap observations are not integrated Host evidence until the same Codex
turn invokes `adb.exec` and receives the events.

## W3 acceptance ladder

### L1 source

- exact-argv process wrapper;
- fake adb executable proves unknown argv and no injection;
- this ADR and machine status exist.

### L2 host integration

- ordinary adb client talks to an ordinary server in a disposable host test;
- multiple-device, offline, unauthorized and unknown-subcommand observations
  remain raw;
- cancellation/timeout closes only the requested client process group.

### L3 image

- exact Linux ARM64 adb artifact is in Root Linux BOM;
- executable path/version/hash match config and target-files/rootfs payload;
- no typed adapter is substituted;
- Android owner-open product graph contains no old ADB gate as prerequisite.

### L4 physical device

One live Codex turn executes at least:

```text
adb devices -l
adb -s ZY32JLVHGN shell id
adb -s ZY32JLVHGN shell 'echo owner-open > /data/local/tmp/tos-probe'
adb -s ZY32JLVHGN shell cat /data/local/tmp/tos-probe
```

The exact command/result stream returns to the same turn.

### L5 fault

Capture at least:

- unauthorized target;
- offline target;
- USB unplug before dispatch;
- USB unplug after dispatch before response;
- adb server restart;
- phone reboot;
- tunnel loss;
- Host crash;
- output exhaustion and cancellation.

No ambiguous mutating call may be silently duplicated.

## W3-B follow-on

A later integrated topology may replace the external host dependency with:

- an ordinary adb server inside Root Linux with a supported transport; or
- a byte-transparent Android-owned relay to an existing transport.

It must preserve the same raw argv/result ABI and mechanism-only boundary. It
requires a new ADR covering keys, transport identity, boot ordering, SELinux,
recovery and exposure. W3-B is not a prerequisite for owner-host dogfood.

## Consequences

Positive:

- shortest path to real raw ADB;
- no typed command catalog;
- no second semantic authority;
- existing owner-host USB/key mechanics are reused;
- future topology replacement does not change the Agent-facing ABI.

Costs:

- W3-A depends on an owner-controlled external host and tunnel;
- phone reboot breaks the integrated process and tunnel;
- host server state participates in the binding fingerprint and evidence;
- public release needs a different security and availability posture.

## Explicit non-claims

This ADR selects a topology. It does not prove that:

- a Linux ARM64 adb client is currently packaged;
- the USB reverse/server endpoint is currently established;
- the new runtime crate compiles or has passed its authored tests;
- the owner-open Host invokes it;
- a live Codex turn has executed a physical ADB effect;
- this topology is suitable for multi-user/public release.
