# R5 Batch E checkpoint — physical ADB topology

Status: **byte-transparent relay and exact-argv qualification source authored; physical evidence open**

## Source slice

```text
Codex same-turn adb.exec
  -> ordinary measured adb executable
  -> explicit ADB_SERVER_SOCKET
  -> bounded loopback smart-socket relay
  -> selected owner-host reverse/forward endpoint
  -> physical Android target
```

Implemented source properties:

1. relay binds only loopback endpoints;
2. relay preserves arbitrary bytes and half-close order;
3. relay never parses ADB service strings or command semantics;
4. no serial, host, port or privilege argv is injected;
5. concurrent connections and per-direction buffers are finite;
6. event records contain byte counts but no payload;
7. owner-authored qualification plan passes each argv exactly once;
8. inherited `ANDROID_SERIAL` is removed;
9. timeout or uncertain relay loss never triggers automatic redispatch;
10. report binds adb/Python/relay measurements and binary output digests.

## Gate E1 — exact source runner

Required on one exact commit:

```text
python compileall for relay, qualifier and tests
owner-open ADB relay process fixtures
owner-open ADB qualification fake-adb fixtures
R5 graph/verifier closure
Rust owner-open closure
```

No L4 promotion is allowed from fake upstream or fake adb fixtures.

## Gate E2 — target topology selection

Bind one concrete topology in evidence:

```text
Root Linux local relay listener
Android/Root Linux network namespace placement
owner-host reverse or forward mapping
host adb server address and version
ADB key and authorization custody
physical USB transport
```

The selected topology must not rely on a wrapper silently injecting a serial or
rewriting adb argv.

## Gate E3 — physical ordinary-adb behavior

The owner-authored plan must prove:

- zero, one and multiple target behavior without implicit serial selection;
- authorized, unauthorized and offline target observations;
- unknown subcommand/service transparency;
- shell success and failure observations;
- binary push/pull round-trip;
- install/update result;
- server restart and USB disconnect;
- reboot/recovery transition where safe;
- no repeat of an operation whose acceptance became uncertain.

## Gate E4 — same Codex turn

A real installed Codex turn must call the ordinary `adb.exec` tool, receive raw
stdout/stderr/exit observations, continue reasoning in the same turn, and
produce the final result without a second semantic planner.

## Gate E5 — Android product integration

After host-process qualification:

1. include relay/Host artifacts in the clean owner-open product profile;
2. define init lifecycle and restart policy;
3. define SELinux and namespace admission;
4. expose only the selected local endpoint to Root Linux;
5. add AiShell status/inspect controls without ADB semantic filtering;
6. build target-files and prove forbidden legacy packages are absent.

## Holds

The following remain false until evidence exists:

```text
real adb server handshake proven
physical USB target observed
same-turn physical ADB effect proven
Android image included
reboot/power-loss qualified
public release allowed
```
