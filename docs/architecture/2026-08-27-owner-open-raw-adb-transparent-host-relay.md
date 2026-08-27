# ADR: owner-open raw ADB through a transparent independent-host relay

Date: 2026-08-27  
Status: **ACCEPTED FOR P0 OWNER-OPEN IMPLEMENTATION**  
Plan: `TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md` W4  
Semantic contract: `codex-sovereign-direct-tools-v1.json`

## 1. Decision

The P0 owner-open product uses an ordinary platform-tools `adb` client/server
owned by an independent owner-controlled host supervisor. The Direct Agent Host
or Root Linux connects to a mechanism-only relay and sends exact ADB argv. The
relay executes the ordinary client against the configured server and returns
byte-preserving stdout, stderr, exit and transport observations.

The relay is not an ADB semantic wrapper. It does not parse subcommands to make
an authorization decision, inject a serial, choose a device, add host/port
arguments, downgrade privilege, require an approval lease or rename backend
errors.

A real ARM64 adb client/server inside Root Linux remains an optional later
transport for TCP/recovery/external-device use. It is not a prerequisite for
P0 and does not replace this decision unless a new ADR records a measured,
operationally better topology.

## 2. Why this topology

The Android-managed Root Linux environment normally runs on the same physical
phone as Android. Making that environment control the same phone through its
own USB gadget path is not a sound default topology: the phone is not an
independent USB host for itself, and pretending otherwise would introduce a
special self-ADB shim that is neither ordinary platform-tools behavior nor a
transparent transport.

The project already distinguishes three execution surfaces:

- host Linux;
- Android-managed Root Linux;
- one or more Android/recovery targets.

An independent host naturally owns the USB connection and ordinary adb server.
It can also remain alive while the phone reboots, which makes reboot and
recovery observations more truthful. Root Linux local control remains available
through direct shell, System API and Accessibility; ADB remains the ordinary
multi-target Android transport rather than a fake local privilege bridge.

## 3. Runtime graph

```text
Codex turn / Direct Agent Host
  -> adb.exec raw argv
  -> owner-open relay client
  -> authenticated local transport to independent host supervisor
  -> ordinary platform-tools adb client
  -> ordinary adb server and configured USB/TCP targets
  -> raw stdout/stderr/exit/transport observations
  -> same Codex turn
```

The relay client and server may use a Unix-domain socket, inherited stdio or an
explicit owner-configured mutually authenticated network channel. TCP/HTTP
exposure is never the default and must be recorded in the active owner-open
configuration and evidence.

## 4. Exact request semantics

The `adb.exec` request supplies `argv` excluding the program name. The relay
must pass those elements to the configured ordinary adb executable without
insertion, deletion, splitting, quoting reinterpretation or reordering.

Examples:

```json
{"tool":"adb.exec","argv":["devices","-l"]}
```

```json
{"tool":"adb.exec","argv":["-s","ZY32JLVHGN","shell","id"]}
```

```json
{"tool":"adb.exec","argv":["future-subcommand","--future-flag"]}
```

An empty argv is transport-valid and lets the selected ordinary adb executable
produce its normal help/error result. Unknown and future subcommands remain
valid.

The request may carry `target_id` as correlation/routing metadata. The relay
must not convert that metadata into an injected `-s` argument. Codex explicitly
places `-s`, `-H`, `-P`, `-L` or other ordinary adb options in argv when it wants
them. When argv does not select a device, ordinary adb behavior applies,
including the real multiple-device error.

## 5. Configuration

Owner-open configuration records, at minimum:

- relay endpoint and transport;
- host supervisor identity/admission method;
- adb executable path and observed version;
- adb server socket/environment configuration;
- credential/key home and explicit inherited credential FDs;
- output, process and connection ceilings;
- event/spool paths;
- configured target aliases as informational records;
- whether the supervisor is expected to survive phone reboot.

The relay does not merge an unrelated operator adb profile silently. Explicit
environment overrides are recorded as the active config generation.

## 6. Identity and admission

The independent host supervisor is owner-controlled. Local Unix socket mode and
peer credentials are the default admission mechanism. A network bridge requires
explicit mutual authentication and an exposure record.

Admission answers “which local owner-open peer may use this powerful transport.”
It does not answer “is this adb command semantically safe.”

ADB private keys and pairing state remain host configuration. Their bytes are
not inserted into model text or normal event payloads. Named credential FDs are
`CLOEXEC` unless the ordinary adb process explicitly requires inheritance.

## 7. Process and byte mechanics

For each normalized call, the host supervisor:

1. validates framing, argv representation and mechanical limits;
2. binds the call id, exact request bytes and active config generation;
3. attempts the accepted record;
4. spawns the exact configured adb executable with exact argv;
5. attempts the started record with PID/process-group and binding fingerprint;
6. drains stdout/stderr independently as raw bytes;
7. reports exit, signal, timeout, client cancel, I/O or uncertain transport
   state;
8. attempts exactly one terminal record.

The relay never parses stderr into an Authority decision. UI presentation may
recognize text for display, but stored raw bytes remain authoritative.

## 8. Disconnect, reboot and uncertainty

The independent host can outlive a phone reboot, but that does not make every
ADB operation exactly-once.

- If the local adb process exits and all output/exit status are observed, return
  that terminal result.
- If USB or server transport drops before the effect state is known, return the
  actual adb result when available and otherwise
  `unknown_after_disconnect` with inspectable local process/transport facts.
- Never re-run the argv automatically because the target reappeared.
- A reconnect or retry uses Codex/owner judgment and a new call id unless it is
  attaching to an identical still-live call.
- Phone reboot may interrupt the old Root Linux turn. An independent Host may
  keep the client stream alive only when its turn/provider lifecycle is also
  independent and the evidence records that topology.

## 9. Same-phone local control

This ADR does not use ADB as a hidden local privilege escalation path for the
same phone. Local Android effects use the owner-open direct shell target,
System API or Accessibility as selected by Codex. ADB is used when ordinary adb
transport is the requested mechanism, including external Android devices,
recovery/bootloader targets and host-driven build/install/reboot workflows.

## 10. Failure behavior

The following remain raw backend observations, not semantic HOLD/denied states:

- no devices/emulators found;
- more than one device/emulator;
- unauthorized or offline target;
- server version mismatch or restart;
- adbd root/remount rejection;
- install/push/pull failure;
- recovery/bootloader transport loss;
- unknown subcommand or option;
- missing executable or configuration error.

The Host may add a stable mechanical class such as `transport_unavailable`,
`timed_out`, `client_cancelled`, `io_error` or
`unknown_after_disconnect`, while preserving all raw bytes and exit facts.

## 11. Security consequences

This topology gives an admitted owner-open peer the same broad power as the
configured adb client/key/server. Required mitigations are:

- local-only endpoint by default;
- exact peer/socket admission;
- process-group and descendant cleanup;
- finite frame/output/process/spool bounds;
- explicit credential handling;
- no shell interpolation of argv;
- raw-byte-safe event transport and UI escaping;
- call-id conflict detection and conservative restart reconciliation;
- independent owner emergency stop and adb key revocation.

A sealed/public profile may add policy before the same relay primitive, but it
must be an explicit profile and cannot become an owner-open prerequisite.

## 12. Implementation surfaces

Expected new isolated surfaces:

```text
crates/trillionnium-owner-open-adb-relay-protocol/
apps/trillionnium-owner-open-adb-relay/
apps/trillionnium-owner-open-host/src/adb_backend.rs
apps/trillionnium-owner-open-host/src/adb_reconcile.rs
```

The owner-open path must not import or invoke the current typed
`trillionnium-agent-direct-tools::adb::AdbRequest` product adapter. That adapter
remains migration/history material until removed.

## 13. Required tests

Host tests:

- exact argv including empty and unknown subcommands;
- no serial/host/port/privilege injection;
- fake adb executable records exact `argv` and environment;
- raw binary stdout/stderr and large output;
- multiple-device, unauthorized, offline and root-remount text preserved;
- timeout/cancel/process-exit races;
- relay disconnect and server restart;
- identical call attach and conflicting call rejection;
- no automatic redispatch after uncertain transport loss.

Physical tests:

- `adb devices -l`;
- explicit `-s <serial> shell id`;
- push/pull/install;
- forward/reverse;
- unauthorized/offline and server restart;
- root/remount/reboot real result;
- USB unplug and phone reboot recovery/uncertainty;
- recovery/bootloader target when owner configured.

## 14. Acceptance

This ADR is implemented when one Codex turn sends exact raw argv through the
relay, receives byte-preserving observations from an ordinary adb client/server,
and the L4/L5 evidence proves normal and disconnect/reboot behavior without
injected routing or blind retry.

Until then, W4 remains `SPEC_ONLY`; accepting this ADR is not a runtime or device
capability claim.
