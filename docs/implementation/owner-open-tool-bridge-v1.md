# Owner-open tool bridge v1

Status: **r4 W1/W2 source implementation; standalone validation pending**  
Date: **2026-08-27**  
Source: `crates/trillionnium-owner-open-tool-bridge`

## 1. Purpose

The bridge makes one narrow transition executable:

```text
one validated owner-open tool request
  -> one turn-scoped registry call
  -> at most one local process spawn
  -> raw process events
  -> one terminal registry observation
```

It is not a Host connection protocol, provider adapter, persistent journal or
semantic policy component.

## 2. Inputs

`BoundToolCall` contains:

- exact `CallKey` scope;
- binding fingerprint;
- correlation-only target label;
- codec-authored canonical request bytes;
- bridge-computed request SHA-256;
- typed direct runtime request (`Shell` or `Adb`).

The optional claimed digest constructor re-computes and compares the digest
before registry admission.

### Codec obligation

The production Host codec must produce canonical bytes and the typed request
from the same strict parse. The bridge intentionally does not re-parse JSON.
This avoids two protocol implementations, but it means the Host integration
must prevent a caller from independently supplying mismatched canonical bytes
and process fields.

## 3. Dispatch sequence

1. Validate bridge limits, request digest and binding fingerprint.
2. `registry.begin` with exact request facts.
3. `registry.claim_spawn`.
4. Return Existing/Inhibited without process creation when applicable.
5. For Granted, create one runtime cancellation token.
6. Start a bounded cancellation monitor from the registry's shared signal.
7. Execute shell or ordinary adb through the direct process runtime.
8. On Started, record the exact spawn generation and PID.
9. Hash and forward each raw runtime event in order.
10. Convert the exact process terminal and observation digest into a registry
    terminal.
11. Return execution result only after registry completion.

## 4. Observation digest

The local digest uses a length-prefixed binary preimage containing:

- schema label;
- call ID;
- tool label;
- target label;
- spawn generation;
- event ordinal;
- accepted/start PID/output stream/output bytes/terminal fields;
- local bridge/runtime error text when a process terminal is unavailable.

This digest is local correlation evidence. It is not the final wire/JCS digest
and does not replace raw output event storage.

## 5. Failure ordering

### Cancellation monitor creation failure

No process is started. The bridge records a `bridge_failure` terminal under the
claimed generation, then returns the local error.

### Runtime request rejection

The bridge adds a local-error event to the digest, records a
`runtime_rejected` terminal, joins the monitor and returns the runtime error.
The call never remains indefinitely Started.

### Event sink panic

The panic is caught at the boundary, the runtime cancellation token is set, the
process is allowed to reach a real terminal, and that terminal is recorded
before `EventSinkPanicked` is returned.

### PID registry failure

The process continues to terminal so the local observation is not discarded.
After terminal completion the bridge returns `RegistryObservation` for the PID
conflict. The terminal remains inspectable.

### Monitor panic

The runtime terminal is recorded first; then the bridge returns
`CancellationMonitorPanicked`.

## 6. Duplicate behavior

An exact duplicate request may observe Started or Terminal and returns
`Existing`; the bridge never creates a second process. It does not yet replay
raw output bytes because the registry stores state/history, not output payloads.
W2.3/W5 must attach a spool/event store before the Host promises full replay.

A conflicting request under the same scoped call ID fails at `begin` before a
new spawn claim.

## 7. Cancellation behavior

Registry cancellation is polled at a bounded interval and mapped into the
runtime's process-group cancellation token.

- before spawn: registry inhibits the call, so no monitor/process is created;
- after spawn: the monitor sets the runtime token;
- the runtime emits the real Cancelled/TimedOut/other terminal;
- remote ADB effect state remains a higher transport/Host uncertainty decision.

The polling monitor is a temporary source implementation. A later reviewed
runtime API may accept a shared cancellation trait directly, eliminating one
thread per active call without changing semantics.

## 8. ADB boundary

The bridge selects the `adb.exec` runtime only from the typed direct tool
variant. It does not inspect subcommands or target labels and never injects:

- `-s`;
- host/server/port;
- transport ID;
- root/remount privilege;
- known-action enum;
- semantic HOLD/approval result.

The configured ordinary adb executable and exact argv are owned by the typed
runtime request produced by the Host codec/config layer.

## 9. Source tests and promotion

Standalone tests must run under Rust 1.93 and prove:

- one real shell process for concurrent duplicate calls;
- exact request conflict and claimed-digest rejection;
- shared cancel to process-group terminal;
- raw unknown adb argv and no target injection;
- spawn failure terminal closure;
- ordered event hashing and registry terminal binding.

Only after these pass may the package be imported into the outer Host graph.
Host integration must then replace arbitrary test canonical bytes with output
from `trillionnium-owner-open-types` strict codecs and bind event emission to
the same turn stream.

## 10. Current claim

> A source bridge from exact call claim to direct local shell/ADB execution has
> been authored with duplicate/cancel/failure tests. It has not been compiled by
> an observed runner or connected to the live owner-open Host/provider.
