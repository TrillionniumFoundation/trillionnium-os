# Owner-open call registry v1

Status: **r4 W1/W2 source implementation; standalone validation pending**  
Date: **2026-08-27**  
Source: `crates/trillionnium-owner-open-call-registry`  
Plan: `docs/plan/owner-open-r4-w2-w3-execution-amendment.md`

## 1. Purpose

The owner-open Host needs one atomic place to answer four questions without
adding a semantic policy plane:

1. Has this exact call already been accepted?
2. Has any thread/process already been granted the right to spawn it?
3. Is cancellation or connection loss known before/after dispatch?
4. Is the terminal result exact, replayable in memory, conflicting or still
   uncertain?

The registry is a process-local mechanism state machine. It does not decide
whether a command is safe, supported or authorized, and it never retries a
call.

## 2. Identity and scope

The key is:

```text
(session_id,
 profile_id,
 task_id,
 turn_id,
 turn_stream_id,
 call_id)
```

The bound request facts are:

```text
request_sha256
binding_fingerprint
tool
target_id
```

`request_sha256` binds the exact requested call bytes according to the owner-open
protocol. `binding_fingerprint` binds the resolved executable/endpoint,
transport, execution identity and configuration generation. Neither value is a
semantic allowlist.

A repeated scoped call ID is legal only when all bound request facts are
identical. A conflicting repeat is `CallIdConflict` before a new spawn can be
claimed.

The same `call_id` in another turn scope is independent.

## 3. State machine

```text
begin exact-new
  -> Accepted

Accepted + cancel
  -> CancelledBeforeSpawn (spawn permanently inhibited)

Accepted + connection lost
  -> ProvenNotStartedAfterDisconnect (spawn permanently inhibited)

Accepted + claim_spawn
  -> Started(generation, pid=None)

Started + record_pid
  -> Started(generation, pid=Some(pid))

Started + connection lost
  -> UnknownAfterDisconnect(generation, pid?)

Unknown + connection attached
  -> Started(generation, pid?)

Started/Unknown + exact terminal
  -> Terminal(generation, terminal)
```

Terminal remains terminal after connection attach/loss. An exact duplicate
terminal is idempotent; a different generation or observation is a conflict.

## 4. Begin and duplicate behavior

### Exact duplicate

`begin(key, request)` returns `Existing` and the current snapshot. It does not
append a second accepted event and does not allocate a spawn generation.

### Conflicting duplicate

Any difference in request digest, binding fingerprint, tool or target returns
`CallIdConflict`. The existing entry remains unchanged.

### Capacity

Capacity exhaustion is a mechanical liveness error. The Host must return it as
`resource_exhausted`/registry-unavailable observation; it must not reinterpret it
as command denial. Only explicit terminal cleanup frees a slot.

## 5. Spawn claim

`claim_spawn` is the sole transition that allocates a monotonic, non-zero process
spawn generation.

Under concurrent calls:

- exactly one caller receives `Granted`;
- all others receive `Existing` with the already started/terminal snapshot;
- a cancelled/disconnected pre-spawn call receives `Inhibited`;
- a mismatched request digest is rejected;
- no caller is authorized to spawn merely because `begin` returned `New`.

The embedding Host must perform process spawn only after `Granted` and must bind
the generation into every PID/output/terminal record.

## 6. Cancellation

The registry exposes one shared atomic `CancellationSignal` per call.

- before spawn: cancellation records one event, inhibits spawn and exposes
  `CancelledBeforeSpawn`;
- after spawn: it marks the signal while the effective state remains Started or
  Unknown until the runtime reports a terminal observation;
- repeated cancellation is idempotent and does not create repeated events;
- cancellation is a request to stop the local process/transport; it is not
  proof that a remote effect did not occur.

A future Host adapter must bridge this signal to the owner-open runtime
cancellation token without polling a second unrelated flag.

## 7. Connection loss and uncertainty

### Before spawn

Because the registry still holds `Accepted` and no generation exists, marking
the connection lost positively proves no process spawn was granted. The call is
permanently inhibited and reported as `ProvenNotStartedAfterDisconnect`.

Reattaching the connection does not reopen the same call ID for spawn. A later
retry is a new call ID.

### After spawn

A started call becomes `UnknownAfterDisconnect`. The registry does not kill,
retry or infer the effect. Reattachment may expose Started again if the process
is still locally tracked; a late terminal may close the call even while the
connection remains lost.

For a remote ADB relay, a process terminal alone may still map to
`unknown_after_disconnect` when transport evidence cannot establish remote
effect state. That mapping belongs in the Host/transport adapter, not this local
registry.

## 8. PID and terminal bindings

### PID

- PID zero is invalid;
- the expected spawn generation is mandatory;
- first exact PID is recorded;
- repeated exact PID is idempotent;
- another PID for the same generation is conflict;
- another generation is conflict.

PID is diagnostic lifecycle evidence, not a stable principal or authorization
identity.

### Terminal

A terminal record carries:

```text
terminal_kind
exit_code OR signal
observation_sha256
stdout_bytes
stderr_bytes
```

It is valid only after spawn claim. The record is generation-bound. Exact
repetition is idempotent; any differing terminal is conflict. The registry does
not parse or hash raw output itself; the Host/process adapter supplies the
canonical observation digest.

## 9. Event history

Each call has a bounded in-memory event ring:

- accepted;
- spawn claimed;
- PID observed;
- cancel requested;
- connection lost/attached;
- terminal recorded.

Sequence numbers are monotonic and never reused. When history is truncated, the
snapshot reports `earliest_history_seq`. `history_from(cursor)` returns the
inclusive available suffix; absence of earlier events is explicit and must not
be presented as durable replay.

This history is diagnostic L1/L2 state. W5 requires a separate durable store
with accepted/started/terminal publication and restart reconciliation.

## 10. Concurrency properties

The implementation serializes registry transitions through one mutex and shares
cancellation through atomics. Authored tests cover:

- 32 concurrent exact begins: one New, 31 Existing;
- 32 concurrent spawn claims: one Granted, 31 Existing;
- two conflicting requests: one accepted, one conflict;
- independent scopes with identical call label;
- generation/PID/terminal binding;
- pre/post-spawn cancellation;
- disconnect unknown and late terminal;
- capacity and explicit cleanup;
- bounded history cursor.

A Rust 1.93 runner must execute these tests before any concurrency claim is
promoted.

## 11. Host integration contract

The Host adapter sequence is:

```text
parse + canonical request digest
resolve target/config + binding fingerprint
registry.begin
registry.claim_spawn
runtime spawn callback -> registry.record_pid
runtime output -> Host event stream/spool
runtime terminal -> canonical observation digest -> registry.complete
provider response -> same turn
```

On client disconnect the Host marks every active correlated call lost before it
drops the connection state. On reconnect it attaches only to exact existing
scope/call identities; it never creates a second process for an existing
started/terminal call.

The first integration must use the Rust owner-open runtime directly, not the old
`shell.exec.v1` broker or typed ADB adapter.

## 12. Durability boundary

The current registry is process-local and cannot prove behavior after Host
restart. Until W5 is integrated:

- a Host crash after possible dispatch is `unknown_after_disconnect`;
- memory absence after restart is not proof of not-started;
- no automatic redispatch is allowed;
- in-memory terminal replay is valid only inside the current Host generation;
- source/host tests must not claim restart durability.

## 13. Claim boundary

Current accurate claim:

> An isolated in-memory state machine for exact-call binding, one spawn claim,
> cancellation and disconnect uncertainty has been authored with unit and
> concurrency tests. It has not been compiled by an observed runner or imported
> by the owner-open Host/runtime.
