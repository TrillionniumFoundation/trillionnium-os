# Owner-open multi-connection broker v1

Status: **ACTIVE TARGET CONTRACT — baseline fixtures L1; exact correlation/audit/startup gap #18 remains open**  
Plan revision: `2026-08-29-r6`  
Unified state machine: `owner-open-effect-state-machine-v1.md`  
Tracking gap: `R5-GAP-BROKER-CORRELATION-001` / Issue #18

## 1. Purpose and boundary

The broker lets multiple local owner clients share one selected owner-open Host
process without becoming a second semantic principal.

```text
AiShell / Codex MCP / owner diagnostics
  -> local Unix socket
  -> owner-open connection broker
  -> bounded transport carrier
  -> job-aware execution core
```

The broker owns only:

```text
local admission
connection and request identity
finite request scheduling
accepted/forwarded/terminal audit
owner-scoped direct results
bounded observation broadcast
disconnect and lifecycle truth
```

It never classifies a command, assigns risk, asks for semantic approval,
rewrites argv, chooses a target/provider or automatically retries an uncertain
effect.

## 2. Trust domain and admission

The foundation carrier uses a filesystem Unix socket. An admitted peer must
satisfy:

1. `SO_PEERCRED` UID equals the configured service/owner UID;
2. the first strict JSON frame carries the current 32-byte random token;
3. the client binds a unique `client_id` for the current broker epoch;
4. the descriptor/token epoch is current and digest-bound.

The socket parent is stable and owner-controlled. Token and descriptor files
are private regular non-symlink files with exact owner/mode/link constraints.
Duplicate JSON members, oversized/unterminated records and unsafe paths fail
before admission.

Same UID plus a readable token is one local trust domain. It is not strong
isolation from a process that has already compromised the same service UID.
Android product admission therefore requires explicit SELinux client/server
domains and socket policy.

## 3. Broker epoch and descriptor

Every broker process creates a random `broker_epoch`. The descriptor binds:

```text
schema
broker_id
broker_epoch
socket carrier and path/name
token epoch and token-file identity
service UID/GID
selected upstream executable identity
exact upstream argv digest
protocol and response model
mechanical bounds
audit-store identity
creation time
no-automatic-redispatch policy
descriptor_sha256
```

Clients reject stale epochs, digest mismatch, incompatible response model,
unsafe paths or non-positive/out-of-policy bounds.

The descriptor is published only after upstream handshake, audit readiness and
socket admission are ready. Any startup failure must terminate/reap the
upstream process group and remove only the exact socket/descriptor object
created by this epoch.

## 4. Sequence domains

The protocol keeps sequence domains distinct:

```text
client_seq             per admitted connection
broker_request_id      stable caller request identity
broker_upstream_seq    one global upstream order
host_seq               assigned by the selected Host
turn/job event cursor  durable observation order
```

The broker never overwrites one domain without preserving the original in a
separate field.

Each connection requires contiguous `client_seq`. Exact duplicate client
requests are idempotent only when their canonical bytes and digest match.
Sequence reuse with changed bytes is a conflict before forwarding.

## 5. Exact request identity

Every request binds the applicable tuple:

```text
broker_epoch
connection_id
client_id
client_seq
broker_request_id
broker_upstream_seq
request_kind
session_id
profile_id
task_id
turn_id
turn_stream_id
call_id
job_id
operation_id
request_sha256
expected_terminal_kind
```

A response is correlated by this tuple and Host-provided identity. Matching only
`frame.kind` plus optional `job_id` is insufficient and is not conformant.

A spontaneous observation, delayed old response or same-kind frame from another
operation may be broadcast as an observation but cannot satisfy a pending direct
result.

## 6. Three-stage broker audit

Effectful forwarding uses:

```text
broker.accepted
broker.forwarded
broker.terminal or broker.uncertain
```

### 6.1 `broker.accepted`

Written and synced before any upstream write attempt. It binds the exact owner,
request bytes/digest and assigned upstream sequence.

If this write fails:

```text
accepted = false
upstream_write_attempted = false
result = broker_audit_unavailable
automatic_redispatch = false
```

### 6.2 `broker.forwarded`

Written after the exact upstream write/flush outcome. It distinguishes:

```text
not_written
written_and_flushed
write_outcome_uncertain
```

A write/flush error after bytes may have reached upstream is uncertain. The
broker enters a hold and refuses new effectful forwarding that depends on the
audit. It does not repeat the request.

### 6.3 `broker.terminal` / `broker.uncertain`

A direct terminal binds the complete request tuple and is delivered only to the
owning connection when attached. If owner delivery is gone, the terminal remains
in audit/Host durable state for later inspection when supported.

Timeout, upstream disconnect, invalid response identity or audit failure after
forwarding yields a conservative uncertain result.

## 7. Result and observation delivery

Response model:

```text
broker_correlated_result_owner_with_broadcast_observation
```

- direct request results are owner scoped;
- non-secret Host observations may be broadcast to admitted clients through
  finite per-client queues;
- private fields are not broadcast unless the protocol explicitly declares
  them observable;
- a client cannot claim another client's result;
- result ownership survives a slow observer and does not depend on observer
  consumption.

Every delivered wrapper includes:

```text
broker_epoch
broker_response_connection_id
broker_request_id
broker_request_client_seq
broker_request_upstream_seq
broker_request_kind
request_sha256
automatic_redispatch = false
```

## 8. In-flight policy

The broker declares an explicit in-flight model:

```text
serialized one-at-a-time
or bounded multiplexed requests with exact response IDs
```

A single accidental global `pending` slot is not an undocumented concurrency
contract. If upstream supports only serialization, the descriptor states that
fact and the broker uses a bounded FIFO with deterministic owner request order
only after requests enter the broker queue. Cross-connection socket arrival
order is not promised.

Queue exhaustion rejects before forwarding. It does not enqueue and later drop
an accepted effect.

## 9. Live job controls

Live/mutating MCP operations additionally bind a process-lifetime
`bridge_instance_id` where the MCP contract requires it:

```text
job.start
job.attach
job.detach
job.write
job.resize
job.close_stdin
job.kill
```

A later bridge may perform durable read-only inspect/wait using the exact job
scope and request digest. It cannot claim an old pipe, PTY master or process
handle unless a separately qualified supervisor transfer design exists.

The broker identity does not replace job `operation_id`; both are bound.

## 10. Disconnect semantics

Client EOF, socket reset or queue backpressure does not imply:

```text
turn.cancel
job.kill
effect not started
request terminal absent
automatic redispatch
```

The broker detaches that client's delivery, continues draining upstream and
preserves audit truth. Accepted work follows Host/job lifecycle rules.

A later client inspects durable state before deciding a new semantic action.

## 11. Slow clients and bounds

Finite limits include:

```text
clients
input frame bytes
per-client input rate
pending requests
per-client queued frames
per-client queued bytes
upstream stderr capture
audit bytes/records
shutdown grace
startup/handshake deadline
```

A slow client is detached or receives a typed resource/resync result. The
broker never pauses or repeats provider, shell, ADB or job effects to help a
slow observer.

## 12. Startup and cleanup

Startup is owned by one total lifecycle guard:

1. validate configuration and immutable upstream identity;
2. open audit store;
3. spawn upstream process group;
4. complete bounded handshake;
5. create listener and verify exact socket object;
6. atomically publish descriptor/token epoch;
7. start request, response and client lifecycle workers;
8. emit readiness.

Failure at any stage:

```text
closes admission
terminates and reaps upstream group
closes FDs/threads
removes exact socket/temporary descriptor objects
preserves startup error
```

An executable path hash measured before spawn is not alone a complete
anti-TOCTOU execution guarantee. L2 installation must bind immutable/deployment
ownership and the actual executed object identity.

## 13. Shutdown and emergency stop

Administrative shutdown:

- stops admission and new forwarding;
- marks pending accepted requests terminal/uncertain according to durable state;
- terminates/reaps upstream after finite grace;
- detaches clients;
- removes exact epoch objects.

It does not infer that accepted upstream effects were successfully cancelled.

Emergency stop is external to normal broker/Codex health, can inhibit respawn
and preserves audit stores.

## 14. Restart and stale state

Broker restart creates a new epoch and token/descriptor. Old descriptors fail
closed.

On reopen:

```text
accepted + terminal    -> replay/inspect exact result
accepted + forwarded, no terminal -> uncertain; never repeat
accepted, proven not forwarded -> may report not-forwarded, still no automatic repeat
corrupt/torn audit     -> quarantine or conservative hold
```

The broker does not reconstruct live connection ownership from an unauthenticated
old PID or stale descriptor.

## 15. Evidence boundary

Known baseline fixtures cover strict JSON, same-UID/token admission, bounded
queues, owner result isolation, observation broadcast and basic disconnect
truth. They do not close Issue #18's target contract.

Required exits:

- exact identity/audit/startup source and mutation tests: L1;
- compiled selected v5/v7 Host behind the broker in target Root Linux: L2;
- Android SELinux/admission and image: L3;
- crash/ENOSPC/reboot/power-loss broker matrix: L5.

Until the corresponding evidence is bound, the broker must not be described as
fully gap closed.
