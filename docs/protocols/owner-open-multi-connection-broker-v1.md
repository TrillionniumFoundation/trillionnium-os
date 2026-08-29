# Owner-open multi-connection broker v1

Status: **R6 normative mechanism contract; repository source candidate, installed-target evidence pending**  
Semantic authority: `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`  
Implementation authority: `TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`  
Machine gap: `R5-GAP-BROKER-CORRELATION-001`  
Selected implementation:

- `tools/owner-open/owner_open_connection_broker.py`
- `tools/owner-open/owner_open_broker_runtime.py`
- `tools/owner-open/owner_open_broker_audit.py`
- `tools/owner-open/owner_open_broker_client.py`

## 1. Purpose and authority boundary

The broker is a mechanism-only local carrier that lets multiple authenticated
owner processes share one selected upstream owner-open Host process. It does
not interpret command meaning, classify risk, select a target, approve an
effect, rewrite shell or ADB arguments, choose a provider, retry an uncertain
effect or infer that a missing record proves an effect did not start.

The process topology is:

```text
owner/AiShell/Codex MCP clients
  -> one private filesystem AF_UNIX broker socket
  -> one broker process
  -> one selected v5 transport Host process
  -> one selected v7 execution core
  -> provider and direct shell/ADB/job processes
```

"One semantic Host" means one semantic decision principal, not one operating
system process. Codex/provider remains the only semantic principal. Broker,
transport, core, stores and runtimes own framing, correlation, persistence,
liveness and recovery only.

## 2. Local trust domain

Admission requires both:

1. Linux `SO_PEERCRED` reports the exact broker effective UID; and
2. the first frame presents the exact private token loaded from a service-owned
   mode-0600 regular file.

The descriptor, token, socket parent and audit parent must be stable real paths
with owner and mode checks. The broker refuses to replace an existing socket
path and removes only the socket/descriptor object whose device and inode it
recorded after creation.

Same UID plus a token is one local trust domain. It is not isolation from an
already-compromised process running under that same UID. Product deployment
must use a dedicated service identity, private parent directories and SELinux,
namespace and cgroup controls at L2/L3.

## 3. Epochs and immutable descriptor

Each process start creates:

```text
broker_id       # stable configured service identity
broker_epoch    # random process-lifetime generation
token_epoch     # digest-derived token generation identifier
```

The private descriptor binds:

```text
schema
broker_id
broker_epoch
token_epoch
socket_path
token_file
audit_file
service_uid
upstream executable path/device/inode/mode/SHA-256
upstream argv SHA-256
Host hello.ack
finite client/queue/request limits
request audit stages
automatic_redispatch = false
descriptor_sha256
```

A client may provide `broker_epoch` in `broker.hello`. A mismatched epoch is a
stale descriptor and fails before request admission. The hello acknowledgement
returns the same epoch and descriptor digest; the client must reject drift.

## 4. Client and upstream sequencing

Each connection has one `client_id` and one strictly contiguous nonnegative
`client_seq`. The client sequence is the original Host frame `seq` and remains
immutable request identity. A gap, regression or duplicate sequence under a
new request ID is a protocol error.

The broker allocates one globally monotonic positive `upstream_seq` for every
new accepted request. Allocation and durable acceptance occur under one
serialized admission boundary. Reopen reconstructs the next upstream sequence
from the durable audit so a new broker process does not reuse a previously
accepted sequence.

The broker sends the upstream Host:

```text
seq                  = upstream_seq
client_seq           = original client frame seq
broker_request_id
broker_request_sha256
direction            = client_to_host
```

The Host must preserve the original semantic correlation fields in its direct
response. Transport sequence rewriting must not replace request identity.

## 5. Canonical request identity

The durable request key is:

```text
broker_id
client_id
request_id
```

The canonical request digest binds:

```text
exact client Host frame
sorted expected response kinds
expected job ID, when present
timeout bound
```

The accepted record additionally binds:

```text
broker_epoch
client_seq
upstream_seq
request kind
session_id
profile_id
task_id
turn_id
turn_stream_id
call_id
job_id
operation_id
attachment_id
request_sha256 supplied by the Host protocol, when present
```

An exact duplicate key with the same canonical digest has one of three results:

- durable terminal exists: replay the exact owner message; no upstream write;
- same live broker epoch, accepted or forwarded but unresolved: attach to the
  existing request; no upstream write;
- older broker epoch, accepted or forwarded without terminal: durably resolve
  to `unknown_after_restart`; no upstream write.

The same key with different canonical bytes is `request_id_conflict` before any
second upstream write.

## 6. Three durable stages

The broker audit is an append-only, single-writer, mode-0600 JSONL log with:

```text
contiguous record seq
previous_record_sha256
record_sha256
bounded records/bytes/line size
strict duplicate-member-safe JSON
full file fsync per transition
exclusive nonblocking writer lock
```

Every accepted request moves through the following state machine.

### 6.1 `broker.accepted`

The record is appended and fsynced before the request enters the pending queue
and before any upstream write attempt. It binds the complete request identity,
canonical digest and allocated upstream sequence.

Failure before this record is durable is rejection-before-acceptance. The
request has no broker authorization to reach upstream.

If the write or fsync result is ambiguous, the audit becomes poisoned. The
broker must not forward the request or admit later effects under that audit.

### 6.2 `broker.forwarded`

The broker performs at most one upstream `write + flush` attempt. After the
write returns successfully, it appends and fsyncs `broker.forwarded` with:

```text
exact encoded frame SHA-256
encoded frame byte count
write_attempts = 1
```

The temporal distinction is explicit:

```text
accepted_by_broker
written_to_upstream_pipe
accepted_by_host
```

`broker.forwarded` proves the local write returned; it does not prove the Host
parsed or accepted the frame. A crash or audit failure after the pipe write is
an uncertain effect boundary and never authorizes automatic redispatch.

### 6.3 `broker.terminal`

A direct correlated Host result, a pre-forward rejection after acceptance, an
upstream disconnect, timeout or restart uncertainty produces exactly one
owner-scoped terminal record. The record includes the exact owner message and a
mechanical status such as:

```text
host_terminal_observed
rejected_after_acceptance_before_forward
unknown_after_disconnect
unknown_after_timeout
unknown_after_restart
```

Reopen replays the recorded owner message byte-for-byte after canonical JSON
encoding. A different terminal under the same request identity is a conflict.

## 7. Exact result correlation

A direct result may satisfy the active request only when:

1. `frame.kind` is in the finite expected-kind set;
2. expected `job_id` is present and exact;
3. every non-null request correlation field is present and exact in the Host
   response; and
4. the frame is not merely a broadcast observation or an older operation.

Required comparison fields are:

```text
session_id
profile_id
task_id
turn_id
turn_stream_id
call_id
job_id
operation_id
attachment_id
request_sha256
```

A missing required field is not a wildcard. It is a non-match. Therefore a late
`job.control.result` for operation A cannot satisfy operation B merely because
both use the same response kind and `job_id`.

The selected v7 Host must echo:

- original turn scope and `turn_stream_id` on every job frame;
- `operation_id` on start/write/resize/close/kill results;
- `attachment_id` on attach results;
- canonical job `request_sha256` where the job request exists.

`host.error` and `job.error` remain direct failure frames only while one request
is active. They are not proof that an external effect did or did not start; the
broker records the observed error without retry.

## 8. Observation broadcast and owner result

Every valid upstream frame is broadcast as:

```json
{
  "schema": "org.trillionnium.owner-open.connection-broker-wire.v1",
  "kind": "observation",
  "broker_epoch": "...",
  "frame": {},
  "automatic_redispatch": false
}
```

Broadcast gives admitted owner clients bounded observation access. It does not
transfer request ownership.

The exact request owner alone receives:

```json
{
  "kind": "result",
  "request_id": "...",
  "broker_response_connection_id": "...",
  "broker_request_upstream_seq": 1,
  "broker_request_downstream_seq": 7,
  "broker_request_kind": "job.write",
  "broker_request_sha256": "...",
  "frame": {},
  "automatic_redispatch": false
}
```

A client disconnect detaches only that delivery path. It does not cancel the
upstream Host, active turn, tool or job and does not trigger another write.

## 9. Finite resource model

The broker has explicit finite limits for:

```text
clients
per-client queued frames
per-client queued bytes
accepted pending requests
audit records
audit bytes
audit line bytes
request timeout
upstream stderr capture
```

Pending capacity is reserved before durable acceptance. Capacity exhaustion is
therefore a pre-acceptance rejection and cannot leave an accepted request that
was never queued.

The current source intentionally serializes upstream effectful request delivery
to one active request because the selected Host carrier has one ordered input
stream and current direct-result semantics are single-active-request. The limit
is explicit (`max_inflight_requests = 1`), not an accidental unbounded or
undocumented global variable. Future multiplexing requires a separately
reviewed protocol revision and exact Host correlation proof.

A slow client whose bounded queue is exhausted is detached. Other clients and
the upstream process continue. Detachment is not cancellation.

## 10. Crash and failure matrix

| Cut | Durable fact | Broker response after recovery | Redispatch |
| --- | --- | --- | --- |
| before `broker.accepted` | no accepted record | rejected/not accepted | caller may submit a new identity |
| accepted, before queue/forward | accepted only | `unknown_after_restart` or recorded pre-forward terminal | never automatic |
| during upstream write | accepted; write outcome uncertain | `unknown_after_disconnect` | never automatic |
| write returned, before forwarded fsync | accepted; effect may have started | audit poisoned / unknown | never automatic |
| forwarded, before Host result | accepted + forwarded | `unknown_after_restart` | never automatic |
| Host result observed, before terminal fsync | result delivery/durability uncertain | audit poisoned / unknown | never automatic |
| terminal durable, before owner delivery | terminal durable | exact terminal replay | no effect execution |
| owner disconnect after acceptance | accepted/possibly forwarded | later inspect or terminal replay | never automatic |
| descriptor/token epoch change | older unresolved request remains bound | `unknown_after_restart` | never automatic |

Timeout is not cancellation. When an accepted forwarded request misses its
correlated result deadline, the broker enters upstream-uncertain state, records
an owner terminal if durability remains available and stops forwarding effects.

## 11. Startup and shutdown cleanup

The upstream process starts in its own process group. Any failure during:

```text
Host hello handshake
socket creation/bind/chmod/listen
descriptor publication
reader/worker initialization
```

must enter one `finally` cleanup path that:

- stops admission;
- closes clients and listener;
- removes only proven socket/descriptor objects;
- sends process-group TERM then KILL under finite deadlines;
- reaps the upstream leader;
- closes all pipe descriptors; and
- releases the audit lock.

No initialization failure may leave a live upstream Host or a stale object that
the next start would mistake for the current broker.

## 12. Client contract

The STDIO client verifies the private descriptor and token, supplies the exact
broker epoch, checks the hello acknowledgement descriptor digest and converts
broker observations back into ordinary Host frames. It uses a process-lifetime
request ID including client and broker epoch.

The client never retries a broker request after timeout, disconnect or unknown
status. Durable read-only inspection is a new explicit request, not a replay of
the effect.

## 13. Evidence ladder and claim ceiling

### L1 repository source closure

Required tests include:

- exact duplicate terminal replay with one upstream write;
- conflicting duplicate rejection before a second write;
- accepted/forwarded/terminal hash-chain validation;
- fsync failure poisoning;
- tamper rejection on reopen;
- unresolved prior-epoch recovery without redispatch;
- delayed old operation, missing correlation and wrong-turn non-match;
- two-client observation broadcast and owner-result isolation;
- slow/disconnected client detachment;
- initialization failure process-group cleanup;
- exact v5/v7 compiled Host integration.

L1 proves the repository implementation and fixtures only.

### L2 installed target closure

L2 additionally requires the exact installed broker, Host, core and Codex
binaries under the target Root Linux identities, real filesystem/socket/audit
paths, sustained backpressure, crash/restart cuts and exact traced MCP job
operations. Until that evidence is bound, `R5-GAP-BROKER-CORRELATION-001` is
`SOURCE_CLOSED_PENDING_EVIDENCE`, not fully `CLOSED`.

This protocol never promotes Android image, physical device, destructive fault
or signed release claims.

## Direct error ownership rule

`host.error` and `job.error` may resolve the active request only when every
non-null request correlation field is present and exact. Merely having one
active request is insufficient. An uncorrelated or stale error is broadcast
as an observation, cannot steal owner-result delivery, and leaves the request
unresolved until an exact result or the finite uncertainty deadline.

Even an exactly correlated error is not proof that an external effect did or
did not start. The Broker records the observed error and never retries the
semantic request automatically.
