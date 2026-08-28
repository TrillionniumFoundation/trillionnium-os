# Owner-open multi-connection broker v1

Status: **R5 source implementation; exact-runner and device evidence pending**  
Semantic authority: `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`

## 1. Purpose

The broker lets more than one local owner client share one selected owner-open
Host process without turning connection management into a second semantic
principal.

```text
AiShell / Codex MCP / owner diagnostics
  -> filesystem Unix socket
  -> owner-open connection broker
  -> one selected v5 transport Host
  -> one job-aware v7 execution core
```

It owns only connection admission, request correlation, bounded delivery and
lifecycle mechanics. It does not classify commands, assign risk, require
approval, rewrite arguments, choose a target, or retry an uncertain effect.

## 2. Admission

The foundation carrier uses a filesystem Unix socket. Each accepted client must
satisfy both:

1. `SO_PEERCRED` UID equals the configured service/owner UID; and
2. the first strict JSON frame contains the current 32-byte random broker token
   encoded as lowercase hexadecimal.

The token file and broker descriptor are private `0600` regular files owned by
the effective service UID. The socket parent must be a stable owner-controlled
directory. Symlinks, unsafe parents, duplicate JSON members and oversized
frames are rejected mechanically.

Android abstract-socket and SELinux-domain admission remain W6 integration
work; they are not implied by the foundation filesystem carrier.

## 3. Descriptor

The broker writes a digest-bound descriptor with schema:

```text
org.trillionnium.owner-open.connection-broker.v1
```

It binds at least:

```text
broker_id
socket_path
token_file
upstream executable identity and argv digest
max_clients
client_queue_frames
client_queue_bytes
max_pending_requests
response_model
```

`descriptor_sha256` binds the canonical descriptor preimage. Clients reject a
descriptor whose digest, path, response model or positive mechanical bounds do
not match.

## 4. Request ownership

Every client request receives one broker-local correlation identity. The
broker records which admitted connection owns that request before forwarding
it upstream.

Direct response frames are delivered to the owning client. Observation frames
that are not private request results may be delivered to every admitted client
through a bounded per-client queue. The response model is:

```text
broker_correlated_result_owner_with_broadcast_observation
```

A client cannot claim another client's pending response. Unknown, duplicate or
conflicting correlation is a protocol error, not a reason to repeat the
upstream operation.

## 5. Job live-control ownership

The Codex MCP job bridge additionally exposes one random `bridge_instance_id`
for its process lifetime. The following live or mutating MCP operations must
carry that exact value:

```text
job.start
job.attach
job.detach
job.write
job.resize
job.close_stdin
job.kill
```

Read-only `job.inspect` and `job.wait` may be issued from a later connection
using the stable job scope and request digest. A later process is not allowed to
pretend it has adopted an old pipe, PTY master or process-group handle.

Thus the current boundary is:

```text
same live bridge/broker owner -> live controls
new bridge or Host process    -> durable inspect/wait only
```

Cross-process file-descriptor adoption remains explicitly unsupported until a
separate SCM_RIGHTS or supervisor-owned design is implemented and qualified.

## 6. Disconnect semantics

Client EOF, socket reset or delivery backpressure does not imply:

```text
turn.cancel
job.kill
effect not started
automatic redispatch
```

The broker removes that connection's delivery ownership, continues draining the
upstream Host, and records bounded transport truth. An already accepted effect
continues under Host/job lifecycle rules. A new client must inspect durable
state before deciding what to do next.

## 7. Bounds

The broker enforces finite limits for:

```text
clients
pending requests
frame bytes
per-client queued frames
per-client queued bytes
upstream stderr
shutdown grace
```

A slow client may lose its delivery attachment or receive a finite
`resource_exhausted`/resynchronization result. That does not authorize the
broker to pause or repeat provider, shell, ADB or job effects.

## 8. Emergency and shutdown

Administrative broker shutdown closes admission, stops forwarding new
requests, drains or terminates the single upstream process according to a
finite grace, and reaps the process group. It does not infer successful
cancellation of already accepted work. Emergency stop independent of Codex and
the normal broker remains an Android/Root Linux W6 requirement.

## 9. Evidence boundary

Source and process fixtures can establish parsing, token admission, peer UID,
request-owner routing, observation broadcast, bounded queues and disconnect
truth. They do not establish:

- Rust Host correctness;
- installed Codex use;
- Android SELinux admission;
- cross-Host descriptor adoption;
- physical shell, PTY or ADB effect;
- crash, reboot or power-loss conformance;
- public release qualification.

Until exact runner records exist, this capability remains
`SOURCE_IMPLEMENTED / L0`.
