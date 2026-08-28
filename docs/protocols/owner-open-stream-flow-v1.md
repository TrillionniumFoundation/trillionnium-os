# Owner-open stream delivery flow v1

Status: **R5 source implementation; Rust execution pending**  
Selected transport: `apps/trillionnium-owner-open-host/src/bin/r5_transport_host.rs`  
Execution core: `apps/trillionnium-owner-open-host/src/bin/r5_control_host_v4.rs`  
Window state machine: `crates/trillionnium-owner-open-stream-window`

## Boundary

The v5 transport carrier controls only delivery of already-produced Host frames.
The v4 core remains responsible for provider/tool execution, per-event durable
append, cancellation, conservative recovery and read-only inspection.

Default behavior is pass-through. A byte window is activated only by an explicit
client stream-control frame and only while the core reports an available durable
event store. This prevents bounded memory pressure from becoming silent loss of
the sole observation copy.

## Controlled frames

The credit gate applies only to high-volume frames:

```text
model.delta
model.message
tool.stdout
tool.stderr
provider.opaque
```

Lifecycle and control frames bypass the byte gate:

```text
hello.ack
turn.accepted
tool.accepted
tool.started
tool.result
turn.cancel.accepted
tool.cancel.accepted
turn.inspect.result
call.inspect.result
turn.end
host.error
stream.* acknowledgements
```

Bypass preserves cancellation, terminal truth and recovery access while model
or process output delivery is paused.

## Client controls

All controls are exact active-turn correlations and carry a stream-local
`control_seq` independent of the ordinary transport frame sequence.

### `stream.window_update`

```json
{
  "kind": "stream.window_update",
  "payload": {
    "control_seq": 1,
    "session_id": "...",
    "profile_id": "owner-open",
    "task_id": "...",
    "turn_id": "...",
    "turn_stream_id": "...",
    "credit_bytes": 65536
  }
}
```

Credit is additive and finite. A duplicate control sequence is idempotent only
when its canonical payload fingerprint is identical. Sequence gaps and payload
drift conflict.

### `stream.pause`

Pauses controlled delivery without pausing provider reasoning, tool execution,
durable append, cancellation or inspection.

### `stream.resume`

Resumes controlled delivery. It does not add credit; the client uses
`stream.window_update` separately.

## Bounded queue and resynchronization

Blocked high-volume frames enter a finite in-memory delivery queue after the
v4 core has appended them to the durable observation store.

If the configured queue bound would be exceeded, the carrier:

1. stops retaining delivery copies for the affected high-volume range;
2. preserves execution and continues reading the core;
3. emits `stream.resync_required` with first/last missing durable cursor;
4. continues delivering lifecycle, cancellation, inspect and terminal frames;
5. suppresses later high-volume frames until recovery is acknowledged; and
6. requires `stream.resume.resumed_through_cursor` at or beyond the advertised
   next cursor after the client has used `turn.inspect`.

No provider or tool effect is redispatched as part of recovery.

## Client disconnect

The carrier drains the core even after its client output path detaches, so the
core can complete and persist the accepted turn. Ultimate client-delivery status
is written to a separate append-only transport journal at:

```text
<event-store-path>.transport
```

The transport journal is observation evidence, not authorization state.

## Claim ceiling

The source and authored tests are L0. `HOST_TESTED` requires an exact Rust 1.93
runner result for format, compilation, unit/integration tests and clippy, bound
to one commit and reviewed lockfile.
