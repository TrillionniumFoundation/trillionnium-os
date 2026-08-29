# Owner-open stream delivery flow v1

Status: **ACTIVE TARGET CONTRACT — v5 transport source baseline L1; job-output/cursor gap #16 remains open**  
Plan revision: `2026-08-29-r6`  
Selected transport: `apps/trillionnium-owner-open-host/src/bin/r5_transport_host.rs`  
Selected execution core: `apps/trillionnium-owner-open-host/src/bin/r5_control_host_v7.rs`  
Window state machine: `crates/trillionnium-owner-open-stream-window`  
Tracking gap: `R5-GAP-STREAM-RECOVERY-001` / Issue #16

## 1. Boundary

The v5 transport controls delivery of already-produced Host frames. It never
pauses provider reasoning or child execution, never changes effect truth and
never redispatches an effect.

The v7 core remains responsible for provider/tool/job execution, exact
correlation, per-event durable append, cancellation, conservative recovery and
read-only inspection.

Default delivery is pass-through. A client activates a finite byte window only
with an exact stream-control request and only while the core reports a durable
observation source capable of filling declared delivery gaps.

## 2. Generated delivery classes

Frame delivery class must be declared in one generated protocol table rather
than repeated hand-maintained `matches!` lists.

### `bounded_stream`

Potentially unbounded frames consume credit:

```text
model.delta
model.message
provider.opaque
tool.stdout
tool.stderr
job.output
```

### `critical_bypass`

Lifecycle, control, inspection, recovery and terminal frames bypass stream
credit:

```text
hello.ack
turn.accepted
provider.status
tool.accepted
tool.started
tool.result
job.start.result
job.control.result
job.inspect.result
job.result
turn.cancel.accepted
tool.cancel.accepted
turn.inspect.result
call.inspect.result
stream.* acknowledgements
stream.resync_required
turn.end
host.error
```

Bypass prevents a zero-credit or paused reader from blocking cancellation,
inspection or terminal truth.

The known baseline currently omits `job.output` from the selected flow
classifier. This document states the required target, not a completed source
claim.

## 3. Identity

Every stream control binds:

```text
session_id
profile_id
task_id
turn_id
turn_stream_id
control_seq
canonical control fingerprint
```

`control_seq` is independent of client, broker and Host frame sequences.

Rules:

- next exact sequence applies once;
- exact duplicate sequence + exact payload returns `existing`;
- duplicate sequence + changed payload conflicts;
- sequence gap conflicts;
- control from another turn/stream conflicts;
- a control cannot authorize semantic retry.

## 4. `stream.window_update`

```json
{
  "kind": "stream.window_update",
  "payload": {
    "control_seq": 1,
    "session_id": "session-1",
    "profile_id": "owner-open",
    "task_id": "task-1",
    "turn_id": "turn-1",
    "turn_stream_id": "stream-1",
    "credit_bytes": 65536
  }
}
```

Credit is additive, finite and capped. The window records:

```text
available_credit_bytes
max_credit_bytes
max_chunk_bytes
paused
closed
total_granted_bytes
earliest_control_seq
next_control_seq
```

A bounded-stream frame larger than `max_chunk_bytes` begins a delivery gap; it
is not split or silently truncated unless a separate chunking protocol defines
that transformation.

## 5. `stream.pause`

Pause stops live delivery of bounded-stream frames. It does not stop:

```text
provider reasoning
shell/ADB/job execution
stdout/stderr/PTTY drains
durable append
turn/tool/job cancellation
inspection
terminal observation
```

The finite delivery queue may fill while paused.

## 6. `stream.resume`

Resume unpauses delivery. It does not add credit.

After a declared gap, resume requires:

```text
resumed_through_cursor >= required_resume_cursor
```

The client proves it used durable inspection to recover through that cursor.
A cursor before the requirement conflicts. Supplying a resume cursor when no
gap exists also conflicts.

## 7. Persist before flow decision

A bounded-stream frame may enter the delivery queue or suppression state only
after its canonical observation is durable under the configured policy.

The transport's copy is delivery state, not the sole evidence copy. When the
core durable store becomes unavailable:

- no new claim of durable recoverability is made;
- an active window is disabled;
- retained queued frames may be released in order;
- an existing gap remains a gap;
- effect execution is not retried;
- the core's journal-degraded policy determines whether new effects continue.

## 8. Queue and gap creation

If credit is unavailable, a bounded-stream frame enters a finite FIFO queue.
The queue binds encoded byte count, event ID and durable cursor.

A gap begins when:

```text
frame exceeds max_chunk_bytes
or queued bytes would exceed max_buffer_bytes
or a required delivery copy cannot be retained
```

On gap:

1. record first/last suppressed event ID and cursor;
2. record suppressed frame count;
3. clear finite delivery copies that can no longer form a complete range;
4. emit `stream.resync_required` through critical bypass;
5. suppress subsequent bounded-stream delivery until recovery is acknowledged;
6. continue reading/persisting execution output;
7. keep controls, inspection and terminal delivery serviceable.

No provider, tool, ADB or job effect is repeated.

## 9. `stream.resync_required`

Example:

```json
{
  "kind": "stream.resync_required",
  "payload": {
    "first_missing_cursor": 120,
    "last_missing_cursor": 247,
    "required_resume_cursor": 248,
    "first_event_id": "stream-event-120",
    "last_event_id": "stream-event-247",
    "suppressed_frames": 128,
    "durable_fallback_available": true,
    "automatic_redispatch": false
  }
}
```

When a stable cursor cannot be derived, the response requires inspection from a
safe earlier cursor, potentially zero. It must not invent a cursor from a
malformed event ID.

## 10. Terminal behavior

Before `turn.end` or `job.result`, the transport converts any remaining queued
but undelivered bounded-stream range into an exact terminal gap. The terminal
payload includes:

```text
stream_resync_required
stream_gap
client_delivery_status_before_terminal_attempt
client_delivery_error
```

Terminal delivery is attempted even when bounded-stream credit is zero.
Delivery failure is recorded separately from effect terminal truth.

## 11. Client disconnect

Client EOF or output failure detaches live delivery. The transport continues
draining the core so accepted work can complete and persist.

A separate transport journal may record:

```text
client delivery attached/detached
first delivery error
stream gap
terminal delivery attempt
transport epoch
```

The transport journal is evidence, not action authority.

## 12. Job inspection and retention

Job output uses the same durable cursor vocabulary as turn/call inspection.
Every inspection result includes:

```text
requested_inclusive_cursor
oldest_available_cursor
next_cursor
total_events
has_more
gap
durable_fallback_available
```

If bounded in-memory job retention evicted an earlier prefix, the Host returns
an explicit missing range. It does not silently begin from the first retained
event.

## 13. Slow consumers and multi-client broker

Each broker client has finite frame/byte queues. One slow client may detach
without stopping upstream output or another client's critical results.

Observation broadcast is best-effort within declared bounds. Durable
inspection/resync is the recovery path. A slow observer does not acquire
permission to pause execution globally.

## 14. Bounds

The selected deployment declares finite:

```text
max credit
max controlled frame/chunk bytes
max queued frames
max queued bytes
control history
maximum inspect page
per-client broker queues
transport journal bytes/records
```

All arithmetic is checked/saturating where appropriate and all externally
supplied values have finite maxima.

## 15. Evidence

Known baseline `479e5fb...` has L1 source evidence for the stream-window
mechanics, pause/resume and resync tests. The following are still required:

- add `job.output` to generated delivery classification;
- explicit oldest-retained cursor/gap behavior;
- zero-credit long-job control responsiveness;
- slow-client sustained-output soak;
- installed target L2 repeat;
- disconnect/storage/reboot fault coverage at L5.

Issue #16 closes the repository source portion only after exact-head tests pass.
