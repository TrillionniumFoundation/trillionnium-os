# Owner-open stream flow control v1

Status: **isolated R5 source state machine; Host integration pending**

The stream window is a mechanism-only byte-credit state machine. It applies
backpressure without interpreting provider text, command meaning, target risk or
whether an observation is desirable.

## State

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

## Controls

- `stream.window_update`: add finite byte credit without exceeding the profile
  maximum;
- `stream.pause`: block new byte reservations;
- `stream.resume`: allow reservations when credit exists;
- `stream.close`: terminally close the local window and discard remaining
  credit.

Every control carries an exact monotonically contiguous sequence number.
Identical duplicate controls are idempotent while retained. A changed duplicate,
sequence gap or trimmed stale control fails without mutating state.

## Data reservation

Before placing a bounded data chunk on a controlled output queue, the carrier
requests a byte reservation. The result is one of:

```text
granted(bytes, remaining_credit)
blocked(paused)
blocked(insufficient_credit)
blocked(closed)
```

Concurrent reservations are serialized by the state lock and cannot overdraw
credit. Credit reservation is delivery accounting only; it does not authorize
or deny the underlying effect. Durable observation persistence must occur
independently of a paused or detached client stream.

## Current boundary

`crates/trillionnium-owner-open-stream-window` implements and tests the state
machine. The selected Host does not yet bind reservations to outbound frames,
so `stream.window_update`, `stream.pause` and `stream.resume` are not yet claimed
as serviceable Host controls.
