# Owner-open turn and call inspection v1

Status: **R5 source protocol; executed Rust/Host evidence pending**

Inspection is a read-only recovery and observability operation. It never starts
a provider, claims a call, dispatches shell/ADB, appends the inspection response
to the observation log, or converts an uncertain effect into a retry decision.

## `turn.inspect`

Required correlation outside the active turn:

```text
session_id
profile_id (defaults to owner-open)
task_id
turn_id
request_sha256
```

Optional fields:

```text
turn_stream_id
inclusive_cursor (default 0)
limit (default 64, maximum 256 on the wire)
```

The Host derives the stable turn-stream ID from session/profile/task/turn and
rejects a conflicting supplied value. During the active turn, the exact request
digest may be inferred from the accepted turn; outside the active turn it is
required to prevent reading another request under reused correlation IDs.

Response kind: `turn.inspect.result`.

A found response includes:

```text
source = durable_event_store
inclusive_cursor
next_cursor
total_events
complete
has_more
frames[]
side_effects = false
automatic_redispatch = false
```

`inclusive_cursor == total_events` is valid and returns an empty tail. A cursor
beyond the next cursor, a request digest conflict, malformed durable record,
multiple terminal records or events after the terminal is an explicit conflict.

## `call.inspect`

`call.inspect` adds an exact `call_id` in the envelope or payload. Conflicting
aliases are rejected.

While the call exists in the in-memory registry, the response contains the
current snapshot and bounded call-state history. A cursor earlier than retained
history reports `history_truncated`; a cursor after `next_event_seq` conflicts.

After restart, if the live registry has no entry, the Host scans validated
turn records and returns only frames whose `call_id` matches exactly. This path
preserves raw tool frames when present but does not reconstruct a semantic call
state that was not durably recorded.

Response kind: `call.inspect.result`.

## Failure and availability

- no durable store: `status=unavailable`;
- no matching records/call: `status=not_found`;
- malformed or conflicting identity: `host.error` with an inspect-specific
  code;
- response larger than the Host frame limit: retry with a smaller limit;
- inspection never performs automatic redispatch.
