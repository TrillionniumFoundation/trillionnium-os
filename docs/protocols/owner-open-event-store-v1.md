# Owner-open event store v1

Schema: `trillionnium.owner-open.event-record.v1`  
Status: **R5 source protocol; Host/restart integration pending**

## Purpose

The store is an append-only observation log. It preserves facts the local Host
actually observed and supports replay/inspection. It does not grant effect
authority, classify a command or prove that an unrecorded effect did not occur.

## Record

Each newline-delimited record contains:

```json
{
  "schema": "trillionnium.owner-open.event-record.v1",
  "store_seq": 12,
  "turn_seq": 4,
  "scope": {
    "session_id": "session-...",
    "profile_id": "owner-open",
    "task_id": "task-...",
    "turn_id": "turn-...",
    "turn_stream_id": "stream-..."
  },
  "event_id": "event-...",
  "kind": "tool.stdout",
  "payload": {},
  "payload_sha256": "...",
  "previous_record_sha256": "...",
  "record_sha256": "..."
}
```

`store_seq` is contiguous across the file. `turn_seq` is contiguous within the
complete turn scope. The first record binds an all-zero previous digest; later
records bind the immediately preceding record digest.

The record digest is computed over the fixed ordered preimage excluding
`record_sha256`. The payload digest binds the canonical serde JSON bytes of the
payload object.

## Identity and duplicates

Event identity is:

```text
session_id
+ profile_id
+ task_id
+ turn_id
+ turn_stream_id
+ event_id
```

An exact repeated append returns the stored record without adding bytes. The
same identity with different kind or payload is an event conflict. The same
local event label is valid in another complete turn scope.

## Open and recovery

The source implementation requires:

- normalized absolute path with a dedicated parent;
- service-owned parent not writable by group/world;
- regular service-owned `0600` file with one hard link;
- `O_NOFOLLOW|O_CLOEXEC`;
- one non-blocking exclusive writer lock;
- bounded file, record and record-count limits;
- recursive duplicate-member-safe decode;
- exact schema, digest-chain and sequence verification.

A final record without newline is truncated and is not silently discarded.
Tampering, duplicate on-disk identity, sequence drift or hash drift stops
reopen. Recovery tooling may be added later, but normal startup must not invent
or skip records.

## Append and sync

Policies:

- `none`: flush userspace buffers only;
- `data`: `sync_data` after each record;
- `full`: `sync_all` after each record.

The owner-open default is intended to be `full` for durable Host events. If a
write, flush or sync becomes ambiguous after bytes may have reached the file,
the writer becomes poisoned and refuses further appends. The Host must mark the
lineage best-effort/unreplayable or stop that evidence path; it must never infer
that the associated effect was not started.

## Replay

Replay is scoped to one complete turn and an inclusive `turn_seq`. Returned
records preserve original event IDs, store/turn sequence and hashes. Replaying a
record does not execute a tool.

## Remaining gates

Not yet implemented or claimed:

- Host writes events before client delivery;
- durable completed-turn replay without provider spawn;
- incomplete-turn reconciliation to `unknown_after_disconnect`;
- job/spool storage;
- retention/compaction;
- ENOSPC, crash, reboot and power-loss evidence;
- Android data-label/SELinux integration.
