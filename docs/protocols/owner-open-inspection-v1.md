# Owner-open turn, call and job inspection v1

Status: **ACTIVE TARGET CONTRACT — turn/call baseline L1; unified job cursor-gap source gap #16 remains open**  
Plan revision: `2026-08-29-r6`  
Canonical alias: `owner-open-inspect-v1.md`  
Unified state machine: `owner-open-effect-state-machine-v1.md`

## 1. Boundary

Inspection is read-only recovery and observability. It never:

```text
starts a provider
claims or spawns a call/job
dispatches shell or ADB
writes job stdin or signals a job
retries an uncertain effect
converts absence of evidence into not-started
appends the inspection response as an effect record
```

Inspection may read validated live registry state, durable records and bounded
indexes. It reports disagreement or missing ranges; it does not reconcile by
performing an effect.

## 2. Common identity

All inspection requests bind the applicable scope:

```text
session_id
profile_id
task_id
turn_id
turn_stream_id
request_sha256
call_id or job_id
```

`profile_id` may default only where the protocol explicitly defines
`owner-open`. A supplied `turn_stream_id` must equal the stable derived value or
current accepted turn value. Conflicting envelope/payload aliases fail.

A request digest is required outside an active bound context so reused IDs
cannot expose another request's records.

## 3. Common cursor response

Every found response carries:

```text
requested_inclusive_cursor
oldest_available_cursor
next_cursor
total_events
complete
has_more
resync_required
gap
durable_fallback_available
source(s)
side_effects = false
automatic_redispatch = false
```

Cursor rules:

- cursor equal to `next_cursor` is valid and returns an empty tail;
- cursor after `next_cursor` conflicts;
- cursor before `oldest_available_cursor` returns an explicit gap;
- missing retained history is never silent;
- a gap includes first/last missing cursor when known;
- malformed/corrupt durable state returns conflict/unavailable, not a partial
  invented history.

## 4. `turn.inspect`

Required correlation:

```text
session_id
profile_id
task_id
turn_id
request_sha256
```

Optional:

```text
turn_stream_id
inclusive_cursor (default 0)
limit (finite deployment maximum)
```

Response kind: `turn.inspect.result`.

A valid result preserves original Host frames and event IDs. It states whether
exactly one terminal exists and whether events appear after terminal. More than
one terminal, identity drift or post-terminal events is a conflict.

Completed durable turns replay without provider execution. Incomplete turns
remain incomplete/unknown; inspection does not append a synthetic semantic
success.

## 5. `call.inspect`

`call.inspect` adds exact `call_id`.

When the call is live, return:

```text
registry snapshot
generation/state
cancellation state
bounded call history
runtime/durable correlated frames
oldest and next history sequence
```

After restart, if the live registry is absent, scan only validated turn records
whose exact call identity and request digest match. Do not reconstruct a richer
semantic state than was durably recorded.

Response kind: `call.inspect.result`.

## 6. `job.inspect`

`job.inspect` adds exact `job_id` and returns:

```text
resident registry snapshot when present
bounded registry history
bounded runtime observations
durable job journal records
live/degraded/terminal state
attachment identities for the current epoch
cursor/gap/replay status
```

Bounded in-memory observations may evict an old prefix. In that case:

```text
requested cursor < oldest available cursor
-> resync_required = true
-> exact missing range when known
-> durable fallback records when available
```

The known baseline does not yet expose complete oldest-retained/gap behavior for
job observations. Issue #16 tracks this source gap.

## 7. `job.wait`

`job.wait` is bounded polling/long-poll observation, not process ownership. It
returns when:

```text
new event exists after cursor
job reaches terminal/degraded state
deadline expires
inspection source becomes unavailable
```

A timeout is an observation timeout. It does not mean the job stopped and does
not authorize start/kill/retry.

## 8. Attachment boundary

`job.attach` may create a live delivery attachment for the current Host/bridge
epoch and return the same inspection shape. `job.detach` removes that delivery
attachment.

A later process can inspect durable state. It cannot claim an old pipe, PTY
master, PID/process-group handle or connection-bound live-control authority.

## 9. Source precedence and disagreement

Inspection may consult:

```text
live registry
runtime observation ring
durable turn store
durable job journal
broker audit
transport delivery journal
```

These sources have different purposes. The response states which were used.
When sources disagree:

- never select the more optimistic state silently;
- preserve each source's last verified cursor/digest;
- return `reconciliation_required`;
- prohibit automatic redispatch;
- allow a later independently authenticated observation to resolve the state.

## 10. Availability and error codes

Suggested statuses:

```text
found
not_found
unavailable
history_gap
conflict
corrupt
reconciliation_required
```

Typical errors:

```text
invalid_inspect_identity
request_digest_conflict
cursor_after_end
cursor_before_retained_history
inspect_limit_exceeded
durable_store_unavailable
durable_record_conflict
response_frame_too_large
```

A response too large for the Host frame limit tells the client to use a smaller
limit. It does not truncate without declaring a gap.

## 11. Privacy and admission

Inspection exposes potentially sensitive prompts, commands and output. The
carrier applies the same local owner/SELinux admission boundary as normal Host
access. A broker observer does not automatically receive private direct result
payloads; read-only inspection still requires exact scope/digest.

## 12. Evidence

Known baseline has L1 source tests for turn/call inspection and durable replay.
Required remaining evidence:

- job oldest-retained cursor and exact gap tests;
- durable fallback/resume integration;
- broker disconnect and later-client inspection;
- installed target Root Linux L2;
- crash/storage/USB/reboot reconciliation at L5.

Inspection evidence never proves an effect beyond the underlying authenticated
records.
