# Owner-open effect state machine v1

Status: **ACTIVE CONTRACT — source conformance and L2/L5 qualification pending**  
Plan revision: `2026-08-29-r6`  
Applies to: turn start, direct tool call, job start, job control, broker forwarding and ordinary ADB effect

## 1. Purpose

This protocol gives every effectful owner-open operation one crash-aware
mechanical model. It does not authorize the effect and does not interpret its
meaning. Its purpose is to prevent contradictory claims such as:

```text
capacity exhausted after a child already ran
journal unavailable therefore not started
client disconnected therefore cancelled
timeout therefore safe to retry
leader exited therefore all descendants are gone
```

## 2. Identity

An effect key contains the identifiers applicable to its layer:

```text
session_id
profile_id
task_id
turn_id
turn_stream_id
call_id or job_id
operation_id
connection_id
client_id
broker_epoch
broker_request_id
request_sha256
binding_fingerprint
```

The exact canonical request bytes bind all provider-owned effect fields.
Correlation-only transport fields are excluded from the semantic request digest
but are separately bound by the broker/Host record.

Rules:

- exact key + exact request bytes attaches or replays known state;
- exact key + different bytes is a conflict before effect;
- an effectful job control always has its own `operation_id`;
- one request's terminal cannot satisfy another request by frame kind alone;
- a new semantic retry/compensation normally uses a new operation identity.

## 3. Mechanical stages

```text
received
validated
capacity_reserved
accepted_durable
effect_attempted
started_or_forwarded_durable
observing
terminal_observed
terminal_durable
delivery_attempted
closed
```

Not every read-only operation needs all stages. An effectful implementation must
not skip a required durable stage without declaring a best-effort policy.

### 3.1 `received`

Bytes entered the component. No acceptance or no-start guarantee is implied.

### 3.2 `validated`

Strict framing, duplicate-member rejection, identity, digest and finite
mechanical bounds passed. Semantic meaning was not classified.

### 3.3 `capacity_reserved`

Finite process/in-flight/storage capacity was atomically reserved before any
child or upstream write attempt.

If reservation fails:

```text
result = rejected_before_acceptance
effect_attempted = false
automatic_redispatch = false
```

The caller may construct a future new request; the component did not accept this
one.

### 3.4 `accepted_durable`

The operation identity and exact digest are durably recorded before the effect
when the operation requires durable-before-effect behavior.

A successful record means only that the mechanism accepted custody. It does not
mean the effect started.

### 3.5 `effect_attempted`

At least one action capable of starting the effect occurred, for example:

```text
spawn/fork/exec path entered
bytes written or flush attempted to an upstream Host
stdin bytes written to a live job
PTY resize ioctl attempted
signal delivered or attempted
ADB process started
remote/provider request released
```

From this point, failure to observe a result is uncertain unless stronger
platform evidence proves otherwise.

### 3.6 `started_or_forwarded_durable`

The component records the observed child/upstream identity:

```text
PID
process group/session
process start time
boot identity
upstream sequence
provider/Host acceptance identity
generation
```

This is not a semantic success record.

### 3.7 `observing`

Output, lifecycle and status facts are appended with exact sequence, byte counts,
hashes and scope. Delivery may be attached or detached independently.

### 3.8 `terminal_observed`

The mechanism observed a terminal fact such as process exit, signal, timeout,
cancellation, explicit Host terminal, broker uncertainty or cleanup failure.

### 3.9 `terminal_durable`

The terminal fact is durably bound to the original accepted operation. Exact
duplicates replay this record without repeating the effect.

### 3.10 `delivery_attempted`

The component attempted to deliver an accepted/observation/terminal frame.
Delivery success or failure does not rewrite effect truth.

## 4. Terminal and degraded states

| State | Meaning | May auto redispatch |
| --- | --- | ---: |
| `rejected_before_acceptance` | validation/capacity failed and no effect attempt is proven | no; caller may submit a new request |
| `spawn_failed` | spawn returned failure before a child existed | no |
| `completed_durable` | terminal record is durable and replayable | no |
| `completed_observed_undurable` | terminal was observed but required persistence failed | no |
| `cancelled_observed` | cancellation reached the mechanism and terminal observation exists | no |
| `timed_out_observed` | local deadline forced termination; remote uncertainty is preserved separately | no |
| `unknown_after_disconnect` | connection ended after effect may have started | no |
| `unknown_after_timeout` | accepted request had no correlated terminal before deadline | no |
| `unknown_after_journal_failure` | persistence failed after effect may have started | no |
| `unknown_after_cleanup_failure` | process/group absence could not be proven | no |
| `reconciliation_required` | durable and live/remote observations do not yet converge | no |

`automatic_redispatch` is always false.

## 5. Durability policies

Every effect kind declares:

```json
{
  "durable_before_effect": true,
  "durable_after_effect": true,
  "continue_when_unavailable": false,
  "terminal_replayable": true,
  "uncertain_restart_result": "unknown_after_restart"
}
```

### 5.1 Fail closed before effect

When `durable_before_effect=true` and the accepted record cannot be written, the
effect must not be attempted.

This is the required default for:

```text
job.start
job.write
job.resize
job.close_stdin
job.kill
broker effectful forwarding
```

### 5.2 Best-effort unreplayable

A read-only or explicitly best-effort observation may continue without a store
only when its contract says so. It must advertise:

```text
event_log_status = best_effort_unreplayable
durable_replay_available = false
```

### 5.3 Failure after effect

If persistence fails after `effect_attempted`, the component records or emits
the strongest available degraded truth and inhibits new effectful operations
that require durability. It must not report `not_started`.

## 6. Process launch protocol

### 6.1 Pre-spawn reservation

Capacity is reserved before spawn. A rejected reservation cannot kill a child
because no child exists.

### 6.2 Post-spawn lifecycle guard

Immediately after successful spawn, a guard owns:

```text
child handle
PID
process group/session
open pipes/PTY
reader and writer tasks
reservation
registry transition
journal transition
```

Until the operation commits to the normal running state, dropping/failing the
guard performs bounded group termination, reap, FD closure, reservation release
and a truthful terminal/degraded transition.

### 6.3 Reader-before-writer

For pipe and PTY jobs, output drains are active before non-empty initial stdin is
written. Initial stdin uses a bounded writer task. A child that writes before it
reads must not deadlock the parent.

### 6.4 Parent and descendant truth

Where supported, parent-death signaling and PID start identity are bound.
Leader exit is followed by bounded process-group/descendant cleanup. The terminal
records:

```text
leader_reaped
process_group_observed_gone
cleanup_error
```

If the process group cannot be proven gone, terminal truth is degraded.

## 7. Broker forwarding protocol

The broker has three distinct custody stages:

```text
broker.accepted
broker.forwarded
broker.terminal or broker.uncertain
```

`broker.accepted` binds client/connection/request identity before write.
`broker.forwarded` binds the exact upstream write/sequence result.
A Host observation is correlated by the complete identity tuple, not only frame
kind or job ID.

A write or flush failure after possible upstream receipt is uncertain. Broker
restart never repeats it automatically.

## 8. Streaming, retention and cursors

Potentially unbounded frames have delivery class `bounded_stream`, including:

```text
model.delta
model.message
provider.opaque
tool.stdout
tool.stderr
job.output
```

Control, inspect, accepted and terminal frames remain serviceable when stream
credit is zero.

Every inspection response carries:

```text
requested_inclusive_cursor
oldest_available_cursor
next_cursor
total_events
has_more
durable_fallback_available
gap
```

If requested cursor is older than retained memory, the response includes an
exact missing range and `resync_required=true`; it never silently begins at a
later cursor.

## 9. Duplicate and restart rules

### Exact duplicate with durable terminal

Return the same terminal/result. Do not perform the effect again.

### Exact duplicate with known live state

Attach or return the current snapshot according to the operation contract.

### Accepted without terminal after restart

Return `unknown_after_restart` or `reconciliation_required`. Do not perform the
effect again.

### Different bytes under the same identity

Return conflict before effect.

### No record

No record is proof of no effect only when the component can prove the request
never crossed an effect-attempt boundary. Otherwise it is unknown.

## 10. Error preservation

The first process/effect error, storage error, delivery error and cleanup error
are separate fields. Cleanup must not overwrite the original observation.

Example:

```json
{
  "terminal_kind": "spawn_failed",
  "effect_error": "ENOENT",
  "journal_error": null,
  "delivery_error": "EPIPE",
  "cleanup_error": null,
  "automatic_redispatch": false
}
```

## 11. Fault-cut matrix

Every implementation must test relevant cuts:

| Cut | Required proof |
| --- | --- |
| before validation | no acceptance |
| after validation, before reservation | no effect |
| reservation failure | no spawn/write |
| after accepted record | no redispatch after crash |
| after fork/spawn, before started record | effect may have started |
| after upstream write, before forwarded record | uncertain |
| during initial stdin | drains remain live; bounded cleanup |
| during output append | degraded journal state |
| after terminal observation, before terminal fsync | observed-undurable |
| after terminal durable, before delivery | exact replay |
| delivery disconnect/backpressure | effect continues; inspection available |
| cleanup TERM/KILL failure | unknown-after-cleanup |
| restart with accepted-only record | unknown/reconciliation |
| ENOSPC/torn/corrupt record | quarantine or conservative recovery |

## 12. Conformance and evidence

L1 requires exact-head unit, property, process and fault-injection tests.
L2 repeats process/broker/provider behavior in target Root Linux.
L3 binds the Android-installed implementation.
L4 observes physical effects.
L5 executes destructive crash/storage/USB/reboot/power-loss cuts.

A source implementation may mark its gap `SOURCE_CLOSED_PENDING_EVIDENCE`; it
may not mark an external exit level closed.
