# Trillionnium OS Effect and Protocol Standard

Status: **NORMATIVE**  
Protocol family: **owner-open-effect-v1**

## 1. Identity

Every effect binds all applicable identifiers:

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
module instance and epoch
request_sha256
binding fingerprint
```

An exact key with exact bytes attaches, inspects or replays known state. The
same key with different bytes is a conflict before effect. Transport-local
sequence fields do not replace semantic request identity.

## 2. Lifecycle

```text
received
 -> validated
 -> capacity_reserved
 -> accepted_durable
 -> effect_attempted
 -> started_or_forwarded_durable
 -> observing
 -> terminal_observed
 -> terminal_durable
 -> delivery_attempted
 -> closed
```

Read-only operations may omit effect stages. Effectful operations declare which
durable stages are mandatory.

## 3. Truth at crash cuts

| Cut | Strongest safe claim |
| --- | --- |
| before validation | not accepted |
| reservation failure before effect | rejected before acceptance |
| accepted but no proof effect remained impossible | unknown or reconciliation required |
| spawn/write/remote attempt occurred | effect may have started |
| started/forwarded without terminal | unknown after restart/disconnect |
| terminal observed but persistence failed | observed but undurable |
| terminal durable but delivery failed | replay exact terminal without repeating effect |

`automatic_redispatch` is always false.

## 4. Durability classes

Every effect kind declares:

```json
{
  "durable_before_effect": true,
  "durable_after_effect": true,
  "continue_when_store_unavailable": false,
  "terminal_replayable": true,
  "uncertain_restart_result": "unknown_after_restart"
}
```

A best-effort read-only observation may continue only when its contract says so
and must advertise that durable replay is unavailable.

## 5. Terminal vocabulary

Required common states include:

```text
rejected_before_acceptance
spawn_failed
completed_durable
completed_observed_undurable
cancelled_observed
timed_out_observed
unknown_after_disconnect
unknown_after_timeout
unknown_after_journal_failure
unknown_after_cleanup_failure
unknown_after_restart
reconciliation_required
```

Effect, storage, delivery and cleanup errors are separate fields; cleanup never
overwrites the original failure.

## 6. Delivery is not effect truth

Client EOF, slow delivery, queue detachment and zero stream credit do not cancel
upstream work. Control, inspect and terminal paths remain serviceable when data
stream credit is zero.

Every cursor response declares:

```text
requested inclusive cursor
oldest available cursor
next cursor
has more
durable fallback
exact missing range
resync required
```

Silent cursor skipping is forbidden.

## 7. Multiplexing

Multi-inflight implementations must prove:

- complete request correlation;
- one owner result per request;
- late and same-kind response isolation;
- per-ordering-key serialization;
- cross-key parallelism;
- bounded queues and capacity reservation;
- fairness and starvation bounds;
- no retry after timeout or disconnect.

Increasing an inflight constant without a protocol revision and correlation
proof is prohibited.

## 8. Leases in effect paths

A mechanical lease may admit work and assign resources. It does not authorize
semantic meaning.

The accepted record binds the lease and fencing identity used at admission.
Lease expiry after an effect attempt cannot rewrite the operation as not
started. A stale writer is fenced from further state mutation, and recovery
reconciles the existing operation without repeating it.

## 9. Extension and compatibility

Protocol versions use explicit major/minor compatibility. Unknown extension
fields are preserved when allowed. Required identity, digest, stage and error
fields are never treated as optional extensions.

Every major protocol change includes producer/consumer matrices, golden frames,
mutation tests, upgrade order and rollback behavior.
