# Owner-open event store v1

Schema: `trillionnium.owner-open.event-record.v1`  
Status: **ACTIVE BASE CONTRACT — exact baseline L1; journal convergence/retention/fault gap #17 remains open**  
Plan revision: `2026-08-29-r6`  
Unified effect state machine: `owner-open-effect-state-machine-v1.md`  
Tracking gap: `R5-GAP-JOURNAL-CONVERGENCE-001` / Issue #17

## 1. Purpose and non-authority

The store is an append-only observation log. It preserves facts the local Host
actually observed and supports replay, inspection and conservative restart
analysis.

It does not:

```text
grant effect authority
classify command meaning
prove an unrecorded effect did not occur
authorize retry from missing/corrupt data
replace process/transport reconciliation
```

The embedding Host declares whether an operation requires durable acceptance
before effect or permits explicit best-effort continuation.

## 2. Record

Each newline-delimited record contains:

```json
{
  "schema": "trillionnium.owner-open.event-record.v1",
  "store_seq": 12,
  "turn_seq": 4,
  "scope": {
    "session_id": "session-1",
    "profile_id": "owner-open",
    "task_id": "task-1",
    "turn_id": "turn-1",
    "turn_stream_id": "stream-1"
  },
  "event_id": "stream-1-event-4",
  "kind": "tool.stdout",
  "payload": {},
  "payload_sha256": "...",
  "previous_record_sha256": "...",
  "record_sha256": "..."
}
```

`store_seq` is contiguous across the file. `turn_seq` is contiguous within the
complete scope. The first record binds the all-zero previous digest; later
records bind the immediately preceding record digest.

The record digest covers the fixed canonical preimage excluding
`record_sha256`. The payload digest binds canonical JSON bytes.

A hash chain detects drift relative to a known chain head. It is not an external
anti-tamper anchor when an attacker can rewrite the complete file and recompute
the chain. L3–L6 evidence therefore binds the file/chain head into separately
protected manifests or signatures where required.

## 3. Identity and duplicates

Event identity is:

```text
session_id
profile_id
task_id
turn_id
turn_stream_id
event_id
```

An exact repeated append returns the stored record without adding bytes. The
same identity with a different kind or payload is a conflict. Event identity is
scoped; the same local label in another complete scope is independent.

## 4. File and parent identity

Open requires:

- normalized absolute path with dedicated parent;
- stable real parent owned by the service and not group/world writable;
- regular service-owned `0600` file with one hard link;
- `O_NOFOLLOW|O_CLOEXEC` where supported;
- parent device/inode stability across open;
- one non-blocking exclusive writer lock;
- bounded file, record, count, identifier and kind limits;
- recursive duplicate-member-safe JSON decode;
- exact schema, sequence, payload digest and record-chain validation.

The deployment evidence additionally records mount ancestry, filesystem, quota
and SELinux label. Source path checks do not prove target mount integrity.

## 5. Open and recovery

Normal reopen verifies the entire retained chain and reconstructs:

```text
record count
byte count
last record digest
event identity index
next per-scope sequence
poisoned/degraded state
```

A final record without newline is a typed torn/truncated tail. Mid-log
corruption, duplicate identity, sequence drift or digest drift is hard
corruption. Normal startup does not silently discard, renumber or skip records.

Repair, when implemented, is a separate explicit tool that:

```text
operates on a quiescent copy
preserves the original corrupt object
identifies the last independently verified boundary
writes a new create-only repaired object
emits a repair receipt and new chain anchor
never changes effect truth or authorizes redispatch
```

## 6. Append protocol

Target append sequence:

1. validate scope, ID, kind and object payload;
2. resolve exact duplicate/conflict;
3. verify capacity before constructing a new record;
4. compute payload and record digests;
5. append the complete JSON record plus newline;
6. flush userspace buffers;
7. apply configured sync policy;
8. verify resulting file length/identity;
9. advance in-memory indexes only after the durable policy succeeds.

Sync policies:

```text
none  -> userspace flush only
data  -> sync_data
full  -> sync_all
```

The owner-open durable default is `full` for accepted/started/terminal records
that are load-bearing for replay. Deployment may batch high-volume observations
only under a separately documented durability and loss contract.

## 7. Ambiguous writes and poisoning

A write, flush, sync or post-write metadata error may occur after bytes reached
the filesystem. The writer enters a poisoned/degraded state and refuses unsafe
further assumptions.

The Host distinguishes:

```text
store unavailable before effect
live journal degraded after effect
terminal observed but undurable
unknown after journal failure
reconciliation required
```

A storage error is preserved separately from process/effect, delivery and
cleanup errors.

The current job dispatcher baseline can drop critical journal errors and fail
to converge live registry versus durable terminal truth. Issue #17 tracks this
source gap; broad “fail closed” language must not be used until the exact state
model and tests close it.

## 8. Operation durability policy

Each embedding operation declares:

```text
durable_before_effect
durable_after_effect
continue_when_unavailable
terminal_replayable
uncertain_restart_result
```

Effectful job controls and broker forwarding default to durable-before-effect.
When their accepted record cannot be written, no effect is attempted.

If persistence fails after effect attempt, new durability-dependent effects are
inhibited. Read-only inspection remains available from the strongest valid
sources.

## 9. Replay

Replay is scoped and cursor-bound. Returned records preserve original IDs,
sequences, hashes and payloads. Replaying records never invokes a provider,
spawns a process, writes stdin, signals a job or invokes ADB.

Completed exact operations replay their terminal. Accepted/started without
terminal becomes unknown/reconciliation required. No record is not no-start
proof when an effect could have crossed the store boundary.

## 10. Cursors and retained ranges

Every store/inspection API exposes:

```text
requested inclusive cursor
oldest retained cursor
next cursor
total logical events
has more
gap or corruption status
```

A caller requesting before retained history receives an explicit gap. Rotation
or retention must not silently make cursor zero mean “first currently retained
record.”

## 11. Retention, rotation and compaction

The deployment contract specifies finite:

```text
maximum active-store bytes
maximum records
rotation threshold
maximum segments
retention duration/bytes
minimum terminal/reconciliation retention
startup recovery-time budget
```

Rotation is quiescent or uses an explicitly journaled segment protocol. Segment
manifests bind:

```text
first/last store and scope cursors
first/last record digests
record count and bytes
previous segment digest
segment SHA-256
creation/close identity
```

Compaction may materialize an inspection index or snapshot but never discard the
only unresolved accepted/started operation record. Compaction receipts are
append-only evidence.

## 12. Capacity exhaustion and cleanup

Capacity is checked before accepting a new durable-before-effect operation.
Exhaustion before acceptance rejects without effect. Exhaustion after an effect
begins is a degraded/uncertain condition.

Cleanup is explicit and auditable. TTL or retention is a liveness mechanism, not
semantic authorization. Unresolved operations and evidence required for current
reconciliation are pinned until resolved or separately archived.

## 13. ENOSPC and fault behavior

Required cuts:

```text
ENOSPC before accepted record
short write during record
flush failure
sync failure
metadata length mismatch
torn final record
mid-log corruption
writer lock contention
rotation failure
directory fsync failure
reboot/power loss at each durable stage
```

Each cut records whether an effect attempt was possible. No cut permits blind
redispatch.

## 14. Privacy and export

Observation payloads may contain prompts, commands, paths, output and provider
metadata. Export policy declares:

```text
owner authorization
redaction rules
token/credential exclusion
maximum export bytes
chain verification
scope filtering
retention and deletion authority
```

Redacted export is a derived object with its own digest and receipt; it is not
the canonical replay store.

## 15. External anchoring

For higher evidence levels, chain heads are bound into:

```text
exact-head CI evidence manifest
installed target receipt
Android image/source manifest
physical-device qualification package
signed release provenance
```

The anchor records store path/epoch, bytes, record count and last digest.

## 16. Evidence boundary

Known baseline `479e5fb...` has L1 tests for strict reopen, duplicate/conflict,
sequence/hash validation, writer locking and completed/incomplete replay
integration.

Still open:

- complete job/runtime degraded-state convergence;
- retention/rotation/compaction implementation;
- explicit oldest-retained cursor behavior across retention;
- installed target mount/SELinux placement;
- ENOSPC, reboot and power-loss qualification;
- external chain anchoring for release claims.

Issue #17 source closure requires exact-head fault injection. L5 remains a real
target/storage evidence lane.
