# Owner-open long-running jobs v1

Status: **ACTIVE TARGET CONTRACT — implementation baseline L1; audited source gaps #14–#17 remain open**  
Plan revision: `2026-08-29-r6`  
Unified state machine: `owner-open-effect-state-machine-v1.md`  
Implementation packages:

- `crates/trillionnium-owner-open-job-registry`
- `crates/trillionnium-owner-open-job-runtime`
- `apps/trillionnium-owner-open-host/src/bin/r5_control_host_v7.rs`
- `apps/trillionnium-owner-open-host/src/bin/r5_transport_host.rs`

## 1. Boundary

A job is a mechanism-only long-running local process. Codex/provider supplies
the exact command or argv and interprets every observation. The Host does not
classify command meaning, select a target, require a semantic approval lease,
rewrite arguments or automatically retry an uncertain job operation.

A job differs from one-shot `shell.exec` because it may survive its creating
turn and exposes separate effectful controls:

```text
job.start
job.write
job.resize
job.close_stdin
job.kill
```

Read-only operations are:

```text
job.inspect
job.wait
```

`job.attach`/`job.detach` affect live delivery ownership and do not adopt an old
file descriptor after Host restart.

## 2. Identity

The job key is:

```text
session_id
profile_id
task_id
turn_id
turn_stream_id
job_id
```

The canonical job request binds:

```text
tool = shell.job
target_id as correlation/routing metadata
mode = pipe | pty
command XOR argv
shell executable identity
cwd
environment delta
initial stdin digest and length
PTY dimensions
opaque extensions
```

The Host computes `request_sha256`. A supplied digest is accepted only when it
matches the canonical request. Same key + same request attaches/replays; same
key + different bytes conflicts before effect.

## 3. Operation identity

Every effectful operation has a stable `operation_id`. Its digest binds:

```text
operation kind
job key
canonical job request digest
exact operation payload
```

Rules:

- accepted + terminal: replay the exact result;
- accepted without terminal: `unknown_after_restart` or
  `reconciliation_required`;
- same operation ID + different bytes: conflict;
- no accepted record permits a no-start claim only when no effect attempt is
  independently proven;
- automatic redispatch is always false.

## 4. Pre-spawn admission

`job.start` must reserve finite job capacity **before** durable acceptance or
spawn. Capacity refusal returns:

```json
{
  "status": "resource_exhausted",
  "effect_attempted": false,
  "accepted": false,
  "automatic_redispatch": false
}
```

The implementation must not spawn a child and then discover that `max_jobs` is
full. This requirement is tracked by `R5-GAP-JOB-ADMISSION-001` / Issue #14.

## 5. Start lifecycle

Target order:

```text
validate request
reserve job slot
write operation.accepted
claim one spawn generation
spawn child under lifecycle guard
establish readers and control handles
record PID/process-group/session/start/boot identity
insert live job and start dispatcher
write job.started / operation.terminal(started)
commit reservation to live ownership
```

Until the live state is committed, one lifecycle guard owns the child,
reservation, FDs, registry and journal transitions. Every failure after spawn
performs bounded process-group cleanup, leader reap, FD closure, reservation
release and a truthful terminal/degraded state.

## 6. Pipe and PTY process mechanics

### Pipe mode

- child has separate stdin/stdout/stderr pipes;
- stdout and stderr drains are active before non-empty initial stdin is written;
- initial stdin is written by a bounded writer task;
- closing stdin drops the pipe writer;
- output remains byte preserving.

### PTY mode

- child creates a session and controlling terminal;
- stdout/stderr are merged into the PTY stream;
- resize uses `TIOCSWINSZ`;
- the current close-stdin mechanism may write an EOT byte;
- EOT is not a universal guarantee that every program treated stdin as closed.

The reader-before-writer and total post-spawn cleanup requirements are tracked
by Issue #15.

## 7. Parent, PID and descendant truth

Where Linux provides the required primitives, the runtime binds:

```text
PID
process start time
boot ID
process group
session ID
parent-death signal configuration
```

The parent-PID race is checked after configuring parent-death behavior.

Leader exit alone is not proof that descendants are gone. After leader exit or
forced termination, the runtime performs bounded group cleanup and records:

```text
leader_reaped
process_group_observed_gone
cleanup_error
```

If process-group absence cannot be proven, terminal status is
`unknown_after_cleanup_failure` or `reconciliation_required`; it is not a clean
completion claim.

## 8. Frames

Client to Host:

```text
job.start
job.inspect
job.attach
job.detach
job.write
job.resize
job.close_stdin
job.kill
job.wait
```

Host to client:

```text
job.start.result
job.inspect.result
job.attach.result
job.detach.result
job.control.result
job.started
job.output
job.result
job.status
job.error
```

Every effectful response binds the exact `operation_id` and request digest.
All job frames carry the complete job scope and `job_id`.

## 9. Start payload

Example pipe job:

```json
{
  "kind": "job.start",
  "seq": 8,
  "direction": "client_to_host",
  "payload": {
    "session_id": "session-1",
    "profile_id": "owner-open",
    "task_id": "task-1",
    "turn_id": "turn-1",
    "turn_stream_id": "turn-stream-1",
    "job_id": "build-1",
    "operation_id": "start-build-1",
    "tool": "shell.job",
    "target_id": "rootlinux",
    "mode": "pipe",
    "argv": ["/usr/bin/ninja", "-C", "out"]
  }
}
```

Example PTY fields:

```json
{
  "mode": "pty",
  "command": "exec /bin/bash",
  "pty": {"rows": 40, "cols": 120}
}
```

`command` and `argv` are mutually exclusive. PTY dimensions are non-zero. A
pipe job must not carry PTY dimensions.

## 10. Input and output bytes

`job.write.payload.data` accepts a UTF-8 string or bounded base64 bytes:

```json
{"encoding": "base64", "data": "AAEC"}
```

`job.output` is byte preserving:

```json
{
  "job_id": "build-1",
  "stream": "stdout",
  "encoding": "base64",
  "data": "...",
  "byte_count": 4096,
  "sha256": "...",
  "cursor": 12
}
```

Output counts and hashes describe observed bytes. They do not guarantee output
completeness after a declared delivery/retention gap.

## 11. Bounded flow control

`job.output` is a `bounded_stream` frame and participates in:

```text
stream.window_update
stream.pause
stream.resume
stream.resync_required
```

Pausing delivery does not pause the child process, persistence, cancellation,
inspection or terminal observation. Accepted/control/inspect/terminal frames
bypass the byte-credit gate.

The current implementation baseline omits `job.output` from the selected flow
classifier; Issue #16 must close this source gap before this section is claimed
as implemented.

## 12. Retention and cursor recovery

Every job inspection returns:

```text
requested_inclusive_cursor
oldest_available_cursor
next_cursor
total_events
has_more
durable_fallback_available
resync_required
gap(first_missing_cursor,last_missing_cursor)
```

If bounded memory evicted old events, inspection must not silently begin at the
oldest retained event. It returns an exact gap and, when possible, durable
records that fill it.

A resume after a delivery gap is accepted only when
`resumed_through_cursor` proves the client inspected through the required
cursor.

## 13. Journal policy and degraded state

Effectful job operations default to:

```text
durable_before_effect = true
durable_after_effect = true
continue_when_unavailable = false
terminal_replayable = true
```

If the accepted record cannot be written, the effect is not attempted. If
persistence fails after the effect may have started, the state is one of:

```text
live_journal_degraded
completed_observed_undurable
unknown_after_journal_failure
reconciliation_required
```

Critical append failures are never discarded. New effectful controls that
require durability are inhibited while read-only inspection remains available
where possible. Issue #17 tracks this source and fault gap.

## 14. Controls

### `job.write`

Binds exact bytes/digest and writes at most once. An accepted operation without
a durable terminal after restart is unknown and is not repeated.

### `job.resize`

Valid only for PTY jobs. It binds rows/columns and one operation identity.

### `job.close_stdin`

Pipe mode closes the pipe writer. PTY mode applies the documented EOT behavior.

### `job.kill`

Signals the exact live process group/session associated with the bound PID
identity. A successful signal syscall is not itself proof that all processes
terminated.

## 15. Inspection and attachment

`job.inspect` and `job.wait` are read-only. They never claim a spawn, control or
retry. They return resident registry state, bounded history, runtime/durable
observations and replay/degraded status.

`job.attach` creates live delivery ownership for the current Host/bridge epoch.
A later process may inspect durable truth but cannot pretend to own an old pipe,
PTY master or process-group handle.

Cross-process live descriptor adoption remains unsupported unless a separate
supervisor/SCM_RIGHTS design is reviewed and qualified.

## 16. Restart truth

A completed durable job never spawns again for the same exact key/request. A
durable accepted start without terminal remains unknown. The current source
does not discover and re-adopt an orphaned process after Host restart.

A late independently authenticated observation may resolve uncertainty, but it
cannot retroactively authorize an automatic replacement process.

## 17. Bounds and cleanup

Configuration declares finite:

```text
max live jobs
max input bytes
max output chunk bytes
max observations/job
max observation bytes/job
journal bytes/records
inspect limit
control operation history
termination grace
startup recovery time
```

Retention/rotation and cleanup are explicit. Exhaustion produces a typed
resource/degraded condition; it is not semantic denial.

## 18. Evidence and claim ceiling

Known exact baseline `479e5fb...` has L1 source/host evidence, including pipe,
PTY, control and no-redispatch fixtures. The audited requirements in Issues
#14–#17 are not closed merely by that historical pass.

Minimum exits:

- Issues #14–#17 source portions: exact-head L1;
- installed Root Linux placement/lifecycle: L2;
- physical normal path: L4;
- crash/ENOSPC/reboot/power-loss: L5.

No source document or fixture promotes those external levels.

## Exact direct-response correlation matrix

Every direct job response binds the full job scope, `turn_stream_id`,
`job_id` and canonical job `request_sha256` once that digest exists.
Effectful responses additionally echo the exact `operation_id`.

| Request | Direct result | Required echoed identity |
| --- | --- | --- |
| `job.start` | `job.start.result` | full scope, `job_id`, start `operation_id`, canonical request digest |
| `job.inspect` | `job.inspect.result` | full scope, `job_id`, optional supplied `operation_id`, canonical request digest |
| `job.attach` | `job.attach.result` | full scope, `job_id`, optional supplied `operation_id`, `attachment_id`, canonical request digest |
| `job.detach` | `job.detach.result` | full scope, `job_id`, optional supplied `operation_id`, `attachment_id`, canonical request digest |
| write/resize/close/kill | `job.control.result` | full scope, `job_id`, exact `operation_id`, canonical request digest |
| rejected job request | `job.error` | every mechanically recoverable field from the rejected request; no field is a wildcard |

An error that cannot recover enough exact request correlation remains an
observation and cannot resolve a different active Broker request. Missing
correlation fails closed into timeout or uncertainty rather than
cross-delivering an error to the wrong operation.
