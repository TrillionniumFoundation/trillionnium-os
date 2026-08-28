# Owner-open long-running jobs v1

Status: **R5 source contract and implementation; exact-repository Rust and device evidence pending**  
Semantic authority: `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`  
Implementation packages:

- `crates/trillionnium-owner-open-job-registry`
- `crates/trillionnium-owner-open-job-runtime`
- `apps/trillionnium-owner-open-host/src/bin/r5_control_host_v7.rs`

## 1. Boundary

A job is a mechanism-only long-running local process. The owner/Codex supplies the exact command or argv and interprets every observation. The Host does not classify command meaning, select a target, require a semantic approval lease, rewrite arguments or automatically retry an uncertain job operation.

A job is distinct from a one-shot `shell.exec` call:

- it may remain live after its creating turn finishes;
- it has a stable `job_id` and job stream;
- stdin, PTY resize, attach/detach and kill are separate operations;
- observations can be inspected after live delivery is lost;
- every effectful control has an independent `operation_id`.

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
target_id               # correlation only
mode = pipe | pty
command XOR argv
cwd
environment delta
initial stdin digest and length
PTY dimensions
opaque extensions
```

The Host computes `request_sha256`. A caller-supplied request digest is accepted only when it exactly matches the canonical request. The binding fingerprint binds the configured shell executable, tool and mode.

An exact scoped job and exact request is idempotent. The same scoped `job_id` with different request bytes is a conflict.

## 3. Operation identity

Each effectful operation carries a stable `operation_id`:

```text
job.start
job.write
job.resize
job.close_stdin
job.kill
```

The operation digest binds:

```text
operation kind
job key
exact operation payload
```

The durable journal writes `operation.accepted` before invoking the local effect. It then writes `operation.terminal` after the effect result is known.

On restart:

- accepted + terminal: return the recorded result; do not repeat the effect;
- accepted without terminal: report `unknown_after_restart`; do not repeat the effect;
- different operation bytes under the same operation ID: conflict.

This rule applies to start, stdin write, resize, close and kill. There is no blind automatic redispatch.

## 4. Frames

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

All job frames carry the job scope and `job_id`. Host output uses a stable job-specific `stream_id`; the creating turn stream remains part of the job key but is not reused as the delivery stream.

## 5. Start payload

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

`command` and `argv` are mutually exclusive. PTY dimensions must be non-zero. A pipe job must not carry PTY dimensions.

## 6. Bytes and PTY

`job.write.payload.data` accepts either a UTF-8 string or:

```json
{"encoding": "base64", "data": "AAEC"}
```

`job.output` is byte preserving:

```json
{
  "stream": "stdout",
  "encoding": "base64",
  "data": "...",
  "byte_count": 4096,
  "sha256": "..."
}
```

Pipe jobs expose `stdout` and `stderr`. PTY jobs expose the merged `pty` stream. PTY close-stdin currently writes an EOT byte; pipe close-stdin closes the stdin pipe.

## 7. Inspection and attachment

`job.inspect` is read-only. It returns:

- resident registry snapshot and bounded registry history when the Host still owns the job;
- bounded in-memory runtime events;
- bounded raw durable journal records;
- inclusive cursor and next cursor metadata;
- replay status: `durable`, `best_effort_unreplayable` or `unknown_after_restart`.

`job.attach` registers a live attachment and returns the same inspection shape. `job.detach` removes that live attachment. After Host restart, durable inspection remains available; reconstruction of a live PTY file descriptor across process restart is not claimed.

## 8. Delivery flow control

The selected Host remains the v5 transport over the v7 job-aware execution core. Job output frames use their own stream ID and therefore participate in the same persisted bounded delivery mechanics as turn/tool output:

```text
stream.window_update
stream.pause
stream.resume
```

Pausing delivery does not pause the child process. Job observations are journaled before live delivery where the journal is available. Retention exhaustion is a mechanical backpressure/fault condition, not semantic denial.

## 9. Process lifecycle

The runtime provides:

- one process group/session per job;
- pipe or PTY setup;
- continuously drained bounded output;
- PTY resize with `TIOCSWINSZ`;
- group signal delivery;
- leader reap and descendant cleanup after leader exit;
- parent-death signal for the direct job child;
- Linux PTY `EIO` interpreted as slave EOF.

The current source does not yet provide cgroup placement, namespace selection, durable file-descriptor transfer, cross-Host live reattachment or proof that all forked descendants die after abrupt Host power loss. Those are later Root Linux and L5 gates.

## 10. Recovery truth

A completed durable job never spawns again for the same job request. A journaled start without a durable terminal is `unknown_after_restart`. The Host does not infer that such a job never started and does not start a replacement.

A late external observation may later resolve uncertainty, but the current source does not discover or re-adopt an orphan process after Host restart.

## 11. Claim ceiling

The checked-in source and authored tests do not establish:

- exact-repository Rust format/test/clippy success;
- installed Codex use of `shell.job`;
- Android image inclusion;
- Root Linux identity/cgroup placement;
- live cross-process PTY reattachment;
- reboot or power-loss conformance;
- public release qualification.

Until those records exist, this capability remains `SOURCE_IMPLEMENTED / L0`.
