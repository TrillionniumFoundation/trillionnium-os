# Owner stage trace contract

This crate and the existing broker common module implement opt-in, source-level stage observations. They do not qualify an installed system, an entire workload, a kernel peak, or L2 performance. The existing 16-owner/32 MiB effect resource pool is unchanged.

The selected Host/Core and broker entrypoints configure tracing only when `TRILLIONNIUM_OWNER_TRACE_SAMPLE` is present. The sample and producer role have an ASCII bound of 128 bytes. Optional `TRILLIONNIUM_OWNER_TRACE_OUTPUT` names an absolute prefix in an existing private directory; each process exports to `prefix.producer_role`. Use an exclusive directory for each physical invocation. Trace hooks retain timestamps and hashes in memory; they never write a log or wait for the trace mutex. Export runs outside product locks. Export failure makes an opted-in entrypoint exit 2, even when the product effect/wire output already completed; the effect outcome must still be read from its own terminal record.

When unconfigured, Rust returns an empty pointer-sized span without calling a clock, hashing, allocating a record, or issuing a syscall. Python decorators return the original function immediately without inspecting caller arguments or properties; explicit span sites use a shared inert context object. This does not claim zero instruction overhead or unchanged binary layout.

## Actual boundaries

Both implementations use Linux `CLOCK_MONOTONIC` (Python `time.monotonic_ns()`), process and native thread IDs, and SHA256 of the bounded local scope key. A key hash is not proof of source identity, request authenticity, or a universal cross-process correlation ID. Static scope keys require the separately retained wire/journal/request context.

| Stage | Actual source boundary |
| --- | --- |
| `broker_accept` | `owner_open_broker_server_v2.py`: the real listener `accept`, including timeout/error exits. |
| `broker_auth` | `owner_open_broker_admission_v2.py::_authenticate`: public peer credentials, hello validation and authentication return/error. |
| `broker_queue_wait` | `owner_open_broker_mux.py`: accepted request queue insertion to selection for dispatch; removal/hold/drain abandons the span. |
| `broker_forward` | `owner_open_broker_convergence_v2.py::_forward_request`: forward admission and the real transport/journal path, including early rejection. |
| `host_decode` | selected transport and Core v2/v4/v7 process entrypoints: actual `RunTurnFrame::decode`, including rejected frames. |
| `host_capacity_wait` | `r5_control_host_v2.rs::send_turn_event_with_timeout`: channel admission and persistence acknowledgement. |
| `journal_append` | broker audit `_append` and event-store `append_under_working`: the actual append operation, including errors. |
| `journal_fsync` | broker audit and event store: actual file/directory `fsync`, `sync_data` or `sync_all`; the no-sync policy does not invent a span. |
| `provider_spawn` | provider-jsonl `run_session`: actual `Command::spawn`. |
| `provider_first_event` | immediately after successful spawn returns, through the first validated JSONL envelope (protocol, sequence, nonempty kind). A `tool.call`, terminal or opaque envelope can be first; this is not the first model token or validation of its semantic payload. |
| `provider_wait` | provider-jsonl: the actual blocking receiver wait, excluding subsequent event processing. |
| `callback_admission` | tool-bridge `execute_fallible_with_deadline`: validation/capacity/registry claim before effect dispatch; scope exit does not assert admission success. |
| `tool_spawn` | runtime and job-runtime pipe/PTY: actual `Command::spawn`. |
| `tool_output` | runtime/job-runtime: actual reader `read` after readiness observation; EOF/error boundaries remain classified by product evidence. |
| `tool_exit` | successful spawn return (job guard construction immediately afterwards) to actual owned exit observation. Job reaper uses its existing non-consuming `WNOWAIT`; the trace does not consume an anchor, signal, or change ownership. Setup failure before observation abandons the span. |
| `tool_cleanup` | runtime/job-runtime: actual process-group cleanup and runtime worker retirement; success must be read from the existing cleanup result. |
| `terminal_persistence` | terminal-only Host frame append, broker audit terminal append and job terminal observation append. Accepted/nonterminal frames are not relabelled terminal. |
| `delivery_queue_wait` | transport blocked frame insertion to release; broker client accepted `_put` insertion hook to dequeue return (includes the small append/get-return overhead, excludes pre-admission Client lock wait). The original queue mutex ensures attachment before a writer can dequeue. Closed/byte-capacity/full rejection creates no span. Suppression/clear abandons the transport span. |
| `client_delivery` | selected transport actual write/newline/flush and broker `send_all_bounded`; this observes write scope, not client application consumption. |

Intervals can overlap or nest. They are not additive latency components. This source integration does not establish all nineteen stages for every WL01–12 operation; several workload drivers, denominators and resource lifecycle hooks remain separate missing inputs.

## Loss and snapshot semantics

Schema `org.trillionnium.actual-monotonic-stage-trace.v1` uses the same closed loss fields in Rust and Python. `loss_observed` is a boolean. Rust `lost_records` is an optional count with `lost_count_semantics="lower_bound"`; Python reports null with `lost_count_semantics="unavailable"`, because it does not claim an atomic loss counter. Capacity exhaustion, contention, abandoned deferred scopes and invalid clock/key boundaries preserve loss instead of overwriting older evidence. Physical completion values are `observed_boundary`, `scope_exit_unclassified`, `exception` (Python), and `abandoned`; none means semantic success.

`snapshot_without_observed_loss` describes only the captured prefix. Every snapshot has `snapshot_only=true`, `producer_quiescence_proven=false`, `trace_complete=false`, and `installed_qualified=false`. A producer can run or lose another span after cloning. An external consumer must retain independent exact process/whole-unit termination, export kernel outcome, source/binary custody, actual workload and raw effect observations before considering a final scope. No consumer here upgrades those flags.

## Source-bound local resource limits

Each recorder admits at most 8192 **completed plus in-flight** spans. Key input is at most 4096 UTF-8 bytes and is discarded after hashing; retained scope strings are exactly 64 ASCII bytes. Python first bounds character length before encoding (at most 16384 temporary encoded bytes), then enforces the 4096-byte key limit. Stage/end strings are closed constants. Sequence and timestamps are unsigned 64-bit, PID unsigned 32-bit, and native TID at most signed 64-bit. Identifier storage is at most 256 ASCII bytes per recorder.

The configured active recorder uses this budget for the entire producer process lifetime, not for each workload operation or batch. Rust's `ACTIVE` `OnceLock` cannot be reset, and the configured Python broker recorder retains its completed records. A long-running broker shared by 1000 samples can therefore exhaust the budget. The external harness must bound the producer lifetime and admitted record count, retain every loss outcome, and reject an incomplete batch under its declared protocol. This implementation does not establish complete coverage of six batches by resetting or discarding records.

Rust tests enforce `size_of<Record>() <= 128`, `size_of<Pending>() <= 160`, and `size_of<Span>() <= 8` on the actual target. The preallocated record vector addresses at most `8192*128` bytes. Completed records plus boxed pending records and their 64-byte hash strings address at most `8192*(160+64)` additional bytes; this intentionally overcounts the completed vector already reserved. A single snapshot clone addresses at most `8192*(128+64)` bytes plus its fixed header and bounded identifiers. These are payload/layout bounds, excluding allocator metadata, allocator rounding, thread stacks and RSS. They are not a 1 MiB recorder claim. A queued frame/guard has an extra optional span field even when disabled.

For the closed record schema, a record encodes in fewer than 512 JSON bytes and the header has a conservative 2048-byte bound. Thus 8192 records have at most 4,196,352 encoded bytes; the independently enforced export limit is 8 MiB. Rust retains a snapshot clone and serialization vector simultaneously. Python retains its recorder dictionaries, cloned snapshot dictionaries and temporary JSON string plus encoded bytes simultaneously. Python object/container overhead is implementation dependent; it cannot use Rust layout bounds or claim a 1 MiB cap. Repeated caller-created snapshots or recorders have no global count bound in this API.

Export paths are at most 4096 bytes/64 components, with at most 64 held directory/file owners. An existing private physical parent and a fresh mode-0600 inode are required; before publication completes, retained parent entries and output identity/size are checked. The five-second monotonic deadline rejects a late returned operation; it is not a kernel I/O timeout or filesystem quota. Partial files and failed exports remain unqualified evidence.

The whole-system producer set and simultaneous recorders/snapshot consumers have not been independently bounded. The proposed 16 MiB aggregate trace budget remains **HOLD**. A future installed recorder must enumerate the exact broker/Host/Core producer set, cap snapshots/exports and account for their actual runtime object/allocator footprints, queue fields and threads before making that claim.

## Module ownership and local verification

Package: `trillionnium-owner-open-trace`.

- [MOD-EXECUTION-CORE](../../docs/modules/MOD-EXECUTION-CORE.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-trace --all-targets
```

The existing planned telemetry module and its activation status are unchanged.

## Reliability boundary for actual batches

Nonblocking trace contention has occurred in an actual owned Host/Core turn:
the product retained its shell exit 9 and terminal frame, while the snapshot
reported two lost records and lacked a retained `tool_exit` boundary. That
round is incomplete performance evidence even though the recorder correctly
reported the loss and the product protocol completed. An integration test may
validate this fail-closed loss contract; it cannot classify a missing stage as
measured. A later 6000-sample qualification must retain and reject incomplete
rounds according to its predeclared batch protocol, rather than cherry-pick
loss-free snapshots or splice them into a batch. Collection reliability under
real concurrency remains a separate optimization gap.
