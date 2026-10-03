# Owner stage trace contract

This crate and the existing broker common module implement opt-in, source-level stage observations. They do not qualify an installed system, an entire workload, a kernel peak, or L2 performance. The existing 16-owner/32 MiB effect resource pool is unchanged.

The selected Host/Core and broker entrypoints configure tracing only when `TRILLIONNIUM_OWNER_TRACE_SAMPLE` is present. The sample and producer role have an ASCII bound of 128 bytes. Optional `TRILLIONNIUM_OWNER_TRACE_OUTPUT` names an absolute prefix in an existing private directory; each process exports to `prefix.producer_role`. Use an exclusive directory for each physical invocation. Trace hooks retain timestamps and hashes in memory; they never write a log or wait for the trace mutex. Export runs outside product locks. Export failure makes an opted-in entrypoint exit 2, even when the product effect/wire output already completed; the effect outcome must still be read from its own terminal record.

When unconfigured, the Rust span primitive returns an empty pointer-sized span without calling a clock, hashing, allocating a record, or issuing a syscall inside that primitive. Rust evaluates caller arguments before entering it, so a caller-provided `format!`, clone or other key expression would still execute. Existing hooks borrow an already present key or use a static string; the primitive does not provide a general lazy-key API. Python decorators return the original function immediately without inspecting caller arguments or properties; explicit span sites use a shared inert context object. This does not claim zero instruction overhead or unchanged binary layout.

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

Rust preallocates one `Mutex<Option<Record>>` per lifetime slot. A bounded strong-CAS loop claims a unique slot; only that span publishes to it, using `try_lock`. Producers therefore never share a publication mutex. Snapshot reads the initially claimed slots individually with `try_lock` and returns an error on a busy or poisoned slot. A snapshot reader can still race with publication and cause an explicitly counted loss. Missing slots, active spans, abandonment and capacity exhaustion stay incomplete. Slots are never recycled, including after a failed publication. Records are emitted in increasing claim-sequence order, with visible gaps for unpublished slots; completion order can differ. The loss-free prefix flag also requires a retained record for every initially claimed slot, so a span closing after its empty slot was read cannot make an incomplete capture appear loss-free. This sequential slot capture is not an atomic whole-recorder snapshot or proof of quiescence.

## Source-bound local resource limits

Each recorder admits at most 8192 **completed plus in-flight** spans. Key input is at most 4096 UTF-8 bytes and is discarded after hashing; retained scope strings are exactly 64 ASCII bytes. Python first bounds character length before encoding (at most 16384 temporary encoded bytes), then enforces the 4096-byte key limit. Stage/end strings are closed constants. Sequence and timestamps are unsigned 64-bit, PID unsigned 32-bit, and native TID at most signed 64-bit. Identifier storage is at most 256 ASCII bytes per recorder.

The configured active recorder uses this budget for the entire producer process lifetime, not for each workload operation or batch. Rust's `ACTIVE` `OnceLock` cannot be reset, and the configured Python broker recorder retains its completed records. A long-running broker shared by 1000 samples can therefore exhaust the budget. The external harness must bound the producer lifetime and admitted record count, retain every loss outcome, and reject an incomplete batch under its declared protocol. This implementation does not establish complete coverage of six batches by resetting or discarding records.

Rust tests enforce `size_of<Record>() <= 128`, `size_of<Mutex<Option<Record>>>() <= 160`, `size_of<Pending>() <= 160`, and `size_of<Span>() <= 8` on the actual target. The preallocated slot vector addresses at most `8192*160` bytes. Completed records plus boxed pending records and their 64-byte hash strings address at most `8192*(160+64)` additional bytes; this intentionally overcounts completed records already reserved in slots. A single snapshot clone addresses at most `8192*(128+64)` bytes plus its fixed header and bounded identifiers. These are payload/layout bounds, excluding allocator metadata, allocator rounding, thread stacks and RSS. They are not a 1 MiB recorder claim. A queued frame/guard has an extra optional span field even when disabled.

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
loss-free snapshots or splice them into a batch. The Rust slot collector removes
the shared producer publication lock, but snapshot contention, other loss causes
and whole-batch collection reliability still require explicit qualification.


## Completion streaming v2

`TRILLIONNIUM_OWNER_TRACE_MODE=streaming-completion` selects a separate codec.
It requires `TRILLIONNIUM_OWNER_TRACE_SAMPLE` and an absolute
`TRILLIONNIUM_OWNER_TRACE_STREAM_OUTPUT` prefix in an existing owner-private
directory. Snapshot output and stream output cannot be mixed. A stream output
without a valid mode, an unsupported mode, or a missing sample is rejected;
entrypoints do not silently fall back to snapshot or default-off success.
Snapshot mode and its 8192-record per-process lifetime are unchanged. The
older begin-order streaming v1 prototype has no compatibility fallback.

Each physical producer names its evidence with role, real PID, Linux process
start ticks and a SHA256 of its boot identifier. This distinguishes Core
process generations under one prefix. Context creation is exclusive; no file
is overwritten. A physical role cannot reinitialize the same generation to
reset a trace. None of these fields proves installed source identity.

The four independent closed-world object schemas are
[context v2](schemas/context.v2.schema.json),
[chunk v2](schemas/chunk.v2.schema.json),
[ACK v2](schemas/ack.v2.schema.json) and
[terminator v2](schemas/terminator.v2.schema.json).
`tools/perf/inspect_monotonic_stream.py` is the strict read consumer. Schemas
validate individual JSON shapes; they do not alone prove file custody,
matching generation/PID, cross-object identity, ordering or complete scope.
The consumer rejects duplicate members, unknown keys, old or mixed versions,
changes during held-FD reads, extra generation files, missing records and
contradictory counts. Use the exact immutable consumer bytes:

```sh
python3 -B tools/perf/inspect_monotonic_stream.py /absolute/private/prefix.role.pid.ticks.boot.context.json
python3 -B -m unittest tools.tests.test_owner_open_monotonic_stream
```

### Start, completion and reuse contract

A successful span start receives one immutable `start_claim_id` and one
resident credit. Pending starts and completed records waiting for ACK share
exactly 1024 credits. They never hold an output bank merely because a scope is
long. `completion_sequence` is assigned when a closed record is admitted to a
bank; it is not a sort of cross-thread end timestamps. A real listener accept
can start first and publish last without renumbering its start identity.

There are two 512-slot completion banks. Sealing preserves every claimed
range; a partially sealed epoch explicitly declares its unused tail through
slot 512. Unused slots are not allocated starts, dropped records or implicit
loss-free records. Before exposing a chunk, all admitted publications must be
closed and present. A publisher retaining a former active bank reselects an
actual available bank within the same finite 512-attempt admission bound;
it does not wait for an exporter, retry an effect or erase a failed span.

Only an immutable exclusive chunk and matching ACK that have passed write,
file fsync, held parent/leaf identity and SHA checks, directory fsync and final
custody/loss checks permit slot clearing and credit return. Slot guards are
dropped before publishing FREE. This ordering is explicit; it does not prove
that a prior observed loss was caused by an early FREE transition. A failed
publication, write, fsync, custody check or late loss retains an incomplete
scope. No drain restarts or silently resumes a sticky failed exporter.

Final source close rejects pending/abandoned/invalid spans, observed loss,
unacknowledged banks and unequal started/published/acknowledged counts. The
consumer verifies unique start IDs exactly cover `[0, started_count)`, ACKs
bind physical chunk FD9/bytes/SHA, and the terminator binds every generation
file and byte. All artifact `trace_complete`, `installed_qualified` and
`producer_quiescence_proven` fields remain false: source close does not prove
whole-process-family quiescence or independent installed custody.

### Separate disk and RAM bounds

Each physical producer has lifetime bounds of 65,536 starts, 256 epochs,
514 files (one context, at most 256 chunk/ACK pairs, one terminator) and 16 MiB
of total physical evidence bytes. Every context, chunk, ACK and terminator is
counted. Metadata objects are capped at 4096 bytes and each chunk at 512 KiB.
Short seals consume an epoch without resetting start IDs; these are ceilings,
not a promise that any workload can reach every ceiling without loss.

RAM admission is independent of that disk bound. Rust owns 1024 slot mutexes
and at most 1024 pending-plus-unACKed bounded records, each with a 64-byte
scope SHA string, bounded sample/role identifiers, and finite parent handles.
The single active exporter may hold up to 512 record clones, a serialized
chunk, ACK metadata and a file-verification read buffer. Python holds at most
1024 pending-plus-unACKed records, each with its bounded record dictionary,
integer objects, SHA string and span object. Its single exporter additionally
holds up to 512 copied record dictionaries and JSON string/UTF-8/read buffers.
The two languages have different object and allocator costs; a record count
is not a one-MiB byte quota. Source-local allocation probes measure requested
Rust allocations and Python `tracemalloc` separately, including a real
1024-pending/512-completed export overlap. They do not measure allocator
metadata, physical RSS, simultaneous producer/exporter families or caller
wire queues and threads.

The proposed aggregate 16 MiB **RAM** budget remains HOLD. It is not this
16 MiB per-producer **disk** bound and is not the planned telemetry module's
resource allowance. Independent accounting must include the actual broker
process, every physical Host/Core generation, simultaneous exporters,
allocator staging, queues and process/thread lifecycle. No new product
background thread or effect resource authority is introduced; the existing
16-owner/32 MiB effect pool remains unchanged.

### Failure and qualification boundary

Rust preserves a saturating lower-bound loss count and an independently
admitted first finite loss phase. Python preserves observed loss with an
unavailable numeric count. Final exporter acquisition busy/poisoned and
physical write/custody failures retain their first phase and bounded message;
an exporter acquiring a lock later cannot replace that cause with a generic
loss error and acknowledge or reuse the retained banks.

These changes preserve the earlier real failed rounds. A prior Host 300-turn
round ended with trace loss whose first loss mechanism was not retained and
remains unknown. A separate deterministic retained-active-index counterexample
proves the bank handoff defect; it does not assign that cause to the historical
round. New source-local 300-turn and Python 1000-request observations are
limited owned protocol evidence. The actual Host 1000-turn run stopped after
420 terminal observations with journal capacity exhaustion and a subsequent
`turn_journal_unavailable`; its exact capacity branch requires separate
resident/read-model diagnosis. It is not replaced by a passing 300-turn run.

Finite buffers can still lose evidence under slow export, insufficient drain
points or long pending spans. Preserve and reject the entire incomplete round;
do not restart/reset producers, discard records, select loss-free fragments or
splice them into a batch. Complete 6000 raw workload samples, workload reset
contracts, real installed execution, full resource lifecycle, family RAM and
L2 remain separate unclosed gates. Normal source contract generation and
accurate fresh candidate verification are also required before integration.
