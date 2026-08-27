# Owner-open Direct Agent Host v1 — implementable core protocol

Status: **r4 implementation profile**  
Normative semantic source: `docs/contracts/codex-sovereign-direct-tools-v1.json`  
Codec schema: `schemas/codex-sovereign-direct-tools.schema.json`  
Rust codec: `crates/trillionnium-owner-open-types`

This document extracts the first implementable subset from the larger owner-open
contract. It does not replace the contract and does not create policy. Unknown
fields and tool labels remain transport-valid unless they make the frame
ambiguous or exceed a mechanical resource bound.

## 1. Transport

The first implementation supports newline-delimited UTF-8 JSON over an
inherited stdio bridge or a local Unix-domain socket. Android abstract socket
`@trillionnium_direct_agent_host_v1` is the target integrated carrier;
`/run/trillionnium/direct-agent-host-v1.sock` is the Root Linux alias when the
namespaces share or bridge the same endpoint.

Each line contains exactly one JSON object. The decoder must reject:

- an empty line;
- a line above the configured byte limit;
- invalid UTF-8/JSON;
- trailing non-whitespace JSON data;
- duplicate object members at any nesting depth;
- a non-object `payload`;
- conflicting aliases.

Connection admission is deployment-specific mechanical security. It is not a
semantic action approval.

## 2. Envelope

Minimum envelope:

```json
{
  "kind": "turn.start",
  "seq": 1,
  "payload": {}
}
```

Core optional fields include direction, client/host sequence, event and
connection ids, turn-stream id, session/profile/task/turn ids, call/job ids,
tool, target and frame digest. Unknown fields are retained.

`seq` is the direction-local wire sequence. `client_seq` and `host_seq` may make
the direction explicit. Replayed events keep their stable `event_id` and event
order but may be delivered on a new connection with a new `connection_id`.

When both aliases are present they must be equal:

- `stream_id` and `turn_stream_id`;
- `target` and `target_id`;
- `parent_turn_id` and `continuation_of`.

An alias conflict is `invalid_frame`; the Host must not choose one value.

## 3. Connection lifecycle

A connection has these implementation states:

```text
CONNECTED
  -> optional HELLO_ACKNOWLEDGED
  -> TURN_ACTIVE
  -> TURN_TERMINAL
  -> CLOSED
```

One connection carries at most one active turn. Starting a second active turn
on the same connection is `turn_already_active`. Concurrent turns use separate
connections.

### 3.1 `hello`

`hello` is an optional preface. It may carry protocol version, prior connection,
turn-stream and exactly one resume cursor/token. It cannot supply the new
turn's user input. The Host responds with `hello.ack`, allocating a provisional
connection id and, when appropriate, a provisional turn-stream id.

A resume tuple is valid only when all supplied values refer to the same prior
turn lineage. A missing, expired or inconsistent cursor returns
`resume_unavailable` and does not execute a tool.

### 3.2 `turn.start`

Payload uses `RunTurnRequest`:

```json
{
  "protocol": "trillionnium.agent.turn.v1",
  "protocol_version": 1,
  "session_id": "session-...",
  "profile_id": "owner-open",
  "task_id": "task-...",
  "turn_id": "turn-...",
  "user_input": "..."
}
```

`profile_id` defaults to `owner-open` when absent/null. Session/task/turn fields
mirrored in the envelope must be byte-equivalent to the payload. Correlation is
bookkeeping and replay scope, not permission.

The Host emits `turn.accepted` before provider execution. It emits exactly one
`turn.end` for the turn lineage. A repeated identical `turn.start` within the
same idempotency scope attaches to the existing stream/result; different bytes
under the same turn identity are a conflict.

### 3.3 `turn.cancel`

Requires session and turn identity, either explicit or inherited from the active
connection. Cancellation records the request and attempts provider/tool process
termination. It does not claim that an already dispatched effect did not occur.

## 4. Tool calls

Client wire tool calls require `call_id` and `tool`. Provider-native events may
omit call id only before normalization; the Host must allocate and publish it
before the event becomes a replayable owner-open event.

Core payload:

```json
{
  "call_id": "call-...",
  "tool": "shell.exec",
  "target_id": "rootlinux",
  "command": "pwd",
  "stream": true
}
```

A call emits, in order where available:

```text
tool.accepted
-> tool.started
-> zero or more tool.stdout/tool.stderr/tool.pty chunks
-> exactly one tool.result
```

A duplicate call id with identical request bytes attaches to the current stream
or replays the terminal result. The same call id with different request bytes is
`invalid_frame_call_id_conflict`. The Host never spawns twice merely because a
client reconnected.

## 5. `shell.exec`

Exactly one non-empty input form is required:

```json
{"tool":"shell.exec","command":"printf 'hello\\n'"}
```

or

```json
{"tool":"shell.exec","argv":["/usr/bin/printf","hello\\n"]}
```

`command` is interpreted by the owner-configured shell. `argv` is passed
without shell parsing. Neither form is a fallback or exceptional mode.

Optional mechanics:

- `cwd`;
- `env`, where string overrides, null unsets, and unspecified inherits;
- `stdin` as UTF-8, base64, named FD or spool reference;
- `timeout_ms`, with zero/null meaning owner-configured default;
- `pty` boolean/object;
- `stream` boolean;
- opaque target/mode/config extensions.

Mechanical rejection includes NUL in process strings, unrepresentable
environment keys, negative timeout, frame/resource overflow and ambiguous
command+argv. It must not include executable allowlists, risk classes or command
meaning.

## 6. `adb.exec`

Payload carries a non-empty raw argv excluding the program name:

```json
{
  "call_id": "call-adb",
  "tool": "adb.exec",
  "argv": ["shell", "id"]
}
```

Unknown subcommands are valid. The wrapper does not inject `-s`, server socket,
host, port, transport, root mode or an alternative command. When target is
absent, ordinary configured adb behavior applies.

Raw stdout/stderr/exit/transport observations are returned. `offline`,
`unauthorized`, `more than one device`, `adbd cannot run as root`, missing
server and USB errors must not be renamed to a semantic HOLD or denial.

## 7. Binary output

Stored event bytes are authoritative. JSON transport uses one explicit binary
encoding field, normally RFC 4648 base64, and records the unencoded byte count.
A presentation client may render UTF-8 when valid but must not change the stored
bytes or digest.

Without PTY, stdout and stderr are independent streams. With PTY, output is one
raw PTY stream; the Host does not normalize echo or CR/LF.

## 8. Flow control

The client may set an initial window and send:

- `stream.window_update` with an absolute available-byte window;
- `stream.pause`;
- `stream.resume` with exactly one inclusive cursor/token.

Pause stops delivery, not execution. When memory delivery is blocked, the Host
spools where configured. If spooling is unavailable, it reports output loss or
resource exhaustion truthfully; it does not reinterpret the command.

## 9. Timeouts, signals and cancellation

Timeout uses a monotonic clock beginning with the accepted record. The first
observed terminal condition wins. Terminal result records:

- exit code or signal;
- whether timeout/cancel was requested;
- whether a signal was delivered;
- whether the process group was observed gone;
- output completeness/spool state;
- event-store status;
- uncertainty if the process/target state cannot be established.

## 10. Persistence and uncertainty

P0 attempts records in this order:

```text
accepted -> started -> chunks -> terminal
```

If storage is unavailable, the Host may continue the owner-open call and marks
it `best_effort`/`unreplayable`. After restart:

- terminal record: replay terminal and chunks;
- started without terminal: inspect process/transport evidence, otherwise
  `unknown_after_disconnect`;
- accepted with explicit proof no spawn attempt: `not_started`;
- no record where dispatch could have begun: `unknown_after_disconnect`.

No case permits automatic uncertain-effect redispatch.

## 11. Stable error classes

Initial implementation error classes:

- `invalid_frame`;
- `invalid_frame_call_id_conflict`;
- `frame_too_large`;
- `resource_exhausted`;
- `provider_unavailable`;
- `transport_unavailable`;
- `io_error`;
- `timed_out`;
- `client_cancelled`;
- `unknown_after_disconnect`;
- `resume_unavailable`;
- `turn_already_active`.

Backend stderr is not replaced by these classes. The class describes the Host
observation while raw bytes remain attached when available.

## 12. Compatibility

The owner-open carrier does not use legacy `AgentApiRequest`, `submit_plan`,
`run_tool`, plan approval, risk tier, Capability Lease, shell broker
registration or typed ADB request enums. A bridge may translate transport bytes
only when translation is lossless and does not add semantic decisions. The
legacy API remains an explicit sealed/history profile until removed.

## 13. Foundation implementation boundary

The initial r4 Host implements strict frames, stdio/filesystem UDS, `hello`, a
single synchronous `turn.start`, correlated provider events, `turn.cancel` and
honest `provider_unavailable`. It does **not** yet claim Android abstract-socket
admission, live Codex, direct shell, raw ADB, durable replay, asynchronous
cancellation, flow control or device integration.

## 14. Required test vectors

The codec and Host suites must cover:

- duplicate keys at envelope and nested payload levels;
- trailing JSON and oversized frame;
- unknown extension round trip;
- alias equality/conflict;
- string/integer protocol version;
- turn correlation conflict;
- command-only, argv-only, neither and both;
- unknown ADB subcommand with no target;
- NUL and environment encoding failures;
- boundary-size argv and frames;
- binary output chunk examples;
- duplicate call replay and byte-conflict;
- resume cursor/token combinations;
- timeout/cancel/exit race models.
