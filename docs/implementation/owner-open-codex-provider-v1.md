# Owner-open Codex provider v1

Status: **r4 W1 implementation specification; help probe source authored**  
Date: **2026-08-27**  
Semantic contract: `docs/contracts/codex-sovereign-direct-tools-v1.json`  
Execution plan: `docs/TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md`

## 1. Purpose

The owner-open Host must launch and supervise one installed Codex provider,
stream provider events, observe its tool calls, execute those tools through the
mechanism substrate and return observations to the same turn. The provider
adapter must not infer current CLI behavior from a source asset name, stale
version constant or historical documentation.

W1 therefore uses four explicit gates:

```text
W1.0 installed CLI help observation
  -> W1.1 auditable launch prefix
  -> W1.2 fake provider JSONL lifecycle
  -> W1.3 live Codex bootstrap turn
  -> W1.4 integrated same-turn shell/ADB
```

No earlier gate may be presented as a later capability.

## 2. W1.0 — installed CLI help observation

Canonical source: `tools/owner-open/probe_codex_cli.py`.

The probe performs only:

```text
<codex> --version
<codex> --help
<codex> exec --help
```

It records:

- real executable path, device/inode, UID/GID, mode, byte size and SHA-256;
- raw stdout/stderr, byte counts and hashes for each probe;
- observed version text;
- whether help exposes an `exec` subcommand;
- whether exec help exposes JSON event transport;
- whether help exposes sandbox/full-access or bypass modes;
- whether model and configuration override options are visible.

It does not:

- execute `codex exec`;
- provide a prompt;
- open a credential file;
- contact an OpenAI/provider endpoint;
- start MCP or another tool server;
- assert that a help option works at runtime;
- assert same-turn or device capability.

The only valid claim ceiling is:

```text
INSTALLED_CLI_HELP_OBSERVATION_ONLY
```

### Executable boundary

The probe refuses a symlink, empty/unlinked file, non-executable file,
group/world-writable file, file larger than 512 MiB or an executable that
changes while measured. These are mechanical executable-identity checks, not
provider admission or a fixed product UID policy.

### Probe boundary

Each command has one absolute 10-second timeout and a 1 MiB combined output
bound. A non-zero exit, invalid UTF-8, timeout or oversized output is a raw probe
failure. The probe does not fall back to a different executable or older flag
set.

### Evidence publication

A requested report is written with temp/create, file fsync, mode 0600, atomic
replace and parent-directory fsync. Its claims explicitly keep credentials,
provider contact, model invocation, exec turn, MCP, Host integration, same-turn
effect and release evidence false.

## 3. W1.1 — auditable launch prefix

The next source component consumes a W1.0 report and an owner launch policy. It
produces, but does not execute, a launch prefix:

```text
<measured executable> exec <observed JSON option> <observed owner-open option>
```

### Required inputs

- exact W1.0 report digest;
- expected executable SHA-256;
- selected access mode;
- optional model/config overrides;
- owner-open configuration generation;
- working directory and environment/credential-FD policy;
- prompt-delivery mode selected by a separately tested adapter.

### Access-mode selection

Supported policy labels are:

| Policy | Required observed help | Emitted prefix behavior |
| --- | --- | --- |
| `bypass-approvals-and-sandbox` | bypass flag visible | use that exact long option |
| `danger-full-access` | sandbox option and value visible | use the observed sandbox option/value |
| `auto-owner-open` | at least one of the above | deterministic preference recorded in plan |

No mode is synthesized when help lacks a required option. Unsupported option is
`provider_configuration_error`, not a reason to hide shell/ADB from Host health.

### JSON transport

An exec JSON option must be observed before the adapter claims JSON event
transport. Help observation proves only that an option is advertised. W1.2 and
W1.3 must still prove actual framing and event behavior.

### Model/config options

A model or config override may be added only when:

1. the owner explicitly configured it;
2. the corresponding option was observed;
3. the complete emitted argv is recorded;
4. secret values are not placed in the model prompt or evidence.

The provider adapter must not silently merge an unrelated operator Codex
profile.

## 4. W1.2 — fake provider JSONL lifecycle

Before invoking a real provider, a fixture executable must exercise the entire
Host adapter:

1. emit a provider/session start event;
2. emit streamed model text;
3. emit one shell tool call;
4. receive raw stdout/stderr/exit observation;
5. emit more model text;
6. emit a deliberate failing command;
7. receive its non-zero observation;
8. continue and emit one final turn event;
9. respond to cancellation and malformed output.

### Required tests

- partial JSONL reads and multiple records per read;
- duplicate members and oversized records;
- unknown events are preserved as opaque provider events;
- one tool call maps to one Host call ID and one process spawn;
- same provider call bytes after reconnect attach/replay local state;
- same call ID with different bytes is conflict;
- provider EOF before terminal is `provider_interrupted`;
- invalid provider event is `provider_protocol_error`;
- stderr is bounded and remains diagnostic;
- provider process group is closed on timeout/cancel/Host teardown;
- tool failure does not force provider failure when the provider continues.

W1.2 proves the adapter mechanics only. It does not contact a real model.

## 5. W1.3 — live Codex bootstrap turn

A live bootstrap may run only after W1.0/W1.1 are captured against the installed
binary and W1.2 is green.

### Minimal sequence

The live provider must:

- start using the exact measured executable and recorded argv/environment;
- emit machine-readable events rather than parsed terminal prose;
- return model text for a no-tool prompt;
- execute a harmless temporary-file shell call through the owner-open runtime;
- observe a deliberate non-zero command and continue;
- terminate or cancel cleanly;
- record provider version/model/endpoint/config generation as correlation facts.

### Credentials

Credentials remain owner configuration or explicitly inherited FDs. The probe
and launch-plan generator never open them. The provider child may access only
the credential mechanism deliberately configured for that run. Raw secrets are
excluded from evidence and prompts.

### Network

Owner-open network is owner configured. A provider outage, DNS/TLS error,
account error or unsupported model is returned as a real provider observation.
The Host does not switch providers or local models silently.

## 6. W1.4 — integrated same-turn tool loop

W1 is complete only when one live Codex turn:

```text
user input
  -> provider event stream
  -> shell.exec / adb.exec tool call
  -> owner-open process runtime
  -> raw output/terminal event
  -> same provider turn
  -> final model text
```

### Correlation

Every provider event is normalized into:

```text
session_id
profile_id
 task_id
 turn_id
 turn_stream_id
 connection_id
 provider_session_id
 call_id
 provider_native_call_id
 parent_call_id
 event_id
 client_seq / host_seq
```

Missing provider-native IDs are allocated by the Host inside the already
correlated turn and recorded. They are never inferred from model prose.

### Tool ownership

Codex chooses tool, command, argv, target, retry and meaning. The Host/process
substrate owns only correlation, process/transport/storage/liveness and honest
observations. No plan, risk, approval, Authority or typed ADB hop is introduced.

### Cancellation

- `turn.cancel` requests provider and active-call cancellation;
- `tool.cancel` targets one correlated call;
- first observed terminal condition wins locally;
- remote/ADB effects are not guessed;
- an uncertain mutating call is never automatically repeated.

## 7. Host/provider boundary

The adapter should implement a small interface rather than importing the old
`SupervisedCodexProvider` graph:

```text
probe() -> ProviderCapabilities
start_turn(RunTurnRequest, EventSink, CancellationToken)
  -> ProviderTurnTerminal
```

The provider process adapter may be an independent process/stdio component for
initial dogfood. It must not depend on:

- `trillionnium-tool-runtime::supervised_codex`;
- capability issuer/token types;
- egress journal/guard;
- P01 final runtime measurement;
- plan submission or Authority receipts;
- `trillionnium-shell-exec` registration leases;
- typed ADB contracts.

Mechanical executable measurement may be reused in a smaller owner-open module
without carrying those semantic dependencies.

## 8. Event and output bounds

Initial owner defaults:

- provider stdout line/frame: 1 MiB;
- aggregate live provider stdout before spool: 16 MiB;
- provider stderr: 1 MiB;
- provider start timeout: 30 seconds;
- no-tool turn timeout: 5 minutes;
- tool call timeout: supplied by tool request/owner default;
- cancellation grace: owner configured;
- one active turn per connection.

These are liveness controls. Exhaustion is a raw mechanical/provider error and
must not be renamed as semantic refusal.

## 9. Version and compatibility

Source must not hard-code a CLI version as admission identity. Every run records
the actual observed version and executable hash. Compatibility is determined by
probe capabilities and executable integration tests.

A new CLI version invalidates prior executable-bound help evidence. It does not
rotate the semantic Agent principal; it requires a new W1.0/W1.1 observation
and affected W1.2/W1.3 tests.

## 10. Required evidence ladder

| Level | Proof |
| --- | --- |
| L1 | probe/launch source and fake executable tests |
| L2 | fake JSONL provider through Host/runtime |
| L3 | exact provider executable/config included in Root Linux/image graph |
| L4 | live Codex same-turn shell and raw ADB on authorized device |
| L5 | provider crash, timeout, disconnect, credential/network failure, reboot and recovery |
| L6 | separate public release qualification |

## 11. Current status

Authored:

- `tools/owner-open/probe_codex_cli.py`;
- fake CLI normal, non-zero, timeout, oversized-output, symlink/mode and atomic
  report tests;
- this implementation specification;
- machine status and source evidence.

Not claimed:

- tests have executed in Rust/Python CI on a real runner;
- any installed Codex binary has been probed;
- an exec prefix has been generated;
- a model/provider has been contacted;
- JSON event transport has run;
- a live Codex turn or same-turn tool effect exists;
- Android/Root Linux inclusion or release qualification.
