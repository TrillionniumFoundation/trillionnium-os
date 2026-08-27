# Owner-open process substrate v1

Status: **r4 W2/W3 source slice — validation and Host integration pending**  
Date: **2026-08-27**  
Semantic authority: `docs/contracts/codex-sovereign-direct-tools-v1.json`  
Execution sequencing: `docs/TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md`

## 1. Purpose

This document turns the r3 owner-open shell/ADB decision into an implementable
mechanism boundary. The implementation lives in
`crates/trillionnium-owner-open-runtime` and is deliberately isolated from the
pre-r3 plan, Authority, capability-lease, risk, approval, P01 custody and
closed `shell.exec.v1` broker graphs.

The substrate answers one narrow question:

> Given a mechanically valid request and an already selected execution
> environment, start the exact process, stream the real bytes, maintain bounded
> liveness, terminate the complete process group when required, reap it and
> return one honest terminal observation.

It does **not** decide whether a command is safe, desirable, approved, standard,
destructive or supported by a named target.

## 2. Non-negotiable invariants

1. `shell.exec` accepts either a command string or element-preserving argv.
2. A command string is executed as `<configured shell> -c <command>`.
3. argv bypasses shell parsing: element zero is the executable and all later
   elements are passed unchanged.
4. `adb.exec` starts the configured ordinary adb executable with exact argv,
   excluding the program name.
5. The ADB wrapper never injects `-s`, a host, port, transport, privilege mode,
   timeout policy or known-subcommand restriction.
6. Unknown and future ADB subcommands remain transport-valid.
7. `target_id` is correlation metadata only in this slice. It cannot rewrite
   the process or turn a capability observation into admission policy.
8. cwd, environment, stdin, stdout and stderr are mechanism inputs/outputs;
   their content is not semantically inspected.
9. Every mechanically valid call emits one `accepted`, zero or one `started`,
   zero or more output chunks and exactly one terminal event.
10. Validation failure occurs before `accepted` and therefore proves no spawn
    attempt was made.
11. Spawn failure occurs after `accepted`, before `started`, and is returned as
    `spawn_failed` rather than a semantic denial.
12. Timeout, cancellation and output exhaustion terminate the process group,
    use a bounded TERM-to-KILL grace period and reap the child.
13. Output bytes are never converted through UTF-8. NUL and arbitrary binary
    bytes are retained in the library event.
14. Non-zero exit, signal, missing executable, broken stdin, SELinux denial,
    missing ADB authorization and target errors remain real observations.
15. This slice never retries a process automatically.

## 3. Request model

### 3.1 Common fields

| Field | Meaning | Mechanical validation |
| --- | --- | --- |
| `call_id` | Per-turn call correlation | Non-empty, bounded ASCII identifier |
| `target_id` | Diagnostic/routing correlation | Optional bounded string; no admission effect |
| `cwd` | Child working directory | Optional bounded OS path; no workspace allowlist |
| `env` | Inherited environment delta | String sets, null removes, absent inherits |
| `stdin` | Raw child stdin | Bounded bytes |
| `timeout` | Monotonic call deadline | Zero/absent normalizes to owner default |

Environment keys reject NUL, empty keys and `=` because the operating-system
process API cannot represent them. Values reject NUL for the same mechanical
reason. This is not a key/value policy allowlist.

### 3.2 Shell command form

```text
program = configured shell, default /bin/sh
argv    = ["-c", exact command string]
```

The substrate does not tokenize, normalize, quote, inspect or classify the
command. Selection of a different shell is owner configuration and must be
recorded by the integrated Host as part of the resolved binding fingerprint.

### 3.3 Shell argv form

```text
program = argv[0]
argv    = argv[1..]
```

Empty argv is an invalid frame. Empty individual arguments are valid. The
substrate does not require an absolute executable path and does not reject
shells, interpreters, `env`, `busybox`, package managers, build tools or future
programs.

### 3.4 ADB form

```text
program = configured adb executable, default PATH lookup of "adb"
argv    = exact request argv
```

The following are all valid at this layer:

```text
["devices", "-l"]
["-s", "ZY32JLVHGN", "shell", "id"]
["root"]
["remount"]
["reboot", "recovery"]
["forward", "tcp:9000", "localabstract:service"]
["future-subcommand", "--future-option"]
```

Whether the selected adb binary/server/target accepts an operation is reported
through its stdout, stderr and exit status. The wrapper does not predict it.

## 4. Event model

The library emits events synchronously through one sink callback. Sequence
numbers start at zero and are monotonically increasing for one call.

```text
accepted
started(pid)
stdout(raw bytes) / stderr(raw bytes) ...
terminal
```

Terminal kinds are:

| Kind | Meaning |
| --- | --- |
| `exited` | Process exited normally; exit code is retained, including non-zero |
| `signaled` | Process terminated by a signal not initiated by a higher-priority local condition |
| `timed_out` | Monotonic deadline was observed before a natural terminal state |
| `client_cancelled` | Cancellation was observed before timeout/natural completion |
| `resource_exhausted` | Combined raw output reached the configured bound |
| `spawn_failed` | Program could not be started; no `started` event exists |
| `io_error` | Process supervision/read/reap mechanics failed |

The terminal record also carries exit code, signal, delivered stdout/stderr byte
counts, truncation, elapsed monotonic duration and an optional mechanical error.

## 5. Race and precedence rules

The implementation polls the child and local control state on one supervising
thread. The intended precedence is:

1. A child status already observed by `try_wait` is a natural terminal result.
2. Otherwise, cancellation observed before timeout yields `client_cancelled`.
3. Otherwise, deadline expiry yields `timed_out`.
4. Output exhaustion observed while the child is still active yields
   `resource_exhausted`.
5. A supervision failure may replace the local terminal reason with `io_error`
   because the substrate can no longer make a stronger lifecycle claim.

These are local-process rules only. A future remote/relay ADB transport must use
`unknown_after_disconnect` whenever it cannot establish whether a remote effect
occurred. This crate does not claim remote exactly-once behavior.

## 6. Process lifecycle

Before spawn the child is configured to create a new POSIX process group.
Cancellation, timeout and output exhaustion signal the negative process-group
ID so descendants are included. Supervision then:

1. sends `SIGTERM`;
2. polls until the owner-configured grace deadline;
3. sends `SIGKILL` if still running;
4. waits for and reaps the direct child;
5. drains/joins stdout and stderr reader threads;
6. joins the stdin writer;
7. emits exactly one terminal event.

This closes a major source-level lifecycle gap, but it is not yet equivalent to
Android/Root Linux production custody. PID namespace, cgroup, UID/GID,
capability, seccomp, SELinux, mount namespace and init-respawn integration are
W2 follow-on work.

## 7. Mechanical limits

The default source limits are owner-open liveness defaults, not a safety policy:

- argv elements: 4,096;
- individual argument: 64 KiB;
- total argument bytes: 256 KiB;
- environment entries: 4,096;
- environment delta bytes: 512 KiB;
- stdin: 16 MiB;
- combined delivered output: 16 MiB;
- output chunk: 16 KiB;
- default timeout: 90 seconds;
- TERM grace: 250 ms.

The integrated owner-open config will make these values owner-controlled and
record the effective configuration generation per turn/call. Increasing or
exhausting a limit must never be represented as an authorization decision.

## 8. Test obligations

`crates/trillionnium-owner-open-runtime/tests/runtime.rs` covers:

- raw stdout/stderr, binary NUL and deliberate non-zero exit;
- element-preserving argv with spaces and shell-looking text;
- cwd, set/remove environment and binary stdin;
- timeout and process-group termination;
- cancellation with one spawn and one terminal event;
- output exhaustion and exact delivered-byte cap;
- unknown/future ADB argv without target/serial injection;
- honest spawn failure;
- malformed empty argv rejected before any process event.

Required validation commands are:

```sh
cargo fmt --all -- --check
cargo test --package trillionnium-owner-open-runtime
cargo tree -e features -p trillionnium-owner-open-runtime
```

A green host test raises this slice only to L2. It does not satisfy Android image
or physical-device acceptance.

## 9. Integration plan

### 9.1 Next Host change

`trillionnium-owner-open-host` must translate a correlated provider-native or
wire `tool.call` into these requests, preserve the existing turn/session/call
IDs, forward each output event on the same turn stream and feed the terminal
observation back to the same Codex turn.

The Host integration must add:

- per-call cancellation token lookup;
- duplicate `call_id`/different request-byte rejection;
- in-memory no-double-spawn behavior;
- bounded output backpressure and spool transition;
- conversion of raw bytes to the protocol's canonical binary representation;
- one terminal tool event and one eventual turn terminal;
- source tests proving the old broker/Authority path is not imported.

### 9.2 Root Linux placement

W2 must then run the same process substrate inside the configured Root Linux
namespace with explicit process identity and lifecycle bindings. The acceptance
command remains:

```sh
id; uname -a; command -v adb
```

Killing the owner-open Host/provider must not leave an untracked child process.
Restart must reconnect or honestly report interruption.

### 9.3 Real ADB transport

W3 must supply either:

- an ordinary ARM64 adb client/server in Root Linux; or
- a byte-transparent Android/host relay.

That decision requires a dedicated topology ADR covering server socket, keys,
USB/TCP, unauthorized/offline states, recovery/bootloader, restart and reboot.
This source slice merely proves the no-parser/no-injection process boundary.

## 10. Explicit non-claims

At publication of this source slice, the project does not claim:

- successful Rust 1.93 CI in GitHub Actions; the repository currently has no
  assigned runner for the observed workflow job;
- live Codex invocation or same-turn tool-result continuation;
- owner-open Host integration;
- Root Linux namespace or Android image inclusion;
- a real ARM64 adb client/relay;
- durable replay/resume/reconciliation;
- L4 physical device effect or L5 fault evidence;
- signed/public release readiness.

These holds must remain visible in machine status and PR description until
independently cleared.
