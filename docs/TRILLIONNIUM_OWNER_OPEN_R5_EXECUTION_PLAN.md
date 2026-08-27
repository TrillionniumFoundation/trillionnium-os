# Trillionnium OS owner-open execution plan

Revision: **2026-08-28-r5**  
Status: **ACTIVE — the only implementation sequencing and closeout plan**  
Semantic baseline: `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`, revision `2026-08-27-r3`  
Prior execution plan: `TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md`  
Machine status: `status/owner-open-r5-status.json`  
Traceability: `status/owner-open-r5-traceability.tsv`

## 0. Authority

R3 remains normative for product semantics: Codex is the only semantic control
plane; owner-open shell and ADB are direct primitives; the substrate owns only
framing, process, transport, storage, liveness and recovery mechanics. R5
supersedes R4 for implementation order, source closure, evidence promotion and
what the project builds next.

No source file, authored test, schema, receipt or historical device observation
may promote a capability beyond evidence actually captured against the exact
commit. In particular:

- authored Rust tests are not a Rust test pass;
- a host process test is not an Android image result;
- a fake `adb` executable is not a physical ADB effect;
- a local shell process is not proof of Root Linux placement;
- a completed source graph is not proof of clean target-files;
- owner-authorized dogfood is not public-release qualification.

## 1. R5 critical-path outcome

R5 closes the first executable, controllable same-turn loop:

```text
owner/AiShell turn.start
  -> one owner-open Host connection
  -> one Codex/provider semantic turn worker
  -> provider model/status event
  -> provider tool call
  -> exact shell command/argv or ordinary adb argv
  -> raw stdout/stderr/terminal observation
  -> observation returned to the same provider turn
  -> provider continues and produces final model output
  -> exactly one turn terminal

parallel control path:
client frame reader
  -> correlated turn.cancel or tool.cancel
  -> turn token or scoped call registry
  -> provider/tool process-group cancellation
  -> truthful cancelled observation
```

The loop must preserve uncertainty. An exact duplicate call attaches to a
known local call; a changed request under the same scoped call ID conflicts; an
uncertain remote effect is not automatically repeated; a missing terminal after
restart becomes inspectable or `unknown_after_disconnect`.

Provider, tool and control events must not wait in a complete-turn vector before
becoming observable. The Host persists and attempts delivery as each event is
produced. Loss of the client output path detaches delivery; it does not
retroactively cancel an accepted effect. Cancellation is a distinct correlated
control operation with its own acknowledgement and terminal observation.

## 2. Non-negotiable engineering invariants

### 2.1 One semantic principal

Codex chooses intent, context, tool, target, command, retry, compensation and
the meaning of an observation. No owner-open component may reconstruct a plan,
assign a risk class, require a semantic approval lease, rewrite a command,
inject an ADB serial/host/port, select a weaker target or silently choose another
provider.

### 2.2 Mechanism safety remains mandatory

The source closure must provide:

- duplicate-member-safe and bounded framing;
- exact connection/turn/call correlation;
- finite argv, environment, stdin, output, process, queue and spool ceilings;
- process groups, cancellation, timeout and child reaping;
- byte-preserving stdout/stderr and later PTY transport;
- stable accepted/started/chunk/control/terminal observations;
- per-event best-effort persistence and honest delivery status;
- conservative disconnect and restart reconciliation;
- explicit local peer/socket admission on Android;
- an out-of-band emergency stop.

These are mechanical constraints. They must not become semantic allow/deny
policy.

### 2.3 Exact R5 source closure

An unqualified Cargo build/test may include only:

```text
apps/trillionnium-owner-open-host
crates/trillionnium-owner-open-types
crates/trillionnium-owner-open-runtime
crates/trillionnium-owner-open-call-registry
crates/trillionnium-owner-open-event-store
crates/trillionnium-owner-open-provider-jsonl
crates/trillionnium-owner-open-tool-bridge
crates/trillionnium-owner-open-turn-loop
```

The Host package disables automatic binary discovery. Only these binary roots
are selected:

```text
trillionnium-owner-open-host    -> src/main.rs
trillionnium-owner-open-r5-host -> src/bin/r5_control_host_v2.rs
```

Superseded `r5_host`, streaming-only and first control-carrier experiments may
remain as unselected history, but must not enter `--all-targets` implicitly.
The exact machine gate is
`docs/contracts/owner-open-forbidden-default-graph-v2.json`.

Legacy `trillionniumd`, plan/Authority, privilege broker, broad OS types, typed
direct tools, sealed shell broker, egress and journal packages remain explicit
history/sealed targets. They may not enter owner-open defaults through a
workspace default, feature unification or unreviewed internal dependency.

## 3. Evidence vocabulary

| Status | Meaning |
| --- | --- |
| `NOT_STARTED` | No current normative implementation artifact. |
| `SPEC_ONLY` | Requirements exist; source behavior is not claimed. |
| `SOURCE_IMPLEMENTED` | Source is authored and structurally reviewed; no executed behavior claim. |
| `HOST_TESTED` | Exact source passed relevant unit/process integration tests. |
| `IMAGE_INCLUDED` | Exact artifact is present in a clean Android target-files build. |
| `DEVICE_OBSERVED` | Required effect was observed on the authorized physical device. |
| `FAULT_TESTED` | Required crash/disconnect/reboot/ENOSPC/power-loss cases passed. |
| `RELEASE_QUALIFIED` | Separate signed release profile and evidence are complete. |

Evidence levels:

- **L0:** parsed contract, source graph and source-shape checks;
- **L1:** unit/property/fuzz tests;
- **L2:** real host processes, pipes, sockets, cancellation and replay;
- **L3:** clean Android image, Soong/init/SELinux and target-files evidence;
- **L4:** physical same-turn shell and ADB effect;
- **L5:** provider/Host crash, disconnect, USB loss, reboot, ENOSPC and power loss;
- **L6:** signed public-release qualification.

## 4. Work packages

### W0 — source and product graph isolation

Deliverables:

1. exact R5 Cargo default closure;
2. package-by-package reviewed internal dependency edges;
3. explicit Host binary targets with Cargo autobin discovery disabled;
4. negative source-marker checks;
5. Android owner-open product profile with Authority/lease/P01/old broker nodes absent;
6. Soong, init, SELinux and target-files negative evidence.

Exit: source closure is `HOST_TESTED`; Android closure is `IMAGE_INCLUDED`.

### W1 — same-turn provider/tool loop and active controls

Deliverables:

1. provider emits model/status events;
2. provider invokes a bound tool callback;
3. direct bridge executes one shell/ADB process at most once;
4. raw runtime events return to the provider;
5. every turn/runtime event reaches a synchronous Host sink when produced;
6. provider may continue after a non-zero or cancelled tool result;
7. bounded input/control reader remains serviceable while the turn worker runs;
8. correlated `turn.cancel` reaches the turn token and provider;
9. targeted `tool.cancel` reaches the scoped call registry only;
10. client EOF does not imply cancellation;
11. exactly one turn terminal is emitted;
12. provider panic/failure becomes one truthful terminal.

Current source roots:

- `crates/trillionnium-owner-open-turn-loop`;
- `apps/trillionnium-owner-open-host/src/bin/r5_control_host_v2.rs`.

Immediate acceptance tests:

- failed shell observation followed by provider continuation;
- provider event sink runs before `ProviderHost::emit` returns;
- runtime `started` reaches the sink before the process completes;
- exact duplicate call causes one process effect and one existing-call event;
- ordinary ADB unknown argv remains exact and receives no target injection;
- `turn.cancel` is accepted while a shell process runs and the provider returns
  a cancelled turn;
- `tool.cancel` cancels only the target call and provider reasoning continues;
- provider panic closes one terminal;
- conflicting canonical request under the same scoped call ID does not spawn.

Exit: fake provider through the selected Host reaches `HOST_TESTED`, including
streaming, detached-delivery and active-control process tests.

### W2 — external and installed Codex provider adapter

Deliverables:

1. bounded external provider JSONL process protocol;
2. provider event/tool-call/tool-result duplex transport;
3. explicit correlated `turn.cancel` and `turn.cancelled` exchange;
4. finite cancellation grace and provider process-group cleanup;
5. probe the installed CLI/app-server instead of using a source version label;
6. record executable path/hash/version/help capabilities;
7. build an auditable full-access launch argv;
8. normalize native provider JSON events without parsing terminal prose;
9. map native provider tool calls into W1;
10. return tool observations to the same native provider turn.

Exit: a live Codex turn performs shell success, deliberate shell failure, raw
ADB observation and final model continuation at L2; later the same sequence is
observed on device at L4.

### W3 — direct shell substrate

Deliverables:

- command-string and element-preserving argv;
- cwd, inherited environment delta and binary stdin;
- stdout/stderr byte streaming;
- PTY/session/resize support;
- process groups, timeout, signal and cancellation;
- output/spool limits and descendant cleanup;
- configured Root Linux UID/GID/namespace/cgroup placement.

Exit: host L2 process suite, then physical Root Linux L4 observation.

### W4 — ordinary raw ADB substrate

Deliverables:

- explicit topology ADR: real ARM64 client/server or byte-transparent relay;
- exact argv excluding program name;
- no serial/host/port/privilege injection;
- unknown/future subcommands remain transport-valid;
- USB/offline/unauthorized/recovery/reboot observations remain raw;
- conservative disconnect/reconnect state;
- the same targeted cancellation and process lifecycle mechanics as shell.

Exit: physical `adb devices -l`, `adb shell id`, deliberate failure and one
visible device mutation in the same Codex turn.

### W5 — event store, replay and recovery APIs

Deliverables:

- append-only accepted/started/chunk/control/terminal records;
- explicit `best_effort`/`unreplayable` storage state;
- stable event IDs and inclusive cursors;
- event-by-event persistence while provider/tools are active;
- completed-call replay without re-execution;
- incomplete-call reconciliation to `unknown_after_disconnect` where needed;
- client-delivery detach without cancellation of accepted effects;
- turn/call inspect operations;
- long-running job inspect/attach/write/resize/close/kill;
- bounded retention and explicit cleanup.

Immediate acceptance tests:

- a provider event is visible in the durable file while the provider remains
  blocked before terminal;
- a closed client output pipe does not stop provider execution or terminal
  persistence;
- completed replay does not start a second provider process;
- incomplete replay persists `unknown_after_disconnect` before delivery and
  never automatically redispatches;
- turn/tool cancellation acknowledgement is persisted before the resulting
  terminal observation.

Exit: L2 streaming/control/replay/restart tests and L5 fault matrix.

### W6 — Android/Root Linux integration and AiShell

Deliverables:

- clean owner-open product make/Soong profile;
- one init-owned Host, Android abstract socket and SELinux admission;
- no startup dependency on Authority, lease, egress, P01 or old shell broker;
- Root Linux writable overlay and restart lifecycle;
- thin AiShell turn client, event rendering, cancel, reconnect and inspect;
- out-of-band emergency stop capable of inhibiting respawn.

Exit: clean target-files L3 and physical normal-path L4.

### W7 — qualification, self-development and optional release

Deliverables:

- exact source/manifest/feature/Soong/rootfs/provider/image/device bindings;
- provider/Host/client disconnect tests;
- USB loss, reboot, ENOSPC and power-loss tests;
- Codex build/install/update/recover dogfood loop;
- separate optional sealed/public profile, signing, AVB/rollback, OTA and
  multi-user review.

Owner-open dogfood exits at L4/L5. Public release requires separate L6 and may
not block owner-open development.

## 5. Implementation batches

### Batch A — graph and direct-process foundation

Source-authored:

- exact R5 graph contract and verifier;
- direct shell and ordinary ADB process runtime;
- scoped call registry and registry-to-runtime bridge;
- same-turn callback loop and external provider JSONL adapter.

Promotion hold: exact Rust runner output is still absent.

### Batch B — durable replay foundation

Source-authored:

- append-only durable event store;
- stable semantic request digest and turn-stream identity;
- completed replay without redispatch;
- incomplete reconciliation to `unknown_after_disconnect`.

Promotion hold: replay and fault tests have not executed on a real runner.

### Batch C — streaming, detached delivery and active controls

Source-authored:

- synchronous turn-event sink;
- runtime event forwarding while a process is active;
- per-event Host persistence and flush;
- detached client delivery without effect cancellation;
- bounded input/control reader and independent turn worker;
- active correlated `turn.cancel`;
- targeted active `tool.cancel`;
- provider JSONL cancellation acknowledgement and finite cleanup grace;
- explicit Host binary selection with autobin discovery disabled.

Current acceptance gate:

1. obtain a runner that executes Rust 1.93;
2. fix every format, compile, test and clippy finding;
3. bind exact command output and generated lock to the commit;
4. do not promote beyond L0 until those records exist.

### Batch D — next source development

- add inclusive replay cursors and `turn.inspect`/`call.inspect` APIs;
- add bounded stream window, pause and resume behavior;
- add durable long-running jobs and attach/write/resize/close/kill;
- define multi-connection ownership and cross-connection control correlation;
- bind the installed Codex provider;
- implement the selected real ADB topology.

### Batch E — Android and physical qualification

- cut the Android owner-open product graph;
- wire init/SELinux/abstract socket/AiShell;
- build clean target files;
- collect L4 and L5 evidence.

## 6. Definition of owner-open dogfood done

Owner-open dogfood is complete only when one evidence package proves:

1. one Android-started owner-open Host and no forbidden legacy semantic node;
2. one physical Codex turn invokes Root Linux shell and ordinary raw ADB;
3. raw tool events return to that same turn and Codex continues;
4. exact duplicate local calls do not spawn twice;
5. uncertain effects are never blindly re-dispatched;
6. client/provider/Host failure, USB loss and reboot yield inspectable truth;
7. emergency stop works without Codex/provider availability;
8. Codex can build, install, inspect and recover the dogfood userland;
9. evidence binds exact source, Android manifest/patches, Cargo graph, Soong
   graph, rootfs, provider runtime, target files and device fingerprint.

Until those facts exist, status remains implementation-in-progress and public
release remains false.
