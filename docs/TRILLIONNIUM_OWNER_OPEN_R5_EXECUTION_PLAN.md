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

No source file, test source, schema, receipt or historical device observation
may promote a capability beyond evidence actually captured against the exact
commit. In particular:

- authored Rust tests are not a Rust test pass;
- a host process test is not an Android image result;
- a fake `adb` executable is not a physical ADB effect;
- a local shell process is not proof of Root Linux placement;
- a completed source graph is not proof of clean target-files;
- owner-authorized dogfood is not public-release qualification.

## 1. R5 critical-path outcome

R5 closes the first executable same-turn loop:

```text
owner/AiShell turn.start
  -> one owner-open Host connection
  -> one Codex/provider semantic turn
  -> provider model/status event
  -> provider tool call
  -> exact shell command/argv or ordinary adb argv
  -> raw stdout/stderr/terminal observation
  -> observation returned to the same provider turn
  -> provider continues and produces final model output
  -> exactly one turn terminal
```

The loop must preserve uncertainty. An exact duplicate call attaches to a
known local call; a changed request under the same scoped call ID conflicts; an
uncertain remote effect is not automatically repeated; a missing terminal after
restart becomes inspectable or `unknown_after_disconnect`.

## 2. Non-negotiable engineering invariants

### 2.1 One semantic principal

Codex chooses intent, context, tool, target, command, retry, compensation and
the meaning of an observation. No owner-open component may reconstruct a plan,
assign a risk class, require a semantic approval lease, rewrite a command,
inject an ADB serial/host/port, select a weaker target or silently choose another
provider.

### 2.2 Mechanism safety remains mandatory

The source closure must still provide:

- duplicate-member-safe and bounded framing;
- exact connection/turn/call correlation;
- finite argv, environment, stdin, output, process and spool ceilings;
- process groups, cancellation, timeout and child reaping;
- byte-preserving stdout/stderr and later PTY transport;
- stable accepted/started/terminal observations;
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
crates/trillionnium-owner-open-tool-bridge
crates/trillionnium-owner-open-turn-loop
```

Legacy `trillionniumd`, plan/Authority, privilege broker, broad OS types, typed
direct tools, sealed shell broker, egress and journal packages remain explicit
history/sealed targets. They may not enter the owner-open defaults through a
workspace default, feature unification or an unreviewed internal dependency.

The exact machine gate is
`docs/contracts/owner-open-forbidden-default-graph-v2.json`.

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
3. negative source-marker checks;
4. Android owner-open product profile with Authority/lease/P01/old broker nodes absent;
5. Soong, init, SELinux and target-files negative evidence.

Exit: source closure is `HOST_TESTED`; Android closure is `IMAGE_INCLUDED`.

### W1 — same-turn provider/tool loop

Deliverables:

1. provider emits model/status events;
2. provider invokes a bound tool callback;
3. direct bridge executes one shell/ADB process at most once;
4. raw runtime events return to the provider;
5. provider may continue after a non-zero tool exit;
6. exactly one turn terminal is emitted;
7. provider panic/failure becomes one truthful terminal.

Current source root:
`crates/trillionnium-owner-open-turn-loop`.

Immediate acceptance tests:

- failed shell observation followed by provider continuation;
- exact duplicate call causes one process effect and one existing-call event;
- ordinary ADB unknown argv remains exact and receives no target injection;
- provider panic closes one terminal;
- conflicting canonical request under the same scoped call ID does not spawn.

Exit: fake provider through a real Host process reaches `HOST_TESTED`.

### W2 — installed Codex provider adapter

Deliverables:

1. probe the installed CLI/app-server instead of using a source version label;
2. record executable path/hash/version/help capabilities;
3. build an auditable full-access launch argv;
4. normalize provider JSON events without parsing terminal prose;
5. map native provider tool calls into W1;
6. return tool observations to the same native provider turn;
7. cancel provider and active local process groups.

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
- conservative disconnect/reconnect state.

Exit: physical `adb devices -l`, `adb shell id`, deliberate failure and one
visible device mutation in the same Codex turn.

### W5 — event store, replay and recovery

Deliverables:

- append-only accepted/started/chunk/terminal records;
- explicit `best_effort`/`unreplayable` storage state;
- stable event IDs and inclusive cursors;
- completed-call replay without re-execution;
- incomplete-call reconciliation to `unknown_after_disconnect` where needed;
- long-running job inspect/attach/write/resize/close/kill;
- bounded retention and explicit cleanup.

Exit: L2 replay/restart tests and L5 fault matrix.

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

## 5. Immediate implementation batches

### Batch A — current change

- repair graph/status drift introduced when registry and tool bridge entered
  Cargo defaults;
- add exact R5 graph contract and verifier;
- add W1 same-turn callback loop and source tests;
- add CI commands for format/test/clippy and graph capture;
- keep status at L0 until a runner returns exact command output.

### Batch B — next

- execute Rust 1.93 format/test/clippy on the exact commit;
- fix every compiler, race and failure-closure defect;
- import W1 behind the Host provider boundary;
- replace vector-return provider events with serviceable streaming controls;
- add fake external provider JSONL process integration.

### Batch C

- bind the installed Codex provider;
- add durable event store/reconciliation;
- implement the selected real ADB topology;
- collect a complete host L2 same-turn evidence package.

### Batch D

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
