# Trillionnium OS owner-open execution plan

Revision: **2026-08-28-r5**  
Status: **ACTIVE — L1 source closure complete; L2–L6 qualification remains**  
Semantic baseline: `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`, revision `2026-08-27-r3`  
Prior execution plan: `TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md`  
Machine status: `status/owner-open-r5-status.json`  
Traceability: `status/owner-open-r5-traceability.tsv`  
Exact L1 evidence: `evidence/2026-08-28-owner-open-r5-exact-source-closeout.md`

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

The exact source candidate `fa1d287103c46aff35cf5e95addbc18da8a92063`
passed the complete Python and Rust source closure on GitHub Actions run
`33186972324`. This promotes the reviewed source slice to `HOST_TESTED / L1`.
It does **not** promote installed Codex, Root Linux placement, Android image,
physical ADB, device fault or public-release claims.

## 1. R5 critical-path outcome

R5 closes the first executable, controllable same-turn loop:

```text
owner/AiShell turn.start
  -> optional same-UID filesystem Unix connection broker
  -> v5 bounded transport carrier
  -> job-aware v7 owner-open core
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
  -> correlated turn.cancel, tool.cancel or job control
  -> turn token, scoped call registry or durable job runtime
  -> provider/tool/job process-group control
  -> truthful acknowledgement and terminal observation
```

The loop must preserve uncertainty. An exact duplicate call attaches to a
known local call; a changed request under the same scoped call ID conflicts; an
uncertain remote effect is not automatically repeated; a missing terminal after
restart becomes inspectable or `unknown_after_disconnect`.

Provider, tool, job and control events must not wait in a complete-turn vector
before becoming observable. The Host persists and attempts delivery as each
event is produced. Loss of the client output path detaches delivery; it does not
retroactively cancel an accepted effect. Cancellation and job controls are
distinct correlated operations with their own acknowledgements and terminal
observations.

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
- exact connection/turn/call/job correlation;
- finite argv, environment, stdin, output, process, queue, window and spool ceilings;
- process groups, cancellation, timeout and child reaping;
- byte-preserving stdout/stderr and PTY transport;
- stable accepted/started/chunk/control/terminal observations;
- persist-before-delivery where durable operation is configured;
- conservative disconnect and restart reconciliation;
- no automatic redispatch after uncertainty;
- explicit local peer/socket admission on Android;
- an out-of-band emergency stop.

These are mechanical constraints. They must not become semantic allow/deny
policy.

### 2.3 Exact R5 source closure

The default Cargo closure is exactly:

```text
apps/trillionnium-owner-open-host
crates/trillionnium-owner-open-call-registry
crates/trillionnium-owner-open-event-store
crates/trillionnium-owner-open-job-registry
crates/trillionnium-owner-open-job-runtime
crates/trillionnium-owner-open-provider-jsonl
crates/trillionnium-owner-open-runtime
crates/trillionnium-owner-open-stream-window
crates/trillionnium-owner-open-tool-bridge
crates/trillionnium-owner-open-turn-loop
crates/trillionnium-owner-open-types
```

The Host package disables automatic binary discovery. The selected binary roots
are exactly:

```text
trillionnium-owner-open-host    -> src/main.rs
trillionnium-owner-open-r5-core -> src/bin/r5_control_host_v7.rs
trillionnium-owner-open-r5-host -> src/bin/r5_transport_host.rs
```

Superseded `r5_host`, earlier streaming/control carriers and historical cores may
remain as unselected source history, but must not enter `--all-targets`
implicitly. The exact machine gate is
`docs/contracts/owner-open-forbidden-default-graph-v2.json`.

Legacy `trillionniumd`, plan/Authority, privilege broker, broad OS types, typed
direct tools, sealed shell broker, egress and old journal packages remain
explicit history/sealed targets. They may not enter owner-open defaults through
a workspace default, feature unification or unreviewed internal dependency.

### 2.4 Exact L1 closeout record

The source candidate was generated from base
`668c031ba4533dc482866fd2da37b61118b92bf8`, restricted to the sorted 31-file
manifest, committed locally as
`fa1d287103c46aff35cf5e95addbc18da8a92063`, fully qualified, and then pushed
only after every gate passed.

The closeout includes:

- generated owner-open type freshness;
- exact R5 graph verification and verifier regressions;
- 680 Python tests with five explicit external-material skips;
- `cargo fmt --all -- --check`;
- `cargo test --locked --all-targets`;
- `cargo clippy --locked --all-targets -- -D warnings`;
- locked Cargo metadata and feature tree capture;
- exact candidate patch, file inventory and SHA-256 evidence verification.

The claim ceiling is
`EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX`.

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
- **L1:** exact-checkout unit, property, fixture and process tests;
- **L2:** installed target Root Linux Host/broker/provider/Codex process integration;
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

Current state: source closure is `HOST_TESTED / L1`; Android product-graph
closure remains open. Exit: Android closure reaches `IMAGE_INCLUDED / L3`.

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
12. provider panic/failure becomes one truthful terminal;
13. broker ownership isolates direct results while broadcasting bounded observations.

Selected source roots include:

- `crates/trillionnium-owner-open-turn-loop`;
- `crates/trillionnium-owner-open-provider-jsonl`;
- `crates/trillionnium-owner-open-runtime`;
- `crates/trillionnium-owner-open-call-registry`;
- `apps/trillionnium-owner-open-host/src/bin/r5_control_host_v7.rs`;
- `apps/trillionnium-owner-open-host/src/bin/r5_transport_host.rs`.

Current state: fake-provider, process, broker, disconnect, streaming and active
control paths are `HOST_TESTED / L1`. Exit: the same sequence passes against the
installed target Codex and target Root Linux at L2.

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
10. return tool observations to the same native provider turn;
11. bind live controls to one process-lifetime `bridge_instance_id`;
12. validate the exact traced MCP job sequence without hidden retry.

Current state: adapter, MCP bridge, exact-byte trace and lifecycle fixtures are
source-complete and `HOST_TESTED / L1`; no installed target Codex was executed.
Exit: a live installed Codex turn performs shell success, deliberate shell
failure, pipe/PTY job control, raw ADB observation and final continuation at L2;
later the same sequence is observed on device at L4.

### W3 — direct shell and durable job substrate

Deliverables:

- command-string and element-preserving argv;
- cwd, inherited environment delta and binary stdin;
- stdout/stderr byte streaming;
- pipe and PTY session support;
- attach/detach/write/resize/close-stdin/kill;
- process groups, timeout, signal and cancellation;
- output/spool limits and descendant cleanup;
- operation-level request binding and no-redispatch recovery;
- configured Root Linux UID/GID/namespace/cgroup placement.

Current state: runtime, registry, durable journal, restart, EOF and pipe/PTY
paths are `HOST_TESTED / L1`. Exit: installed target Root Linux L2 process suite,
then physical Root Linux L4 observation.

### W4 — ordinary raw ADB substrate

Deliverables:

- explicit selected topology: real ARM64 client/server or byte-transparent relay;
- exact argv excluding program name;
- no serial/host/port/privilege injection;
- unknown/future subcommands remain transport-valid;
- USB/offline/unauthorized/recovery/reboot observations remain raw;
- conservative disconnect/reconnect state;
- the same targeted cancellation and process lifecycle mechanics as shell.

Current state: exact-argv and relay mechanics are source-tested fixtures only.
Exit: physical `adb devices -l`, `adb shell id`, deliberate failure and one
visible device mutation in the same installed Codex turn.

### W5 — event store, replay, flow and recovery APIs

Deliverables:

- append-only accepted/started/chunk/control/terminal records;
- explicit configured-journal failure semantics;
- stable event IDs and inclusive cursors;
- event-by-event persistence while provider/tools are active;
- completed-call and completed-job replay without re-execution;
- incomplete reconciliation to `unknown_after_disconnect` where needed;
- client-delivery detach without cancellation of accepted effects;
- turn/call/job inspect operations;
- bounded delivery window, pause/resume and resync-required;
- bounded retention and explicit cleanup;
- broker/client disconnect truth without automatic redispatch.

Current state: persistence, restart, flow, inspection, broker and job recovery are
`HOST_TESTED / L1`. Cross-Host adoption of old live file descriptors remains
unsupported. Exit: installed target L2 restart/reconnect suite and L5 crash,
ENOSPC, reboot and power-loss matrix.

### W6 — Android/Root Linux integration and AiShell

Deliverables:

- clean owner-open product make/Soong profile;
- one init-owned Host, Android abstract socket and SELinux admission;
- no startup dependency on Authority, lease, egress, P01 or old shell broker;
- Root Linux writable overlay and restart lifecycle;
- install Host, broker, trace and Codex MCP bridge;
- thin AiShell turn client, event rendering, cancel, reconnect and inspect;
- out-of-band emergency stop capable of inhibiting respawn.

Current state: source contracts and verifier fixtures exist, but the audited
Android overlay still selects forbidden legacy nodes. Exit: clean target-files
L3 and physical normal-path L4.

### W7 — qualification, self-development and optional release

Deliverables:

- exact source/manifest/feature/Soong/rootfs/provider/image/device bindings;
- provider/Host/client disconnect tests;
- USB loss, reboot, ENOSPC and power-loss tests;
- Codex build/install/update/recover dogfood loop;
- separate optional sealed/public profile, signing, AVB/rollback, OTA and
  multi-user review.

Current state: exact source and Cargo evidence reached L1. Owner-open dogfood
exits at L4/L5. Public release requires separate L6 and may not block owner-open
development.

## 5. Implementation batches

### Batch A — graph and direct-process foundation

Closed at `HOST_TESTED / L1` on the exact v15 source candidate:

- exact R5 graph contract and verifier;
- direct shell and ordinary ADB process runtime;
- scoped call registry and registry-to-runtime bridge;
- same-turn callback loop and external provider JSONL adapter.

### Batch B — durable replay foundation

Closed at `HOST_TESTED / L1`:

- append-only durable event store;
- stable semantic request digest and turn-stream identity;
- completed replay without redispatch;
- incomplete reconciliation to `unknown_after_disconnect`;
- configured-journal unavailable state fails closed.

### Batch C — streaming, detached delivery and active controls

Closed at `HOST_TESTED / L1`:

- synchronous turn-event sink;
- runtime event forwarding while a process is active;
- per-event Host persistence and flush;
- detached client delivery without effect cancellation;
- bounded input/control reader and independent turn worker;
- active correlated `turn.cancel`;
- targeted active `tool.cancel`;
- provider JSONL cancellation acknowledgement and finite cleanup grace;
- explicit Host binary selection with autobin discovery disabled.

### Batch D — inspection, flow, jobs, connection and installed Codex

Source portions closed at `HOST_TESTED / L1`:

- inclusive replay cursors and `turn.inspect`/`call.inspect` APIs;
- bounded stream window, pause/resume and resync behavior;
- durable long-running pipe/PTY jobs and all reviewed controls;
- same-UID multi-connection broker and connection-bound MCP controls;
- exact-byte MCP trace and installed-Codex qualification runner.

Qualification portions still open:

1. execute the probe against the actual target Root Linux Codex executable;
2. bind executable path, digest, version, help bytes and authentication state;
3. execute the exact traced MCP sequence with real pipe and PTY jobs;
4. prove no hidden retry across disconnect/reconnect;
5. execute the selected physical ADB topology.

### Batch E — Android and physical qualification

Open critical path:

1. remove every forbidden legacy node from the selected Android product graph;
2. wire init, SELinux, abstract socket, Root Linux and AiShell;
3. build and inspect clean target files;
4. collect installed-Codex L2, image L3 and physical L4 evidence;
5. collect crash, disconnect, USB-loss, reboot, ENOSPC and power-loss L5 evidence;
6. keep public release false until a separate signed L6 profile passes.

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

The repository-internal source and CI blocker chain is closed at L1. Installed
Codex, Android image, physical device, destructive fault and public-release gaps
remain evidence-gated and may not be converted into source claims.
