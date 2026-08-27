# Trillionnium OS owner-open execution plan

Revision: **2026-08-27-r4**  
Status: **ACTIVE — the only implementation sequencing and closeout plan**  
Semantic baseline: [`TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md), revision 2026-08-27-r3  
Machine status: [`status/owner-open-r4-status.json`](status/owner-open-r4-status.json)  
Traceability: [`status/owner-open-r4-traceability.tsv`](status/owner-open-r4-traceability.tsv)

## 0. Authority and relationship to r3

The r3 canonical plan remains the normative product and protocol decision:
Codex is the only semantic control plane; owner-open shell and ADB are direct
primitives; the substrate owns only process, transport, storage, liveness and
recovery mechanics. This r4 document supersedes r3 only for implementation
order, engineering gates, evidence requirements, status vocabulary and file
ownership. If r3 and r4 differ on product semantics, r3 wins until an explicit
architecture amendment updates the machine contract. If they differ on what to
build next or what counts as complete, r4 wins.

No source, test, generated receipt, static image or historical device
observation may promote a row in this plan beyond the evidence actually
collected. In particular:

- `SOURCE_IMPLEMENTED` is not `DEVICE_OBSERVED`;
- a source-shape test is not a live Codex turn;
- a host `adb` invocation is not the integrated Android product path;
- a userdebug hotpatch is not a clean target-files build;
- a successful command is not proof of restart or power-loss behavior;
- an owner-open dogfood milestone is not a public-release claim.

## 1. r4 outcome

The r4 critical-path outcome is a small, inspectable owner-open product graph:

```text
AiShell or owner client
  -> Direct Agent Host connection
  -> exactly one active Codex turn lineage per connection
  -> native or transparent shell.exec / adb.exec call
  -> process or ADB transport
  -> byte-preserving events and truthful terminal state
  -> the same Codex turn
```

The first complete dogfood demonstration must prove all of the following in one
bound evidence package:

1. Android starts one owner-open Host and no forbidden legacy semantic node.
2. AiShell starts one Codex turn and renders provider/tool events from that turn.
3. The turn executes both command-string shell and element-preserving argv in
   the configured Root Linux environment.
4. The same turn executes ordinary raw ADB argv without injected serial, host,
   port, approval, risk tier or privilege substitution.
5. Real stdout, stderr, exit status, signal, timeout and transport errors return
   without semantic renaming by an intermediate service.
6. Disconnect, provider crash, Host crash, USB loss and reboot produce an
   inspectable state or `unknown_after_disconnect`; no uncertain call is
   automatically re-dispatched.
7. An out-of-band owner recovery path can stop respawn and recover the device
   without depending on Codex or the provider endpoint.
8. The evidence binds exact control-plane source, Android manifest/patches,
   Cargo features, Soong modules, rootfs, Codex runtime, target files and device
   build identity.

## 2. Non-negotiable engineering invariants

### 2.1 One semantic principal

Codex owns intent, context selection, policy, consent language, tool and target
choice, retry, compensation and interpretation. No owner-open component may
reconstruct a plan, assign a risk class, require a semantic approval lease,
select a weaker target, rewrite a command, translate an unknown ADB subcommand,
or decide whether the requested action is appropriate.

### 2.2 Mechanism safety remains mandatory

Owner-open removes a second semantic authority; it does not remove mechanical
isolation. The Host must still enforce:

- unambiguous framing and duplicate-member rejection;
- local peer/socket admission appropriate to the selected deployment;
- finite frame, argv, environment, FD, process, output and spool bounds;
- exact process-group ownership, child reaping and cancellation mechanics;
- explicit credential FD inheritance and `CLOEXEC` defaults;
- byte-preserving stdout/stderr/PTY transport;
- monotonic timeout accounting;
- durable or explicitly best-effort event status;
- truthful crash/restart reconciliation;
- an out-of-band emergency stop.

These checks report malformed input or resource exhaustion. They never become
safe/unsafe classifications or command allowlists.

### 2.3 Profile isolation is structural

Owner-open and sealed/history code may share low-level codec or process
mechanics, but they must have separate product roots. A forbidden node is not
made safe by being dormant at runtime if it is still compiled, linked,
installed, imported by a broad Java glob, selected by Cargo feature unification,
or started through an init property chain.

The owner-open default graph must not include:

- `TrillionniumAiAuthority` or Capability Lease Issuer;
- `trillionnium-agent-privilege-broker`;
- `trillionnium-privilege-broker-protocol`;
- `trillionnium-agent-egress-guard` or its launcher/probe;
- direct-operation custody high-water services;
- the pre-r3 shell broker/worker product closure;
- operation-journal promotion/receipt services used as effect admission;
- P01 materialization, receipt-stage or final-artifact packages as a Host gate;
- the fixed-control-FD stdio proxy;
- typed-only ADB helpers in the direct path;
- broad `org.trillionnium.platform(.internal)` Authority/lease consumers.

They may remain explicit sealed/history targets until deletion, but every such
target must require a non-default profile and must fail the owner-open negative
graph test if reintroduced.

### 2.4 Honest uncertainty

General shell and ADB effects are not exactly-once. A call may have executed
when a response is lost. The Host records accepted/started/terminal facts it can
prove and otherwise returns `unknown_after_disconnect`. It does not infer
`not_started` from missing data, claim success from transport closure, or retry
an uncertain effect under the same or a new call id without a Codex/owner
decision.

### 2.5 Logs cannot become authorization

Event storage is observability. In owner-open P0, storage failure does not deny
an otherwise mechanically valid direct call. The Host attempts accepted,
started, chunk and terminal records; if storage is unavailable it marks the
lineage `best_effort`/`unreplayable`, continues where mechanically possible and
never presents missing logs as proof that no effect occurred.

## 3. Status vocabulary

Every capability in `status/owner-open-r4-status.json` uses exactly one level:

| Level | Meaning |
| --- | --- |
| `NOT_STARTED` | No current normative implementation artifact. |
| `SPEC_ONLY` | Normative requirements exist, but no source implementation is claimed. |
| `SOURCE_IMPLEMENTED` | Source is structurally implemented; no host behavior claim. |
| `HOST_TESTED` | Relevant host unit/integration tests pass against exact source. |
| `IMAGE_INCLUDED` | Exact artifact is selected by a clean Android product build and verified in target files. |
| `DEVICE_OBSERVED` | A physical device produced the required live observation. |
| `FAULT_TESTED` | Required crash/disconnect/reboot/power-loss cases pass. |
| `RELEASE_QUALIFIED` | Separate signed release profile and evidence are complete. |

A row may contain subordinate checks at lower levels, but its headline status
is the lowest required acceptance level not yet satisfied. Evidence records
must never infer a higher level from the number of tests or lines of code.

## 4. Evidence levels

| Level | Evidence class | Minimum contents |
| --- | --- | --- |
| L0 | Contract/source shape | Parsed schema, generated-file freshness, forbidden-symbol and graph checks. |
| L1 | Unit/property/fuzz | Exact test command, toolchain, seed/corpus where applicable, pass/fail counts. |
| L2 | Host process integration | Real child processes, pipes/PTY/socket, cancellation, output and restart tests. |
| L3 | Android image/static | Clean manifest, patch set, Soong graph, target-files paths/hashes, SELinux policy. |
| L4 | Physical live effect | Device fingerprint, exact turn/call ids, raw events and visible effect. |
| L5 | Fault/recovery | Provider/Host crash, disconnect, USB loss, reboot, ENOSPC and power-loss observations. |
| L6 | Public release | Production signing, AVB/rollback, OTA, multi-user and release security review. |

Owner-open dogfood closeout requires L4 for the normal path and L5 for the
specified recovery cases. L6 is explicitly separate.

## 5. Work-package map

| ID | Name | Critical-path result |
| --- | --- | --- |
| W0 | Product graph isolation | One owner-open build/link/install/start graph with negative proof. |
| W1 | Codec and connection substrate | Strict extensible frames and one-turn-per-connection state machine. |
| W2 | Provider and same-turn event bridge | One Codex session emits model/tool events into the bound turn stream. |
| W3 | Direct shell substrate | Command/argv, cwd/env/stdin/PTY, signals, output and cancellation. |
| W4 | Raw ADB substrate | Ordinary adb argv or byte-transparent relay, no semantic wrapper. |
| W5 | Event store, jobs and recovery | Inspectable accepted/started/terminal records and conservative reconciliation. |
| W6 | Android integration | Clean Soong/init/SELinux/product closure and Root Linux lifecycle. |
| W7 | AiShell owner-open UI | Text ingress, stream rendering, cancel and reconnect without Authority UI. |
| W8 | Qualification and evidence | Reproducible L0-L5 evidence bound to exact source/image/device. |
| W9 | Optional sealed/public profile | Restrictions and release evidence that never block owner-open. |

W0-W4 are the immediate critical path. W5 begins with W1 and must be sufficient
for honest uncertainty before device fault qualification. W6 and W7 integrate
only the source interfaces produced by W1-W5. W9 cannot change W0-W8 acceptance.

## 6. W0 — product graph isolation

### 6.1 Deliverables

1. Add the isolated `trillionnium-owner-open-types` crate with no dependency on
   broad legacy OS types, privilege, policy, shell broker or direct-tools
   crates.
2. Add `trillionnium-owner-open-host` as the only executable default product
   root. The Host may depend on the isolated codec and external primitives, but
   not on legacy plan, Authority, broker, direct-tools or broad OS types.
3. Remove `trillionniumd`, privilege broker, fixed stdio proxy, legacy
   direct-tools, shell-exec and tool-runtime roots from Cargo `default-members`;
   retain them only as explicit sealed/history workspace targets.
4. Define the machine-readable forbidden default graph contract.
5. Add a verifier that checks exact Cargo defaults, isolated Host/codec
   dependencies and source markers, generated codec freshness, plan/status
   revision consistency and known Android overlay violations.
6. Split Android product selection into an explicit owner-open profile and a
   sealed/history profile. Remove forbidden packages from owner-open
   `PRODUCT_PACKAGES`, `PRODUCT_PACKAGES_DEBUG`, broad Java source globs and init
   property chains.
7. Prove the final graph using `cargo metadata`, `cargo tree -e features`, Soong
   `module-info.json`, target-files file lists, init service enumeration and
   classpath/source selection reports.

### 6.2 Concrete source boundaries

Control plane:

- `Cargo.toml`
- `apps/trillionnium-owner-open-host/`
- `crates/trillionnium-owner-open-types/`
- `docs/contracts/owner-open-forbidden-default-graph-v1.json`
- `tools/verify-owner-open-foundation.py`
- `.github/workflows/owner-open-foundation.yml`

Android integration:

- `vendor/trillionnium/config/common.mk`
- owner-open profile makefile added beside `common.mk`
- `vendor/trillionnium/prebuilt/common/Android.bp`
- `init.trillionnium-system_ext.rc`
- `packages/apps/TrillionniumAiShell/Android.bp`
- framework/services/app imports of `org.trillionnium.platform(.internal)`
- Trillionnium SDK source/resource selection
- SELinux file/service/domain declarations for retired nodes

### 6.3 Acceptance

W0 is complete only when:

- unqualified Cargo default resolution contains exactly the isolated Host and
  codec roots and no legacy product root;
- owner-open Host and types have no forbidden internal dependency or legacy
  semantic source marker;
- an owner-open Android build has no forbidden module, file, service, socket,
  classpath edge or package;
- every retained sealed/history target requires an explicit profile;
- a negative test fails after intentionally adding any forbidden node;
- the exact reports are attached as L0/L3 evidence.

The first r4 foundation change completes the Cargo/default-product portion of
W0 and adds the isolated Host source root. Android/Soong/init/SELinux graph
convergence remains open and must be represented as such in machine status.

## 7. W1 — codec and connection substrate

### 7.1 Codec rules

The codec must implement the machine contract without generating policy. It
must:

- reject duplicate JSON members recursively before typed decoding;
- reject empty, oversized, trailing or structurally ambiguous frames;
- retain unknown extension fields and opaque tool/target labels;
- enforce alias equality when both aliases are present;
- enforce finite mechanical bounds;
- accept both command-string and argv shell forms, exactly one per call;
- accept non-empty raw ADB argv including unknown/future subcommands;
- never inject serial/host/port/profile/approval/privilege fields;
- keep correlation fields distinct from permission or identity decisions.

Generated outputs are limited to constants, codecs, schemas and test vectors.
They must not emit allowlists, risk tiers, approval requirements, fixed UID/GID,
SELinux admission, target capability gates or executable policy.

### 7.2 Connection state machine

One connection carries at most one active turn lineage:

```text
CONNECTED
  -> optional HELLO_ACCEPTED
  -> TURN_ACCEPTED
  -> TURN_RUNNING
  -> TURN_END
  -> CLOSED
```

A connection may receive control frames while the turn runs. Concurrent turns
use separate connections. A Host-generated `connection_id` is unique per
transport connection; `turn_stream_id` is stable for the turn lineage across
reconnects. `hello` may establish version/resume context but does not replace
`turn.start` session/task/turn input.

Current source foundation:

```text
crates/trillionnium-owner-open-types/src/lib.rs
apps/trillionnium-owner-open-host/src/lib.rs
apps/trillionnium-owner-open-host/src/main.rs
apps/trillionnium-owner-open-host/tests/stdio_process.rs
```

The current foundation handles a synchronous provider call and therefore does
not yet keep control frames serviceable while a real provider/tool is running.
Batch B must move provider delivery to an asynchronous state machine before
`turn.cancel`, flow control or reconnect can be claimed as live behavior.

As resume, flow control, jobs and asynchronous provider delivery grow, split
these into explicit `codec`, `connection`, `turn_state`, `correlation`,
`flow_control` and `error` modules rather than reintroducing the legacy Agent
API state dispatcher.

### 7.3 Flow control

The Host maintains explicit delivery windows. `stream.pause` stops new event
delivery without cancelling the process. `stream.resume` replays from an
inclusive cursor and then resumes live delivery. A zero initial window is legal
and causes spooling where available. Flow-control state never changes whether
the effect is allowed.

### 7.4 Acceptance

- strict parser golden and negative vectors pass;
- unknown fields survive decode/encode/replay;
- aliases conflict deterministically;
- one connection cannot start a second active turn;
- the real Host binary passes a stdio JSONL process integration test;
- sequence and replay ordering is stable;
- slowloris input is bounded by one absolute handshake/frame deadline;
- pause/window/resume does not duplicate or re-execute a call;
- fuzzing covers frame decode and state transitions.

## 8. W2 — provider and same-turn event bridge

The r4 foundation contains a provider trait, normalized provider events and an
`UnavailableProvider` that produces a correlated `provider_unavailable`
terminal result. This is an honest interface seam, not a Codex integration or
runtime-readiness claim.

### 8.1 Provider forms

Support, in order:

1. installed `codex exec --json` using an observed full-access flag supported by
   that binary;
2. a long-lived Codex/app-server interface when it materially improves restart,
   streaming or subagent support.

The Host probes `codex --help` and `codex --version` on the target runtime. A
source asset name is not runtime version evidence. Unsupported optional flags
produce a truthful provider configuration error; they do not hide direct tools
or start a fallback model/provider.

### 8.2 Same-turn correlation

Every provider-native tool event is normalized before publication:

- allocate or bind `call_id`;
- bind session/profile/task/turn/turn-stream correlation;
- resolve the configured target and execution identity;
- hash the exact observed request bytes using the normative canonicalization;
- attempt accepted/started persistence;
- forward chunks and terminal events using stable ids.

Model text alone is never treated as proof that a tool ran. A provider-side
effect without a correlated native or transparent event is unreplayable and
must be marked as such.

### 8.3 Acceptance

One turn must:

- emit provider lifecycle events;
- execute a successful tool call;
- execute a deliberate failing tool call;
- continue reasoning after the failure;
- return final model text;
- expose all events to the same client stream;
- cancel promptly and reap provider descendants;
- return provider outage/authentication errors without semantic substitution.

## 9. W3 — direct shell substrate

### 9.1 Request semantics

`shell.exec` accepts exactly one of:

- `command`: executed by the owner-configured shell, with `/bin/sh` as the
  minimal default; or
- `argv`: passed element-for-element to process creation without shell parsing.

The substrate records exact command/argv, resolved executable or shell, target,
cwd, environment generation, stdin form, PTY parameters and config generation.
It does not require an executable allowlist or standard risk class in the
owner-open profile.

### 9.2 Process mechanics

Implement:

- explicit process groups/session ownership;
- optional PTY and controlling terminal;
- independent stdout/stderr pipes when no PTY is selected;
- raw PTY byte stream when PTY is selected;
- UTF-8, base64, FD and spool stdin forms;
- inherited environment plus string override/null unset semantics;
- owner-configured UID/GID/groups/capabilities/namespaces/seccomp/no-new-privs;
- monotonic timeout, signal escalation and child reaping;
- bounded buffering plus disk spool for backpressure;
- output truncation metadata without corrupting the effect state;
- explicit process-exit, signal, timeout, cancel and I/O terminal results.

### 9.3 Cancellation and races

Whichever terminal condition is first observed wins:

- delivered client cancel -> `client_cancelled`;
- monotonic deadline first -> `timed_out`;
- process exit first -> exit/signal result;
- remote/namespace loss with uncertain process state ->
  `unknown_after_disconnect`.

Cancellation is not proof that a child performed no effect. The event stream
must include whether a signal was delivered and whether the process group was
observed gone.

### 9.4 Acceptance

Host tests cover:

- command string and argv byte preservation;
- cwd and environment inheritance/override/unset;
- binary stdout/stderr including NUL and invalid UTF-8;
- PTY echo/CRLF behavior as raw bytes;
- large output, backpressure, pause/resume and ENOSPC;
- timeout/cancel/exit races;
- grandchildren and daemonizing children;
- Host crash and restart reconciliation;
- no import or invocation of the pre-r3 shell broker/worker.

Device acceptance additionally proves the configured Root Linux overlay is
writable, `/bin/sh` exists, processes restart under Android init and a live
Codex turn receives the real shell observations.

## 10. W4 — raw ADB substrate

### 10.1 Architecture decision required before implementation

Select and document exactly one primary product topology:

- a real ARM64 adb client/server inside Root Linux; or
- a byte-transparent relay to an Android/host adb server.

The decision must state server location, socket, USB/TCP ownership, key custody,
pairing, restart behavior, root/recovery modes and reboot continuation. The
current typed `AdbRequest` enum and `BackendUnavailable` product adapter are
migration material, not the owner-open implementation.

### 10.2 Request semantics

`adb.exec` receives a non-empty raw argv excluding the program name. Unknown and
future subcommands pass through. The wrapper must not:

- inject `-s` or choose a device serial;
- inject server host/port/socket;
- downgrade root/remount/reboot/install or another operation;
- map raw adb output to semantic HOLD/denied labels;
- prevalidate against an informational capability record;
- retry an uncertain command automatically.

A target label is a routing/diagnostic hint. When absent, ordinary configured
adb behavior applies, including the real multiple-device error. A caller that
needs the adb help surface may invoke the ordinary binary through `shell.exec`
or pass the adb implementation's explicit help argv.

### 10.3 Acceptance

Within one Codex turn, demonstrate:

- `adb devices -l`;
- a selected-device `shell id`;
- an unknown or less-common subcommand reaching adb unchanged;
- unauthorized, offline and multiple-device errors as raw adb output;
- push/pull/install binary and progress handling;
- forward/reverse and server reconnect;
- root/remount/reboot rejection or success exactly as reported by the device;
- USB unplug and reboot uncertainty without blind redispatch;
- recovery/bootloader routing where configured.

## 11. W5 — event store, jobs and recovery

### 11.1 Minimum record model

Persist or attempt to persist:

```text
accepted -> started -> zero or more chunks -> exactly one terminal record
```

Each record carries record type, kind, all correlation ids, request digest,
binding fingerprint, config generation, target/resolved target, dispatch/effect
state, sequence, raw bytes or spool reference, timestamps and storage status.

P0 may use append-only best effort. P1 requires fsync/atomic publication and
readback. Missing storage never turns into a semantic denial.

### 11.2 Duplicate calls

Within the call-id scope:

- identical request bytes attach to the existing local stream/result;
- the same call id with different bytes is `invalid_frame_call_id_conflict`;
- after restart, a terminal record is replayed;
- a started record without terminal is reconciled conservatively;
- no record is not proof of `not_started` if dispatch could have begun.

### 11.3 Jobs

Long-running `shell.job.*` mechanics are incremental after basic calls. Jobs are
scoped to session and profile, have explicit attach/write/resize/close/kill
operations and inclusive cursors, and survive only to the extent proven by
durable local records and process evidence. TTL is liveness cleanup, never
semantic authorization.

### 11.4 Acceptance

Fault tests cover accepted-record crash, post-spawn/pre-started crash,
started/no-terminal crash, terminal-before-delivery crash, disk full, corrupt
last record, Host restart, provider restart, client reconnect, job attach and
explicit cleanup.

## 12. W6 — Android and Root Linux integration

### 12.1 Clean integration source

The audit overlay is evidence, not a permanent development topology. Convert
all owner-open Android changes into either reviewed commits in their manifest
projects or an ordered, zero-fuzz, hash-verified patch series. A clean-room
script must:

```text
repo init/sync pinned manifest
-> verify every project HEAD
-> apply reviewed changes with zero fuzz
-> run graph/source tests
-> build target files
-> verify module/init/SELinux/classpath closure
-> publish exact evidence manifest
```

### 12.2 Root Linux lifecycle

Android owns mount/overlay/bootstrap/init and the out-of-band stop. Root Linux
provides the Codex runtime, shell, adb client/relay endpoint, writable workspace,
network and spool. The Host must expose exact interruption/restart facts rather
than silently reconnecting a turn across phone reboot when its process died.

### 12.3 Acceptance

- owner-open product contains one Host and no forbidden product node;
- init starts the Host directly, not behind Authority/high-water/shell-ready
  semantic gates;
- SELinux permits required process/transport mechanics and denies unrelated
  peers;
- rootfs contains the exact runtime and tools claimed by the evidence manifest;
- kill/restart produces a new PID and truthful turn interruption;
- target files and installed files match the verified module graph.

## 13. W7 — AiShell owner-open UI

AiShell is a thin client. It sends text and optional context correlation, renders
model/tool chunks, exposes cancel, reconnect and inspect, and clearly labels
best-effort/unreplayable or unknown outcomes. It must not retain Capability
Lease, Authority approval, risk-tier or typed-command semantics in the
owner-open source set.

Acceptance requires:

- one visible active turn per connection;
- model and tool event ordering;
- binary output presentation without altering stored bytes;
- cancel and reconnect controls;
- unknown-after-disconnect and provider-unavailable states;
- Accessibility disabled without blocking shell/ADB;
- no broad Java source glob importing retired platform Authority code.

## 14. W8 — qualification and evidence

Every qualification package must include:

- control-plane commit SHA and dirty-state assertion;
- Android manifest digest, project heads and patch/commit list;
- Cargo metadata and feature tree;
- Soong module graph, classpaths, init services and SELinux policy digest;
- toolchain versions and build command;
- rootfs, Codex runtime and direct-tool digests;
- target-files/image hashes and device fingerprint/slot/state;
- test vector ids, commands, raw logs and result summary;
- explicit evidence level and claims not made.

Create separate suites for L0/L1, L2, L3, L4 and L5. A summary may link raw
artifacts but may not replace them.

## 15. W9 — optional sealed/public profile

The sealed profile may add semantic restrictions, approvals, narrower identity,
stronger durable admission, production signing, AVB/rollback and multi-user
policy. It must reuse the owner-open mechanism substrate through an explicit
profile adapter, remain absent from owner-open defaults and never be required
to start or use owner-open shell/ADB.

No work in W9 can be cited as completion of W0-W8.

## 16. Immediate implementation batches

### Batch A — r4 foundation

Scope in the first r4 change:

- this execution plan;
- machine status and traceability;
- owner-open threat model and implementable protocol subset;
- isolated `trillionnium-owner-open-types` crate;
- isolated `trillionnium-owner-open-host` default product root;
- strict duplicate-key frame decoder and mechanical validation;
- schema and codec-only constant generator;
- root Cargo default-member isolation;
- provider boundary with an honest unavailable production default;
- stdio/file-UDS Host carrier and same-turn correlation source tests;
- forbidden-graph contract and verification tooling;
- CI for generation, graph checks, Python tests, package tests and a spawned
  Host-process JSONL integration test.

Acceptance: L0/L1 source and unit evidence plus an L2 host-process test when CI
passes. No live Codex provider, shell, ADB, Android image or device capability
is claimed.

### Batch B — Host connection hardening and Codex bridge

Extend the isolated Host foundation with:

- Android abstract-socket carrier and peer admission;
- asynchronous provider delivery so cancel/control frames remain serviceable;
- bounded connection/turn deadlines and multi-connection concurrency;
- stable event store, inclusive cursor resume and flow-control windows;
- installed `codex --help`/`--version` probe and full-access launch selection;
- native Codex JSON event normalization into the same turn stream;
- provider descendant cleanup and truthful restart/disconnect outcomes.

Acceptance: complete L2 connection/provider tests. Direct tool execution remains
unclaimed until Batch C.

### Batch C — direct shell

Add process substrate, streaming, cancellation, PTY, environment and P0 event
spool. Integrate a Codex provider turn and prove same-turn shell events at L2,
then move to Android Root Linux L4.

### Batch D — raw ADB

Land the ADB topology ADR and transparent implementation; prove host transport,
then same-turn physical device control and disconnect/reboot behavior.

### Batch E — Android graph cutover

Remove forbidden nodes and SDK closure from the owner-open product, wire the
new Host/AiShell/Root Linux graph, produce clean target files and run L4/L5
qualification.

## 17. Required CI lanes

1. `owner-open-foundation`: generated freshness, JSON/schema parse, graph
   verifier and owner-open crate/Host tests.
2. `owner-open-isolated-features`: fresh Cargo resolution proving no legacy
   feature unification in the owner-open root.
3. `legacy-explicit`: retained sealed/history targets compile only when named.
4. `host-integration`: process/socket/PTY/recovery tests as they land.
5. `android-source-contract`: patch, make/Soong/init/SELinux/classpath checks.
6. `android-build`: clean target-files build on controlled infrastructure.
7. `device-dogfood`: owner-authorized hardware suite with raw evidence upload.

A lane name must describe its evidence level. `source-pass` must never be
reported as `device-pass`.

## 18. Definition of done for owner-open dogfood

Owner-open dogfood is complete only when all are true:

- W0-W7 have at least their stated acceptance level;
- W8 contains complete L4 normal-path and L5 fault evidence;
- one Codex turn executes host/Root Linux shell and raw ADB and receives all raw
  observations;
- the Android owner-open graph has no forbidden node or SDK edge;
- uncertain effects are never silently retried or mislabeled;
- the owner can inspect, cancel, stop respawn, recover and restore;
- Codex can modify/build/install or update its userland on the authorized test
  device;
- README, current state, machine status and evidence make no stronger claim.

Public release remains incomplete until W9/L6 is separately qualified.

## 19. Change-control rules

Any change that alters protocol fields, call-id scope, effect uncertainty,
profile isolation, process identity, event durability, ADB topology or release
boundaries must update in the same pull request:

1. the normative contract or an explicit ADR;
2. generated codec outputs and schemas;
3. this plan if sequencing/acceptance changes;
4. machine status and traceability;
5. affected tests and evidence expectations;
6. `CURRENT_STATE.md` when a product or release claim changes.

Historical documents are immutable evidence. New work must not edit history to
make an old result appear current.

## 20. Current r4 status at plan publication

- The isolated owner-open Host and codec packages are source implemented and
  are the only unqualified Cargo default roots in this branch.
- Strict frames, mechanical shell/ADB request codecs, a provider interface,
  correlated provider events, an honest unavailable-provider default and
  stdio/filesystem-UDS process tests are present.
- Live Codex integration, asynchronous control, direct shell runtime, raw ADB
  transport, durable event store and Android graph cutover are not claimed.
- The checked-in Android overlay still contains the legacy Authority/lease/P01/
  shell-broker product graph and therefore remains an explicit W0/W6 HOLD.
- No new physical device, reboot, power-loss, OTA or public-release evidence is
  created by the foundation batch.
