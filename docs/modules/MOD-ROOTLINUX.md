# MOD-ROOTLINUX — Root Linux integration

This document is the detailed source-development, integration and qualification contract for `MOD-ROOTLINUX`. The machine authority remains `docs/machine/module-catalog.v1.json`; this document explains how engineers must implement and operate that contract without widening its evidence ceiling.

## 1. Identity and maturity

- Module ID: `MOD-ROOTLINUX`
- Module version: `1.0.0`
- Name: **Root Linux integration**
- Plane: `platform`
- Primary owner: `team-rootlinux`
- Backup owner: `team-android`
- Maturity: `SOURCE_PROFILE_L2_PENDING`
- Catalog authority: `docs/machine/module-catalog.v1.json`
- Documentation index: `docs/machine/module-document-index.v1.json`
- Resource provenance: `docs/machine/resource-budget-provenance.v1.json`
- Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

Source ownership paths:

- `packaging/root-linux`

The maturity value is a source-state label, not an installed-target or release assertion. A later evidence package must bind the exact source, build, target and reviewer identities before a higher level is claimed.

## 2. Responsibilities

The module has these stable responsibilities:

- runtime image.

Operationally, the required flow is:

The integration assembles the selected owner-open payload, records immutable hashes and service identities, establishes UID/GID, namespace, cgroup, mount and store placement, then starts the host and authenticated provider under a bounded service epoch.

Every accepted transition must carry enough identity to correlate input, state mutation, output and terminal classification. Capacity is reserved before a slow or externally visible operation begins.

## 3. Non-goals and authority boundary

Explicit non-goals:

- semantic policy.

Root capability is minimized and mechanically scoped. Packaging cannot add semantic policy, substitute unpinned provider bytes, broaden namespaces or silently select a legacy authority path.

The provider remains the sole semantic principal. This module may reject malformed, unauthenticated, stale, over-budget or unsafe mechanical input, but it must not invent goals, choose a substitute operation, hide an uncertain effect or widen authority during recovery.

## 4. Context, dependencies and data flow

Direct dependencies: `MOD-EXECUTION-CORE`, `MOD-PROVIDER`, `MOD-GLOBAL-CONTROL`.

The normal data-flow boundary is: validate the versioned input; bind identity and ordering metadata; reserve finite capacity; make the minimal authoritative transition; execute or forward the exact mechanical action; retain bounded observations; publish one terminal or explicit unknown classification.

Dependencies are consumed through their declared APIs. A dependency outage cannot be converted into success. Cycles are prohibited by the machine catalog, and slow external work remains outside broad registry or global-control locks.

## 5. API and protocol contract

- API schema: `org.trillionnium.mod_rootlinux.api.v1`
- Catalog input labels: `rootlinux_service_request_v1`
- Catalog output labels: `rootlinux_service_state_v1`
- Catalog error labels: `rootlinux_error_v1`
- Unknown fields: rejected unless a future compatibility revision explicitly changes the rule.
- Versioning: semantic version `1.0.0`; incompatible changes require a new version and migration evidence.
- Size and count limits: bounded by the resource contract and validated before allocation or durable mutation.

Each request must include its version, request identity, ordering identity and payload digest where applicable. Responses preserve the same correlation identity. Duplicate requests with identical identity and digest are idempotent only where the module contract declares an existing result; identity reuse with different content is an explicit conflict.

### Concrete implementation binding

- Implementation source: `tools/owner-open/stage_owner_open_rootfs_payload.py` — `stage`

The catalog input/output/error names above are versioned logical contract labels,
not a claim that identically named Rust declarations or JSON Schema files exist.
The bound implementation declaration and its codec tests define concrete fields;
source navigation alone does not prove wire compatibility.

The staging helper validates source identity, destination paths, ELF metadata and content digests before assembling a payload. `packaging/root-linux/` contains admission policy inputs, not an already installed system. A successful source staging test does not establish live UID, namespace, cgroup or provider identity.

## 6. State model and ownership

- State schema: `org.trillionnium.mod_rootlinux.state.v1`
- State authority: **authoritative**
- Partition key: `service_epoch`
- State owned: `install manifest projection; service runtime state`
- Durability class: `journaled`
- Retention ceiling: 4096 items and 67108864 bytes per declared bounded in-memory window.
- Terminal vocabulary: `closed` and `unknown`; implementation-specific intermediate states must converge to one of those classifications or a versioned extension.

Only this module may perform authoritative writes for its state families. Read models may be rebuilt from retained authoritative records but cannot become an alternate writer. Every writer carries a module or service epoch; stale epochs fail closed.

## 7. Ordering, concurrency and backpressure

- Ordering key: `service_epoch`
- Maximum declared concurrency: `16`
- Admission resource: `resource_contract.queue_items`
- Lease source: `module_instance_lease`
- Lock scope: `module-local per-key metadata guard`
- Backpressure: `reject_at_capacity`
- Timeout ceiling: `30000` milliseconds
- Lease expiry: `stop_new_admission_and_fence_authoritative_writes`
- Duplicate/conflict rule: `idempotent_duplicate_or_explicit_conflict`

Per-key operations are linearized while unrelated keys may progress concurrently. Process spawn, external I/O, fsync and provider waits are slow paths and must not execute under a global registry lock. At capacity, admission is rejected before starting a process or publishing an accepted effect.

## 8. Effect, cancellation and uncertainty semantics

Automatic redispatch: **forbidden**.

Cancellation is targeted by exact request, call, job, turn, connection or module identity as appropriate. Cancellation requests and terminal completion races are serialized through the authoritative lifecycle transition. Cleanup frees resources but does not authorize a replacement effect.

An accepted operation lacking authoritative terminal evidence is `unknown` or reconciliation-required. A timeout, disconnect, restart, missing journal entry or process-leader exit is not proof that an external effect did not occur.

## 9. Resource budget and SLO status

Resource budget authority: `docs/machine/resource-budget-provenance.v1.json`.

| Contract item | Current source ceiling |
|---|---:|
| CPU weight | 100 |
| Memory | 67108864 bytes |
| File descriptors | 256 |
| Processes | 16 |
| Threads | 64 |
| I/O rate | 10485760 bytes/s |
| Queue items | 4096 |
| Queue bytes | 67108864 |
| Store bytes | 536870912 |
| Operation timeout | 30000 ms |
| Recovery target | 60000 ms |
| Provisional P99 target | 1000 ms |
| Provisional throughput target | 100/s |
| Provisional availability target | 99.0% |
| SLO recovery target | 60000 ms |
| SLO measurement window | 60 s |

Measurement status: **unmeasured until qualified evidence**.

These values are finite source-admission ceilings and provisional objectives, not benchmark results. They remain observe-only until workload profiles `WL-01` through `WL-12`, environment identity, samples, percentiles and resource observations are retained in a qualifying L2 package.

## 10. Persistence, recovery and reconciliation

Service restart validates the live install manifest and state ownership before admitting work. Emergency inhibit remains available independently of provider health.

Durable writes use an explicit commit boundary. Startup validates schema, epoch and record integrity before admission. Corrupt or incompatible authoritative state is quarantined or causes fail-closed startup. Reconciliation observes external reality first; it never fills a missing record by blind effect replay.

### Supervisor group-retirement barrier

The deployed helper is `tools/owner-open/owner_open_rootlinux_supervisor.py`.
`Supervisor.observe_exit` uses Linux `waitid(WNOWAIT)` and never calls
`Popen.poll()` while a process group is owned. The unreaped session leader pins
its numeric PID/PGID until group signalling has finished; an external reaper or
ignored SIGCHLD is unsupported and fails closed. Status reads do not reap it.

`Supervisor.cleanup_groups` sends TERM, then always sends KILL to the original
group before reaping the leader. Two bounded same-namespace procfs observations
must find the leader exited and no live original-group members. Zombies cannot
execute; the installed init/subreaper is responsible for reaping adopted zombies.
Noncritical exit, critical restart and final shutdown all use this barrier.
An unavailable/truncated procfs view, exhausted scan budget, signal error or
cleanup deadline stops replacement and reports cleanup as unconfirmed. Limits
are 65,536 directory entries, 8,192 bytes per stat read and one second per scan;
these are finite observation ceilings, not measured device performance.

The status exposes `cleanup_scope=original_process_group_only`, a per-child
`group_cleanup` observation and `escaped_descendants_absence_proven=false`.
A process group is not a containment boundary for `setsid`/`setpgid` escape.
Installed L2 evidence must additionally establish the service cgroup/namespace
boundary, cgroup-wide cleanup, supervisor-death behaviour and a complete procfs
view. Local fork tests do not close those installed-target requirements.

Any emergency marker, including a dangling symlink or unreadable marker state,
inhibits startup/restart. Inhibit, status and event-log leaves must be distinct
and cannot contain each other. Stop/inhibit is checked between initial child
starts and again before a replacement; already accepted effects are not retried.

Reproduce the local lifecycle boundary from the repository root:

```sh
python3 -m unittest tools.tests.test_owner_open_rootlinux_supervisor -v
```

The fixture creates real local descendants with a pipe readiness handshake,
including TERM-resistant children; no timing-only assumption establishes their
existence. Test-only subreaping collects fixture orphans. Both exact-head and
synthetic-merge source lanes explicitly run this suite. No fixture is evidence
of a physical device, target installation or external-effect rollback.

### Supervisor state-directory and persistence contract

The supervisor acquires a nonblocking exclusive `flock` on the opened state-root
directory **before writing status/events or starting any carrier**. Every state
root and output-parent component is opened with directory/no-follow semantics;
new private parents are created relative to retained descriptors and their parent
entries are synchronized. Existing non-private state directories are rejected,
not silently chmodded. The same rule applies to nested emergency-marker parents.
The directory lock is advisory, local to the inode and retained until final
cleanup/reporting; a competing cooperating supervisor gets a startup error
without changing the first instance's files or spawning children.

State I/O uses the retained parent descriptors, not re-opened absolute output
paths. Namespace checks detect replaced, missing, symlinked or permission-changed
state directories before admission and on inhibit checks. An unavailable parent
is an inhibit condition, **not** evidence that the marker is absent. Descriptors
are close-on-exec and are released on successful, inhibited and failed exits.
Config pathnames are limited to 4,096 UTF-8 bytes and 64 components; at most the
three output-parent chains are retained. These are finite source bounds, not a
measurement of installed descriptor use or filesystem latency.

The two persistence protocols differ:

| Operation/cut | Required source behavior |
|---|---|
| Event write returns a positive short count | Continue writing the remaining bounded bytes; no early success |
| Event write returns zero or an invalid count | Fail immediately; do not spin |
| Event write/file-fsync/directory-fsync fails | Fence further event appends and new carrier admission for this instance; preserve uncertain bytes |
| Existing event tail lacks newline | Reject before first spawn; do not truncate, synthesize a terminal or concatenate another record |
| Event file is symlinked, multiply linked, non-private or non-regular | Reject without writing; use nonblocking open so a FIFO cannot stall the check |
| New event file is written | Synchronize file bytes and parent directory entry before returning success |
| Status write or file-fsync fails before rename | Preserve prior status; remove this attempt's temporary leaf during handled failure |
| Status publication succeeds | Complete write, fsync temporary file, descriptor-relative atomic replace, then fsync parent |
| Parent fsync fails after status rename | Return failure: new bytes may be visible but durability is unknown; do not infer rollback |
| Cleanup audit append fails | Reap all already-settled direct leaders first; storage failure cannot abandon later anchors |

The startup `supervisor_starting` event is an observation and log-health check,
not an acceptance record for a semantic job. Event-tail checking verifies the
record delimiter only; it is not a complete journal-schema/history verifier.
Supervisor events/status must never substitute for the Host's authoritative job
acceptance and reconciliation protocol. No failure path authorizes effect replay.

**Trust and failure limits:** this directory lock does not fence distributed
writers, a renamed/replaced root inode, malicious same-UID/root actors or child
processes surviving a supervisor crash. The installed service manager must keep
the state namespace stable and enforce cgroup-wide cleanup before restarting a
dead supervisor. Rechecking a pathname is not an atomic barrier against a marker
created concurrently with process spawn. Filesystem fsync calls in local tests
are not evidence of real power-loss durability. Those remain installed L2/L5
qualification obligations; `escaped_descendants_absence_proven` remains false.

### Supervisor crash-session fence

The volatile directory lock and the durable session marker solve different
problems. After acquiring the lock, `Supervisor.run` rejects **any** pre-existing
`<state_root>/.supervisor-session.json` before changing event/status files or
starting a carrier. Empty, torn, old-looking, symlink, FIFO and directory entries
all mean reconciliation-required. It never decides a previous session is safe
from a stored PID, PID absence, wall-clock age, readable terminal status or a
released lock. The reserved marker and its descendants cannot be configured as
inhibit, status or event-log paths.

`begin_session` exclusively creates a private, non-inheritable marker containing
schema `org.trillionnium.owner-open.rootlinux-supervisor-session.v1`, a random
32-hex `session_id`, diagnostic `supervisor_pid`, `pid_is_recovery_authority=false`,
`automatic_effect_redispatch=false`, and the original-process-group scope. It
completes short writes, fsyncs the file, then fsyncs the pinned root **before the
first spawn**. Even a failed/partial creation is retained; no age-based recovery
or implicit repair exists. The marker has a fixed-size payload (under 1 KiB),
not an unbounded process registry. Every spawn and loop iteration checks its
inode, private regular-file properties and exact bounded bytes. Status/events
carry the same session ID; pre-admission inhibited observations may carry null.

After a normal stop or a handled emergency stop, `finish_session` requires all
tracked original groups cleaned, direct leaders reaped and the terminal status
and event already written. It checks ownership again, unlinks relative to the
pinned root, then fsyncs that directory. The independent owner inhibit is never
removed. Any failed run (including restart-budget exhaustion), terminal-storage
failure, unconfirmed cleanup or process death leaves the marker for offline
reconciliation. A post-unlink fsync error is a failed release with uncertain
persistence, not success; the last terminal observation is not a release receipt.

A real local regression kills the supervisor with SIGKILL, observes its carrier
still alive, then verifies a second supervisor returns HOLD without starting a
second carrier or using the recorded PID as authority. The test itself uses a
subreaper to safely collect its own orphan. This source regression is not an
installed-process matrix, power-loss test or cgroup containment proof. The fence
blocks automatic takeover; it does **not** terminate surviving processes, resist
a malicious root custodian, fence a replaced root inode or prove escaped children
absent. L2 still requires independent whole-service reconciliation.

### Selected image-builder subprocess and snapshot contract

The selected builder is `tools/owner-open/build_owner_open_rootfs_image_release_v2.py`;
its shared implementation is `build_owner_open_rootfs_image_release.py`.
Both help probes and builds run through the same bounded raw-byte command pump.
It requires Linux `waitid(WNOWAIT)`, default SIGCHLD handling, exclusive reaping
of the direct child and a complete same-namespace procfs view. No `communicate()`
or `poll()` consumes unbounded output or prematurely reaps the group anchor.

Stdout and stderr share the existing 16 MiB capture ceiling. Reads are at most
64 KiB, and remaining capacity plus one sentinel byte limits each read; excess
output fails immediately rather than being checked only after process exit.
Raw bytes, nonzero/signal exit status and their SHA-256 hashes retain the existing
command-result format. The library timeout is finite, 0.001..1800 seconds; the
CLI retains its stricter existing probe/build intervals. Booleans, NaN and
infinite budgets are rejected before starting a process.

Normal leader exit, execution deadline, output overflow, read/selector failure
and setup failure all retire the original group. TERM (1 second) is followed by
KILL (2 seconds) while the leader remains waitable. Two quiet procfs observations
must agree before cleanup is confirmed; each scan is bounded by 65,536 entries,
8,192 bytes per stat and one second within its phase deadline. Reaping has at
most one additional 2-second interval. A lost/reaped anchor never authorizes
another group signal. Signal, scan or reap errors prevent image qualification;
reaping a leader alone cannot turn unconfirmed cleanup into success.

After normal retirement, pipe draining has a separate 1-second ceiling. An
escaped descendant holding a writer produces an explicit drain error and local
pipes are closed, not an infinite wait. This does not terminate escaped children,
prove cgroup containment or constrain synchronous kernel calls. A trusted tool,
stable private namespace and independent build-service containment remain
required. The helper does not retry a command or grant target/release authority.

The original validated staging manifest and its exact bytes remain the authority
for every reproduction run. Each normalized input tree is checked against that
same snapshot **before and after** the image tool runs, including file set, bytes,
hashes, modes, embedded manifest and the runtime-state mountpoint. Rewriting both
external and embedded manifests after the help probe does not change the accepted
snapshot. The tool's expected digest is rechecked before each build and again
before image receipt publication. Equal output hashes from two runs are not
sufficient when the inputs or recorded tool identity have drifted.

These are interval checks, not atomic executable identity or protection from a
malicious tool that changes and restores data between checks. They do not parse
the resulting squashfs to prove its semantic contents. Real toolchain custody,
filesystem durability, Android inclusion and installed inventory require the
existing L2/L3/L5 evidence. No manifest schema or evidence ceiling is promoted.
The extra hashing passes trade bounded I/O for provenance checks; no performance
improvement or installed latency claim is made.

Reproduce the selected staging/build tests with:

```sh
python3 -m unittest tools.tests.test_stage_owner_open_rootfs_payload_release tools.tests.test_build_owner_open_rootfs_image_release_v2 -v
```

Exact-head Android-packaging CI explicitly runs this suite; synthetic-merge full
test discovery also includes it. Local fork/fault fixtures and deterministic fake
image tools establish only source behavior, never an actual Android image.

### Final image identity and publication boundary

Reproduction records alone do not establish the identity of the retained image.
The shared builder now remeasures **every run image after all tool invocations**
against its original digest, byte count and mode before comparing reproduction
records. A later run that changes an earlier image cannot receive a successful
receipt using the earlier digest. The library, like the CLI, requires 2..4 runs;
a single build is not reproducibility evidence.

`image_snapshot` opens an image relative to a retained immediate-parent descriptor
with no-follow/nonblocking/close-on-exec flags. It requires one nonempty bounded
regular file, an allowed owner, one link, no special or group/world-write bits,
and stable descriptor/name metadata across hashing. Capture is streaming, at most
1 MiB per read and at most the existing 8 GiB limit plus one overflow sentinel;
image bytes are not accumulated in memory. Observed growth, replacement, mode,
size or digest drift fails closed. This is interval validation under the existing
trusted-tool/private-namespace assumptions, not immutability against privileged
writers or squashfs format/content verification.

Final image publication uses a create-only hard link followed by removal of the
run name. It cannot overwrite an unexpected existing selected-image name. An
unexpected final manifest is also rejected. The selected image is verified again,
set to mode 0444 using its open descriptor, fsynced, and its parent is fsynced
**before** the manifest is published. Every image/manifest link is within the same
output directory/filesystem; a filesystem without the required hard-link or sync
operations fails rather than falling back to a weaker copy/overwrite protocol.

The manifest uses an exclusively created private temporary file, exact short-write
completion, file fsync, create-only final link, temporary unlink and parent fsync.
It refuses nonfinite JSON, manifests above 16 MiB and modes other than 0600. It
never overwrites an existing manifest, and cleanup removes only a temporary whose
inode still matches this attempt. A second final-image check after manifest
publication must still match before the command may return success.

Image and manifest are **separate durable operations**, not an atomic pair.
Before the publication phase, build errors retain the existing removal behavior.
Once final publication is attempted, an error leaves the output directory intact
and reports `image publication incomplete; output retained`. This includes image
sync failure, final-name collision, manifest sync failure and late image drift.
A visible manifest or image alone is not successful qualification; consumers must
require a successful command result and independently verify the image digest.
Preserve and reconcile retained partial output instead of rerunning the build into
that directory, deleting uncertain receipts or claiming rollback. No new marker
or file-existence test grants installed, Android, fault or release authority.

The existing selected-builder suite includes later-run tampering, no-clobber final
names, short reads/writes, concurrent file replacement, capture limits, descriptor
cleanup, and pre/post-publication sync failures. These injected faults do not prove
power-loss durability. Extra hash/sync passes have unmeasured I/O cost and do not
establish an installed performance baseline or independently authorized custody.

## 11. Security and trust boundaries

Root capability is minimized and mechanically scoped. Packaging cannot add semantic policy, substitute unpinned provider bytes, broaden namespaces or silently select a legacy authority path.

Peer identity, process identity, executable or artifact digest, epoch, namespace and target identity are retained where relevant. Secrets and command content are redacted by default. Emergency inhibit is independent of provider health and prevents new admission without fabricating terminal outcomes.

## 12. Failure matrix and degraded behavior

| Failure | Required classification | Required behavior |
|---|---|---|
| Invalid or unsupported input | rejected-before-accept | no state mutation and no external start |
| Capacity exhausted | rejected-at-admission | no spawn, forward or durable accepted record |
| Timeout or disconnect before terminal proof | unknown/reconciliation-required | stop blind progress; preserve exact identity |
| Process or dependency exit | explicit failure or unknown | converge descendants and fence the epoch |
| Storage I/O or fsync ambiguity | degraded/fail-closed | stop authoritative writes; retain ambiguity |
| Corrupt state | quarantined or fail-closed | no automatic replay |
| Stale writer or lease | fenced | reject the write and emit an audit observation |
| Duplicate identity with changed content | conflict | never deliver the old terminal as the new result |

The degraded state is `fail_closed`. Recovery is `reconcile_before_resume`, and uncertain effects remain `no_automatic_redispatch`.

## 13. Compatibility, migration and rollback

Rolling compatibility is supported under the explicit compatibility and fencing contract. Read/write compatibility currently accepts `v1` and writes `v1` unless the module-specific migration below states otherwise.

Image and service upgrades are manifest-bound. A new service epoch starts only after payload, ownership, mount and state-schema checks pass; rollback restores the last compatible immutable image and fences newer writers.

Rollback is fail-closed. Stateful modules restore the last compatible durable state, fence newer writers and reconcile external effects before admission. A rollback may restore software and state compatibility; it cannot erase an effect already attempted outside the module.

The supervisor configuration and output schema IDs remain `v1`; existing
well-formed private paths and newline-terminated event files remain readable.
Admission is intentionally stricter for non-private parents, symlinked ancestors,
unsafe event leaves and competing owners. During an offline upgrade, stop the
service through its independently administered inhibit, verify no old carriers
remain, inspect owner/mode and every state path component, and explicitly prepare
private directories. Never change permissions or replace a state-root directory
under a running supervisor to make validation pass. Preserve torn event bytes
for operator reconciliation; do not delete/truncate them as an automatic repair.
A terminated process can leave its temporary status file; remove only verified
inactive temporary artifacts during controlled maintenance, not while a writer
holds the root. Rolling back to an older binary removes these new local checks
and therefore needs renewed qualification rather than inherited assurance.

The crash-session fence is a stricter restart contract. Existing v1 config remains
valid except for the reserved `.supervisor-session.json` path. An init restart
loop must not delete that file. To clear a retained marker, an independent
operator must first inhibit and stop the entire service, verify cgroup-wide
cleanup and old-writer absence, preserve the exact marker/status/event bytes,
and reconcile authoritative Host/job state without replay. Only under exclusive
state-root ownership may the operator remove the verified inactive marker and
sync its parent, recording the authorization and reconciliation result outside
the candidate process. PID liveness, a `terminal` string or elapsed time is not
sufficient. A crash during this procedure remains HOLD. Rolling back to a
binary that ignores session fences requires the same offline procedure and new
qualification; do not regain availability by weakening admission.

The additive `session_id` status/event field needs compatibility validation for
consumers that reject unknown fields. The session schema is independent of the
Host effect journal and grants no controller epoch or release authority.

## 14. Observability

Retain payload hashes, signer identity when available, UID/GID, namespaces, mounts, cgroup limits, service epoch, restart count, readiness and inhibit state.

Every metric and log record is bounded and versioned. Required common dimensions are module ID, instance or service epoch, ordering-key digest, operation class and outcome. High-cardinality raw identifiers are hashed or retained only in access-controlled evidence. Readiness means the module can safely admit work; liveness alone is insufficient.

## 15. Verification and evidence

Minimum evidence level declared by the catalog: `L1`.

Source qualification must include unit, concurrency, migration and negative tests, exact clean checkout identity, generated-document verification and immutable artifact digests. Higher-level claims require separate installed-target, Android graph, physical-device, destructive-fault or release packages.

Evidence ceiling: **SOURCE_ONLY_UNTIL_EXACT_HEAD_CI**.

The module documentation verifier checks this document against the machine catalog, verifies required sections and source paths, binds the API and state schema identifiers, checks the provisional budget record and rejects unregistered or misleading documentation.

### Reproduction entrypoint

- Verification source: `tools/tests/test_verify_owner_open_rootfs_payload_selection.py`

Run from the repository root in an isolated host source-test environment:

```sh
python3 -m unittest tools.tests.test_verify_owner_open_rootfs_payload_selection -v
```

This command qualifies only the source behavior that its assertions exercise.
It neither installs the product nor grants L2-L6 evidence. Reproduce the specific
failure before changing a timeout, disabling an assertion or modifying a budget.

## 16. Deployment and runbook

On manifest drift, stop admission, preserve the live filesystem and service metadata, compare exact payload hashes, restore a known compatible image or remain inhibited. Do not bless the live drift in place.

Standard deployment sequence:

1. Bind the exact source and dependency graph.
2. Validate configuration, identity, finite budgets and migration compatibility.
3. Start in inhibited or observe-only state.
4. Recover and reconcile authoritative state.
5. Prove readiness before enabling admission.
6. Drain, fence and retain terminal observations during shutdown.
7. Preserve the exact evidence subject for every promotion decision.

## 17. Open gaps and exit criteria

Open machine gaps: `GAP-PRODUCT-ENTRYPOINT-001`, `GAP-INSTALLED-CODEX-001`, `GAP-ROOTLINUX-PLACEMENT-001`, `GAP-ANDROID-GRAPH-001`, `GAP-RELEASE-001`.

### GAP-PRODUCT-ENTRYPOINT-001 — exit L3

One install manifest selects the product entrypoint and internal children.

Exit evidence must demonstrate:
- source entrypoint is unambiguous.
- target-files contain the exact selected binaries.
- foundation stubs are absent from product inventory.

### GAP-INSTALLED-CODEX-001 — exit L2

Exact installed Codex bytes, identity and same-turn tool callbacks are qualified.

Exit evidence must demonstrate:
- installed hash and signer are bound.
- provider session is authenticated.
- same-turn shell and job trace is retained.
- no hidden retry occurs.

### GAP-ROOTLINUX-PLACEMENT-001 — exit L2

Installed UID, GID, namespaces, cgroups, mounts, stores and restart policy are bound.

Exit evidence must demonstrate:
- install manifest matches the live target.
- resource limits are observed.
- restart and emergency inhibit work.
- an unclean supervisor session blocks new carrier admission until independently reconciled.
- state writes and parent-directory durability failures remain explicit; no torn log is automatically repaired.

### GAP-ANDROID-GRAPH-001 — exit L3

A clean Android graph contains selected owner-open components and no legacy semantic nodes.

Exit evidence must demonstrate:
- clean source and target-files are retained.
- Soong, init, SELinux and package inventory agree.
- installed manifest identities match.

### GAP-RELEASE-001 — exit L6

Signing, transparency, AVB, rollback, OTA, key custody and human authorization are bound.

Exit evidence must demonstrate:
- cryptographic verification passes.
- independent release authorization exists.
- all other gaps are closed.
- public release is explicitly enabled.

A source change may reduce implementation risk, but the status stays open or source-closed-pending-evidence until an immutable, current, independently authorized receipt reaches the declared exit level.
