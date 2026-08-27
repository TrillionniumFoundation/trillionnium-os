# r4 execution amendment: W2 direct process and W3 raw ADB

Revision: **2026-08-27-r4-w2w3-a1**  
Status: **ACTIVE AMENDMENT TO THE R4 EXECUTION PLAN**  
Applies to: `docs/TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md`

This amendment refines W2 and W3 without changing the r3 semantic contract.
When this document is more specific than the original W2/W3 work-package text,
this amendment controls sequencing and acceptance. It does not override W0
profile isolation, W1 same-turn Codex ownership, W5 recovery or W8 evidence
requirements.

## 1. Problem statement

The previous plan correctly required direct shell and raw ADB but grouped too
many independent proofs into broad rows. That creates three failure modes:

1. source wrappers can be mistaken for an integrated Agent capability;
2. a fake/host adb executable can be mistaken for a device-image transport;
3. a successful command can be mistaken for correct cancellation, restart and
   unknown-effect behavior.

W2/W3 are therefore split into explicit maturity gates. A later gate may depend
on an earlier gate's interface, but no source/test/evidence may be promoted
across a missing gate.

## 2. Revised critical path

```text
W0 default graph isolation
  -> W1 correlated same-turn Host/provider loop
  -> W2.0 process substrate source
  -> W2.1 Host tool bridge
  -> W2.2 Root Linux identity/namespace placement
  -> W2.3 stream/backpressure/job mechanics
  -> W3.0 exact adb process boundary
  -> W3.1 ARM64 adb artifact and BOM
  -> W3.2 owner-host server/reverse transport
  -> W3.3 same-turn physical ADB effect
  -> W3.4 disconnect/reboot/server fault qualification
  -> W5 durable reconciliation/self-development
  -> W8 L4/L5 closeout evidence
```

W2.0 and W3.0 may be developed before W1, but they do not become product tools
until W2.1 binds them to the same provider turn.

## 3. W2.0 — mechanism-only process substrate

### Scope

- command-string and argv invocation;
- cwd, inherited environment delta and binary stdin;
- raw stdout/stderr chunks;
- monotonic sequence and one terminal event;
- timeout/cancel/output-exhaustion process-group cleanup;
- no semantic command filtering.

### Source

- `crates/trillionnium-owner-open-runtime`
- `docs/implementation/owner-open-process-substrate-v1.md`

### Exit criteria

- Rust 1.93 format and tests pass;
- feature tree contains no legacy Trillionnium package;
- binary output and non-zero exit are retained;
- command and argv paths are both tested;
- cancellation/timeout terminate a forked descendant, not only the direct
  child;
- output exhaustion emits exactly the configured delivered byte count;
- invalid request emits no accepted/spawn event;
- status remains no higher than `HOST_TESTED`.

### Current state

`SOURCE_AUTHORED_VALIDATION_PENDING`.

## 4. W2.1 — correlated Host tool bridge

### Scope

Translate a provider-native or wire tool call from one active owner-open turn
into W2.0 and return every event to the same turn stream.

### Required Host state

```text
(session_id, profile_id, task_id, turn_id, turn_stream_id)
  -> call_id
     -> request_sha256
     -> binding_fingerprint
     -> cancellation token
     -> dispatch state
     -> terminal state
```

### Invariants

1. Same `call_id` plus same request bytes attaches/replays existing local state.
2. Same `call_id` plus different request bytes is
   `invalid_frame_call_id_conflict`.
3. The Host never spawns twice for one accepted call record.
4. `tool.cancel` resolves only within the correlated turn/profile scope.
5. Raw output is encoded for the wire without UTF-8 loss.
6. Backpressure pauses delivery or spools; it does not kill or re-run a command
   unless a mechanical owner limit explicitly requires termination.
7. One process terminal maps to one terminal tool event.
8. Provider continuation receives the exact terminal observation in the same
   turn.
9. The old Agent plan, shell broker, Authority and typed ADB are not imported.

### Exit criteria

- in-memory duplicate-call and conflict tests;
- output chunk ordering/sequence tests;
- binary wire golden vectors;
- cancellation race tests;
- provider fixture calls shell and continues after success and deliberate
  failure;
- Host process integration proves no second spawn after duplicate delivery;
- claim level no higher than L2 until a live Codex provider is used.

## 5. W2.2 — Root Linux execution placement

### Scope

Run the W2 process substrate inside the configured Android-managed Root Linux
execution environment.

### Required binding facts

- rootfs generation/hash;
- writable overlay generation and mount points;
- execution UID/GID/supplementary groups;
- capabilities and no-new-privs setting;
- mount, PID, network and user namespace selection;
- cgroup path/resource generation;
- cwd and environment generation;
- shell executable path/hash;
- Host boot/process generation.

These are correlation and recovery facts in owner-open. They are not semantic
command admission fields.

### Exit criteria

Inside the selected environment, one same-turn fixture runs:

```sh
id
uname -a
pwd
command -v adb
printf 'binary\000output'
```

Additional acceptance:

- kill the process Host and prove no untracked descendant remains;
- kill the Root Linux launcher and observe interruption/restart honestly;
- missing cwd, read-only filesystem, ENOSPC and SELinux denial remain raw
  observations;
- restart never silently redispatches an uncertain call.

## 6. W2.3 — streaming, jobs and liveness

### P0 synchronous call

- bounded output window;
- pause/resume delivery;
- spill-to-disk after memory window;
- exact accepted/started/chunk/terminal sequence;
- cancellation and timeout.

### P1 long-lived job

- `shell.job.start`;
- status/attach/write/resize/close-stdin/kill;
- PTY session and process group;
- durable job identity scoped to session/profile;
- inclusive cursor replay;
- owner retention/TTL as liveness, not authorization.

### Exit criteria

- slow consumer does not reset the call or lose byte boundaries;
- client disconnect does not cause automatic duplicate execution;
- job attach after a later turn requires explicit correlated identity;
- crash with no durable dispatch proof becomes `unknown_after_disconnect`;
- terminal events are replayed with stable event IDs only after durable commit.

## 7. W3.0 — exact ADB process boundary

### Scope

Use W2.0 to invoke a configured ordinary adb executable with exact argv.

### Invariants

- argv excludes program name;
- argv must be non-empty;
- no serial/host/port/target/privilege injection;
- unknown subcommands are valid;
- target label is correlation only;
- no typed request enum;
- no conversion of stderr into semantic HOLD/denial.

### Exit criteria

A fake adb executable records exact argv for:

```text
["devices", "-l"]
["-s", "serial", "shell", "id"]
["future-subcommand", "--future-option", "value with spaces"]
```

No extra argument may appear.

### Current state

`SOURCE_AUTHORED_VALIDATION_PENDING`.

## 8. W3.1 — ordinary Linux ARM64 adb artifact

### Decision

Root Linux receives an ordinary Linux ARM64 adb client from a reproducible AOSP
build or recorded distribution package. The existing typed
`trillionnium-agent-adb` artifact is forbidden as a substitute.

### Required BOM facts

- source repository/package and exact revision/version;
- source/license notices;
- build command/toolchain or package repository metadata;
- architecture and ELF metadata;
- SHA-256 and size;
- install path and mode;
- dynamic dependencies or static closure;
- `adb version` raw output;
- rootfs package/manifest generation.

### Exit criteria

```sh
file /usr/bin/adb
sha256sum /usr/bin/adb
/usr/bin/adb version
```

match the BOM and rebuilt Root Linux payload.

## 9. W3.2 — owner-host server and local reverse transport

The accepted dogfood topology is defined by
`docs/architecture/2026-08-27-owner-open-raw-adb-topology.md`.

### Source bootstrap

- canonical script: `tools/owner-open/prepare-adb-reverse-v1.sh`;
- requires exact serial and explicit apply/remove;
- default device loopback port 15037;
- default owner-host server port 5037;
- checks host listener exposure;
- writes bounded evidence with all integrated/product claims false.

### Exit criteria

- fake-adb tests pass;
- exact mapping is observable through `adb reverse --list`;
- Root Linux can connect to the device loopback endpoint;
- ordinary ARM64 client returns host-server version/device list;
- endpoint/config generation is recorded per call;
- removing the mapping makes the next call return the real connection error.

Bootstrap proof remains separate from integrated Codex proof.

## 10. W3.3 — same-turn physical effect

### Required sequence

One live Codex turn invokes through the integrated Host:

```text
adb.exec(["devices", "-l"])
adb.exec(["-s", "ZY32JLVHGN", "shell", "id"])
adb.exec(["-s", "ZY32JLVHGN", "shell", "sh", "-c",
          "echo owner-open > /data/local/tmp/tos-probe"])
adb.exec(["-s", "ZY32JLVHGN", "shell", "cat",
          "/data/local/tmp/tos-probe"])
```

### Exit criteria

- model text, tool-call event, exact argv, raw stdout/stderr/exit and final model
  continuation share one turn lineage;
- no legacy broker/Authority process is started;
- serial is present because Codex supplied it, not because the wrapper injected
  it;
- the device file proves a real effect;
- evidence binds source SHA, Android manifest/overlay, rootfs/adb hashes, Host
  config generation and device build fingerprint.

## 11. W3.4 — fault qualification

Required fault matrix:

| Fault | Required observation |
| --- | --- |
| ARM64 adb missing | `spawn_failed`, no started event |
| host server absent | raw client connection error |
| device unauthorized | raw adb unauthorized state |
| device offline | raw adb offline state |
| multiple devices/no serial | raw multiple-device error |
| USB loss before dispatch proof | `not_started` only with positive proof |
| USB loss after possible dispatch | `unknown_after_disconnect` |
| host server restart | real terminal or unknown; no auto retry |
| phone reboot | old turn interrupted; new turn inspects/resumes |
| Host crash | no silent duplicate; inspectable call state |
| cancellation | client process group closed; remote state not guessed |
| output exhaustion | bounded raw prefix plus resource terminal |

Every mutating retry uses a new call ID unless the old call is proven not
started.

## 12. Status and evidence update rules

Each W2/W3 change must update in the same PR:

- relevant source/tests;
- this amendment when acceptance changes;
- implementation/ADR documents;
- machine status;
- traceability;
- evidence record or explicit validation hold;
- PR non-claims.

Status levels are monotonic only with evidence:

```text
NOT_STARTED
SOURCE_AUTHORED_VALIDATION_PENDING
SOURCE_IMPLEMENTED
HOST_TESTED
ROOTLINUX_TESTED
IMAGE_INCLUDED
DEVICE_OBSERVED
FAULT_TESTED
RELEASE_QUALIFIED
```

A later source edit invalidates dependent evidence unless its bound source/hash
set is unchanged or the evidence is repeated.

## 13. Immediate execution order after this amendment

1. Run Rust 1.93 format/test for `trillionnium-owner-open-runtime` and capture
   Cargo feature/lock evidence.
2. Add a forked-descendant cleanup integration test.
3. Add the Host call registry and W2.1 runtime adapter.
4. Add binary event-to-wire golden vectors.
5. Connect a provider fixture through one turn, including deliberate failure.
6. Implement/verify the ordinary ARM64 adb artifact and BOM.
7. Execute the fake-adb bootstrap tests, then the explicit real-device reverse
   bootstrap.
8. Bind live Codex to the same Host turn.
9. Run W3.3 physical effects.
10. Run W3.4 fault matrix and update W8 closeout evidence.

Work on public signing, multi-user policy or sealed approval must not block
steps 1-9.

## 14. Definition of W2/W3 complete

W2/W3 are complete only when:

- the Android owner-open default graph excludes every forbidden legacy node;
- one live Codex turn executes direct Root Linux shell and raw ADB;
- exact raw observations return to that same turn;
- timeout, cancel, Host crash, provider crash, USB loss, server restart and
  reboot obey the documented uncertainty rules;
- no command is semantically gated or rewritten by the substrate;
- no ambiguous effect is automatically duplicated;
- the owner can stop respawn and recover out of band;
- source, image, rootfs, adb, config and device identities are bound in L4/L5
  evidence;
- machine status and README make no stronger claim.
