# Owner-open threat model

Revision: 2026-08-27-r4  
Scope: owner-authorized single-device dogfood profile  
Not a claim: public multi-user or consumer-release security certification

## 1. Security posture

Owner-open intentionally gives the configured Codex runtime broad control of
Root Linux and connected Android targets. The model may issue arbitrary shell
commands and raw ADB argv. This profile optimizes for rapid owner-controlled OS
iteration and truthful observations, not containment of a malicious or fully
compromised semantic Agent.

Removing a second semantic Authority is deliberate. It avoids policy drift,
hidden command rewriting and a dual-Agent architecture. It also means a
successful compromise of the Codex/provider path can become device compromise.
The profile therefore relies on explicit owner trust, mechanical isolation,
short feedback loops, recoverable devices and an out-of-band emergency path.

## 2. Protected assets

- owner credentials and provider tokens;
- Android userdata, accounts and application data;
- Root Linux workspace and source tree;
- ADB private keys, pairing state and server endpoints;
- source, build and update integrity;
- event log authenticity and raw observation bytes;
- availability of Android boot, init and recovery;
- accuracy of effect state, especially after disconnect/restart;
- separation between owner-open and any sealed/public profile;
- release signing and rollback material, when later introduced.

## 3. Trust boundaries

### 3.1 User/AiShell to Direct Agent Host

The local transport decides which peer can request owner-open effects. Socket
mode, Android peer credentials/SELinux or inherited stdio are mechanical
admission controls. Any admitted owner-open peer is powerful; admission is not
per-command approval.

### 3.2 Host to Codex/provider

The Host launches or connects to the configured provider runtime, supplies
credentials through explicit paths/FDs and receives model/tool events. Provider
text is untrusted data. Only correlated tool events count as process/ADB
observations.

### 3.3 Host to Root Linux process substrate

Command bytes, argv, environment, cwd, stdin and PTY cross into a broad execution
domain. Process-group ownership, namespaces, FD inheritance and resource limits
are critical even though command semantics are not filtered.

### 3.4 Host to ADB transport and target

ADB output and connected devices are untrusted. A device may be offline,
unauthorized, compromised, rebooting, in recovery, or a different serial than
expected. The wrapper must not conceal the actual adb decision.

### 3.5 Host to event/spool storage

Storage may fail, fill, corrupt or be modified. Logs support inspection and
replay but must not silently become effect admission or proof that no action
occurred.

### 3.6 Android init and emergency recovery

Android owns process respawn and the out-of-band stop. Emergency recovery must
work when Codex, provider, Root Linux or Host is wedged or malicious.

## 4. Threat actors and assumptions

### In scope

- malicious prompt or retrieved content;
- compromised provider account/session;
- compromised Codex runtime or dependency;
- compromised local app/process that gains Host transport access;
- malicious/compromised ADB target;
- corrupted Root Linux workspace or update;
- accidental destructive model/owner command;
- resource-exhaustion input or output;
- crash, disconnect, reboot, power loss and disk full;
- stale or replayed client frames;
- source/build/profile drift reintroducing legacy nodes.

### Accepted owner-open risks

- Codex can intentionally or accidentally destroy owner data or render the
  dogfood device unbootable;
- prompt injection may lead to harmful commands if Codex fails to reason about
  the content;
- root/ADB authority can escape application-level boundaries by design;
- plain owner-configured logs/workspaces may expose sensitive material to the
  owner/root domain;
- owner-open is unsuitable for untrusted multi-user deployment.

### Out of scope for owner-open closeout

- protection from a malicious physical owner;
- public release anti-rollback and production key ceremony;
- hostile multi-tenant isolation;
- preventing every owner-authorized destructive command;
- confidential-computing protection from the device root owner.

## 5. Threats and required mitigations

### 5.1 T1. Unauthorized local peer reaches the Host

Impact: arbitrary Root Linux/ADB control.

Required mitigations:

- local-only endpoint by default;
- exact owner/group mode for filesystem sockets;
- peer credential and SELinux checks for Android abstract sockets;
- no TCP/HTTP bridge unless explicitly configured and recorded;
- startup refusal on unsafe parent/symlink/socket ownership;
- connection and per-peer resource bounds;
- evidence listing endpoint exposure and permitted peers.

Owner-open semantics do not permit a world-writable socket.

### 5.2 T2. Prompt injection causes destructive actions

Impact: data loss, credential theft, malicious updates, device brick.

Required mitigations:

- Codex visibly receives provenance/context boundaries;
- secrets are not inserted into model text by the substrate;
- owner backups and restore images exist before destructive dogfood;
- out-of-band stop and recovery remain available;
- raw events make the actual command and result inspectable;
- no intermediate service rewrites a dangerous command into something that
  appears safer;
- sealed/public profile, when needed, adds policy outside owner-open defaults.

This threat is not solved by pretending the substrate can infer intent.

### 5.3 T3. Credential exfiltration through environment, argv, logs or output

Impact: provider/account compromise and persistent access.

Required mitigations:

- credentials use owner-configured files or named inherited FDs;
- FDs are `CLOEXEC` unless explicitly inherited;
- event records distinguish secret-bearing metadata from publishable output;
- argv/environment logging has an explicit redaction/display policy while exact
  request custody remains owner controlled;
- crash diagnostics do not dump credentials by default;
- credential rotation runbook and provider revocation are documented;
- no model prompt contains private key/token bytes unless the owner explicitly
  requests it.

### 5.4 T4. Child process escapes lifecycle ownership

Impact: stale privileged process survives cancel/Host crash and consumes future
input or keeps modifying the system.

Required mitigations:

- process group/session ownership before untrusted execution;
- cgroup or equivalent descendant tracking where available;
- no accidental inherited listener/control FDs;
- subreaper/child reaping strategy;
- explicit signal escalation and observed-gone result;
- Host crash reconciliation and emergency init stop;
- tests for grandchildren, daemonization, fork bomb and FD leaks.

### 5.5 T5. Output or input resource exhaustion

Impact: Host/UI/Android instability, disk full, deadlock.

Required mitigations:

- finite frame/argv/env/FD/process/output/spool bounds;
- explicit flow-control windows;
- bounded memory and disk spool quotas;
- nonblocking or independently drained stdout/stderr;
- PTY and pipe deadlock tests;
- resource errors preserve effect-state uncertainty;
- global Android survival floor independent of semantic policy.

### 5.6 T6. ADB wrapper changes the requested operation

Impact: wrong device, unexpected privilege, false success/failure.

Required mitigations:

- raw argv pass-through;
- no automatic serial/host/port injection;
- target labels recorded as hints;
- exact executable/server topology in configuration/evidence;
- raw stdout/stderr and exit status;
- multiple-device/unauthorized/offline errors preserved;
- tests with unknown/future subcommands.

### 5.7 T7. Disconnect/restart causes duplicate effects

Impact: repeated install/delete/reboot/payment-like external action.

Required mitigations:

- call-id plus exact request-byte binding;
- accepted/started/terminal record order;
- duplicate identical call attaches/replays, never respawns;
- conflicting bytes under same call id fail;
- started/no-terminal becomes inspect or `unknown_after_disconnect`;
- no automatic retry of an uncertain effect;
- Codex/owner chooses a new call id after inspection.

### 5.8 T8. Event store is treated as authorization or perfect truth

Impact: commands denied because logging fails, or absence misreported as no
effect.

Required mitigations:

- storage status is explicit metadata;
- owner-open may execute with `best_effort`/`unreplayable` lineage;
- no record is not proof of not-started;
- corruption is surfaced, not silently repaired into a stronger claim;
- release/sealed profile may require stronger durability under a distinct
  profile.

### 5.9 T9. Legacy Authority/profile code returns to owner-open graph

Impact: dual semantic control plane, hidden gates, oversized attack surface.

Required mitigations:

- isolated owner-open product roots;
- machine-readable forbidden graph;
- negative Cargo/Soong/init/classpath tests;
- explicit sealed/history feature/profile;
- no broad source glob across retired packages;
- target-files and runtime service enumeration;
- change review requiring plan/status/traceability updates.

### 5.10 T10. Supply-chain or update substitution

Impact: malicious Host/Codex/rootfs/image.

Required mitigations for dogfood:

- pinned source and Android manifest;
- exact patch/dirty-overlay hashes until clean commits exist;
- lockfile and toolchain recording;
- generated-file freshness;
- rootfs/Codex/tool artifact hashes;
- build and device evidence binding;
- owner-controlled restore path.

Production signing, AVB/rollback and key ceremony are W9/L6 and must not be
misrepresented as present in owner-open.

### 5.11 T11. Malicious ADB target or backend output attacks parsers/UI

Impact: terminal escape, log injection, memory exhaustion, misleading display.

Required mitigations:

- backend bytes treated as untrusted binary;
- explicit byte count and base64 transport;
- UI escaping and safe rendering;
- bounded chunks/aggregate output;
- stored bytes separate from presentation;
- no parsing of adb stderr into authority decisions.

### 5.12 T12. Emergency stop depends on compromised components

Impact: persistent crash loop or malicious Agent prevents recovery.

Required mitigations:

- Android/init-owned stop that can inhibit respawn;
- trigger available without provider network or Root Linux Host cooperation;
- documented boot/recovery procedure;
- test with wedged provider, Host fork loop and full data partition;
- emergency mechanism performs no semantic planning.

## 6. Security properties required before physical dogfood

Before the first integrated physical effect:

- Host endpoint is not world-accessible;
- provider credential path/FD behavior is known;
- process-group/cgroup cleanup works in host tests;
- output/backpressure bounds exist;
- call-id conflict and duplicate behavior are tested;
- event-store failure does not create a false not-started claim;
- emergency stop procedure is rehearsed;
- backups/restore image exist for the authorized device;
- Android graph does not start the old Authority and new Host together as two
  semantic control planes.

## 7. Security properties required before owner-open closeout

- all L5 fault cases in the r4 plan pass;
- no forbidden owner-open product node or classpath edge remains;
- peer/socket admission is verified in target files and on device;
- provider/Host/tool descendants are cleaned or accurately reported unknown;
- raw binary output cannot inject control into AiShell rendering;
- credential leakage tests and operational rotation are complete;
- recovery works with network unavailable and Codex stopped;
- evidence binds exact source/image/device state.

## 8. Residual risk statement

Even after closeout, an admitted owner-open Codex turn remains capable of broad
system modification. The profile is suitable only for an owner who accepts
that a bad model decision, malicious prompt, compromised provider or flawed
self-update can destroy data or brick the dogfood device. The safety promise is
not “the Agent cannot do harm.” It is:

- no hidden second Agent changes the requested semantics;
- local access is mechanically bounded and observable;
- backend results are returned truthfully;
- uncertain effects are not blindly duplicated;
- the owner has an independent stop and recovery path;
- stronger public restrictions can be added later without blocking owner-open.
