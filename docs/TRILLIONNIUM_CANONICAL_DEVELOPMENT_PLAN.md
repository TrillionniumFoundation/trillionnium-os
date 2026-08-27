# Trillionnium OS — canonical development plan

Revision: **2026-08-27-r3 (Codex-sovereign / owner-open implementation lock)**
Status: **ACTIVE — the only implementation plan**
Control-plane tree: /data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-release-sources/p0-agent-native-integration-20260731/trillionnium-os
Android integration tree: /data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/android/lineage-fogos
Device lane: ZY32JLVHGN (owner-authorised userdebug dogfood)

This revision records the architecture decision made after the 2026-08-26
review. It supersedes the earlier wording that put semantic policy, risk
classification, approval and routing in a second OS control plane. It also
amends the implementation interpretation of the 2026-08-06 direct-shell/ADB
ADR. Old documents and source are retained as history or migration material;
they are not a reason to build another Agent.

## 0. Revision-3 implementation lock (read this before editing code)

This section is the short, normative answer to the latest architecture
discussion. The rest of this document expands it into file-level work. If an
older note, test, generated receipt or package comment disagrees with this
section, the older item is migration/history material and must not be wired
back into the owner-open path.

### 0.1 Two execution lanes, one Agent

There are two useful lanes and they must not be confused:

| Lane | What it does now | What it may not do |
| --- | --- | --- |
| Developer bootstrap | Run the installed Codex CLI in an owner-controlled Root Linux/host shell, with full-access mode, `/bin/sh` and the ordinary `adb` binary. This can start before any generated ABI, OTA, BOM or authority work. | It is not evidence that the Android image already has an integrated Agent Host. Record it as a bootstrap observation. |
| Integrated dogfood | Android init starts one `trillionniumd`/Codex Host, AiShell sends `run_turn`, and the same Codex turn invokes raw shell/ADB and receives observations. | It must not start a broker, planner, approval UI, high-water/egress chain or typed-only mock as a prerequisite. |

The first lane is deliberately usable while the second is being implemented.
The second lane is the product target. Neither lane creates a second semantic
Agent.

### 0.2 Owner-open invariants (non-negotiable)

1. Codex is the only semantic control plane. It chooses intent, context,
   target, tool, policy, consent language, retry/undo and the meaning of a
   result.
2. `shell.exec` accepts a command string or element-preserving `argv`.
   `adb.exec` accepts raw ADB `argv` (or the equivalent ordinary
   `shell.exec("adb ...")`). Root, remount, install, reboot, forward, reverse,
   unknown and future subcommands are valid inputs. No wrapper injects a
   serial, host, port, tier, approval or privilege downgrade.
3. The substrate supplies only process/PTY, IPC framing, transport, storage,
   restart, resource-liveness and out-of-band recovery mechanics. A parser or
   resource ceiling may reject malformed bytes or physical exhaustion, but it
   never labels a command safe/unsafe or allowed/denied.
4. A target rejection, missing ADB authorization, provider outage, SELinux
   denial or configuration error is returned as the real observation. It is
   never renamed `operation_denied`, `mutation_unavailable` or a semantic
   `HOLD` by an intermediate service.
5. A disconnected or rebooted remote target is not guessed. If the dispatch
   record cannot establish whether the effect happened, return
   `unknown_after_disconnect`; Codex probes or chooses a new call id. Do not
   claim exactly-once for general shell/ADB.
6. The only unconditional stop mechanism is an out-of-band emergency path
   that can inhibit init respawn. It is a recovery lifeline, not an approval
   service.

### 0.3 Exact default runtime graph

The default owner-open graph is intentionally small:

~~~text
AiShell/text ingress
  -> @trillionnium_direct_agent_host_v1 (or byte-equivalent stdio bridge)
  -> one trillionniumd owner-open Host
  -> one Codex provider process/session
  -> shell.exec / adb.exec raw process + transport
  -> raw observation -> same Codex turn
~~~

The following are explicitly outside that graph: `AiAuthority`,
`CapabilityLeaseIssuer`, `trillionnium-agent-privilege-broker`,
`trillionnium-privilege-broker-protocol`, `trillionnium_agent_egress_guard`,
`trillionnium_direct_operation_custody_high_water*`,
`trillionnium_shell_exec_broker`/worker, operation-journal promotion/receipt
services, `trillionnium-agentd-materialization-p01-userdebug`,
`trillionnium-p01-runtime-config`, `trillionnium-p01-receipt-stage-*`,
`trillionnium-p01-final-artifact-set-v5`, `trillionnium-shell-exec-artifact-set-v1`,
P01/rootfs contract-receipt/SBOM modules, the fixed-control-FD stdio proxy,
and any P01 measured launcher or typed ADB helper. They may remain as named
`sealed-*`/historical targets, but
must not be compiled, linked, installed, started, or imported by the default
owner-open binary/product. In particular, a workspace member, Soong module,
`PRODUCT_PACKAGES_DEBUG` entry, broad Java glob or Cargo feature-unification
edge is not harmless if it can reintroduce one of these nodes.

### 0.4 Work-package board

The following board is the implementation order. “Done” means the observable
acceptance in the last column, not that a source-only receipt exists.

| ID / owner | Scope and concrete touch points | Depends on | Observable acceptance |
| --- | --- | --- | --- |
| W0 Graph / Host | Split Cargo defaults and Soong/init product graph; quarantine old broker, P01, lease, egress, journal and fixed proxy, replace the hard-rejecting rootfs runner/launcher wrappers, and neutralize the complete `org.trillionnium.platform(.internal)` SDK closure plus its live framework source/resource consumers. Touch `Cargo.toml`, `apps/trillionniumd/Cargo.toml`, `vendor/trillionnium/config/common.mk`, `vendor/trillionnium/prebuilt/common/Android.bp`, `init.trillionnium-system_ext.rc`, `file_contexts`, framework service source/resource selections and AiShell source globs. | None | Default build/link/start graph contains one Host and no forbidden node or legacy SDK edge; sealed targets require an explicit feature/variant. |
| W1 Turn / Codex | Add `RunTurnRequest`/stream, provider lifecycle, same-turn event forwarding and truthful full-access launch. Touch `owner_open_agent_api`/`direct_turn`, `providers/codex.rs`, `tool-runtime`, AiShell. | W0 only for integrated path; bootstrap can run immediately | A Codex turn executes `pwd`, creates/reads a file, sees a deliberate failure, continues, and returns model text plus raw tool events. |
| W2 Root Linux / substrate | Writable overlay, `/bin/sh`, process groups, PTY/stream, network and restartable init service. Touch runner/bootstrap, launcher, SELinux and mount setup. | W1 | Inside Root Linux: `id; uname -a; command -v adb`; kill daemon; init gives a new PID; the turn reconnects or reports interruption honestly. |
| W3 Raw ADB / transport | Ordinary ARM64 `adb` client/server or transparent relay, USB/reverse/reconnect, exact argv/stdout/stderr. Touch `adb.rs`, transport adapter, Root Linux payload and ADB init fragment. | W2 | Same Codex turn runs `adb devices -l` and `adb -s ZY32JLVHGN shell id`; unauthorized/offline/root rejection remains raw ADB output. |
| W4 UI/convenience | Thin System API/Accessibility codecs and direct AiShell streaming UI; raw ADB remains fallback. | W1/W3 | UI can send text, render chunks and cancel; disabling Accessibility does not block shell/ADB. |
| W5 Recovery / self-development | Event log/spool, dispatch records, inspect/read, provider/USB/reboot/ENOSPC fault handling, self-update/restore. | W1–W3 | Kill/reboot/unplug yields inspectable state or `unknown_after_disconnect`, never an automatic blind duplicate; Codex can build/update and recover. |
| W6 Release (optional) | Signed production profile, hardware rollback, multi-user isolation and narrower policy. | Productive W5 | Separate release evidence; never a prerequisite for owner-open dogfood. |

W0–W3 are the critical path to direct device control. W4–W6 may proceed in
parallel where useful. No row authorizes a semantic gate.

The plan is an execution document, not a security certification. A local
owner-controlled build may use a dirty worktree and test keys. A public release
has additional signing and recovery requirements, but those requirements must
not prevent the owner from using Codex to build and operate the dogfood system.

**现在就能做：** 在 Root Linux 里直接启动
`codex exec -s danger-full-access --json`（或该已安装 CLI 明确支持的等价
全权限参数），让 Codex 执行 `command -v adb`、`adb devices`、`adb shell id`
和任意 shell 命令。下面的 ABI 生成、Cargo/Soong 收敛和耐久性工作与这条
可运行路径并行推进；它们不是使用直接 shell/ADB 的前置 gate。

## 1. Product contract

Trillionnium is an AI-native Android OS whose built-in Agent is Codex. There is
one semantic control plane:

~~~text
user request
    -> Codex turn (intent, context, reasoning, memory, policy, tool choice)
    -> direct shell / direct ADB / System API / Accessibility tool
    -> mechanism substrate (process, bytes, transport, storage, restart)
    -> raw observation
    -> the same Codex turn
~~~

The phone has no local LLM and no local model scheduler. Inference remains
off-device; the Android-managed headless Root Linux environment contains the
Codex runtime, its tool clients and its writable working state.

### 1.1 Non-negotiable decisions

1. **Exactly one built-in semantic principal.** The active semantic lineage is
   openai-codex / agent-codex-direct-v1: one Codex-controlled turn model and
   one event lineage. This label is not a generated Unix/SELinux identity;
   provider/model version, runtime image, UID/GID, domain and endpoint are
   owner-configured correlation/runtime fields. OpenClaw, Hepta and old provider
   identities are retirement records, not runnable agents. Codex-native
   subagents, when the owner enables them, are an internal Codex feature under
   the same Codex turn and observable tool event stream; a transport adapter is
   optional and is not an additional OS Agent or an independent policy plane.
2. **Codex is the only semantic authority.** Codex owns intent
   interpretation, context selection, memory, target selection, policy,
   consent conversation, retries, undo/compensation, scheduling and the
   meaning of an observation. There is no plan-to-Authority translator,
   hidden risk engine, route planner, approval service or second LLM.
3. **Shell and ADB are first-class product primitives.** Codex must be able to
   issue an arbitrary shell command and an arbitrary ADB command directly.
   Command-string shell mode is a normal mode, not an exceptional fallback.
   adb shell, push, pull, install, uninstall, root, remount, reboot, forward,
   reverse, logcat, bugreport and future ADB subcommands are not blocked by a
   typed allowlist.
4. **The owner-open profile is the development product.** It intentionally
   trusts the Codex instance with broad Root Linux and device control. A bad
   model decision, prompt injection or a bad self-update can therefore damage
   the device. The mitigation is Agent iteration, testing, backups and an
   out-of-band recovery path—not a second semantic policy implementation.
5. **The substrate is mechanism-only.** It supplies the minimum primitives
   that a crashed or powered-off process cannot provide for itself: launching,
   file descriptors and IPC, transport connection, process lifetime, global
   resource liveness, durable bytes and recovery. It does not decide whether a
   command is safe, destructive, allowed or the right next step.
6. **No hidden privilege downgrade.** If the selected target or device does
   not have a requested privilege, the direct tool returns the real error.
   The substrate must not silently substitute a weaker target, a local model,
   another provider or a different command.
7. **Root Linux is mandatory.** It is the Android-managed execution home for
   Codex, not a desktop-Linux side project. The same turn can operate the
   host, Root Linux and one or more Android targets.
8. **Windows remains deferred.** WindowsCompat is absent from Android product
   variants until the Android dogfood loop is useful. Its research archives
   are never an implicit second runtime.

### 1.2 What “open” means

Open means there is no semantic command allowlist, no per-action approval
handshake, no model-facing risk_guard, no hidden capability matrix and no OS
process that rewrites or vetoes a Codex decision. Codex can inspect and change
its own source, policy files, tools and device state.

Open does not mean that physics can be negotiated away. The kernel and a
transport still have finite memory, file descriptors, USB bandwidth and
process IDs; a disconnected socket still cannot deliver bytes. The substrate
may enforce only the Android survival floor (watchdog, frame/parser safety and
global resource exhaustion). Codex/owner configuration may raise or disable
per-target ceilings where the platform permits; exceeding a mechanical ceiling
returns `resource_exhausted` and never becomes an authorization decision,
command rewrite or silent downgrade.

An optional sealed/public profile may add stronger restrictions later. It must
reuse the same substrate and direct-tool ABI, be selected explicitly, and
never become a prerequisite for owner-open development.

## 2. Ownership split

| Concern | Owner | Required behavior |
| --- | --- | --- |
| Intent, clarification and decomposition | Codex | Decide what the user means and ask in the conversation when needed. |
| Context, transcript and durable memory | Codex | Select, summarize, write, delete and migrate its own memory. |
| Tool discovery and selection | Codex | Choose a direct tool; create a script/tool from shell when useful. |
| Target routing and ordering | Codex | Select host, rootlinux, an Android serial or recovery and sequence calls. |
| Risk judgment and consent language | Codex/user | The Agent may ask; owner-open substrate does not insert a mandatory approval gate. |
| Retry, undo and compensation | Codex | Interpret observations and decide whether another call is appropriate. |
| Shell/ADB command semantics | Codex | Send exact command bytes/arguments and interpret the result. |
| Process spawn, pipes, PTY, signals and global liveness | Substrate | Execute the requested bytes and report exit, signal, timeout or resource failure. |
| USB/TCP/ADB connection | Substrate | Connect the requested target and expose transport errors; no target substitution. |
| Credentials and key handles | Substrate + owner configuration | Make configured handles available. Never invent an identity or silently rotate it. |
| Event persistence and crash recovery | Substrate | Preserve bytes and expose unknown_after_disconnect; Codex chooses recovery. |
| Emergency stop and boot recovery | Out-of-band substrate | Let the owner recover a wedged Agent without becoming a semantic planner. |

When a proposed feature appears in both columns, implement the substrate half
as a primitive and the Agent half as a Codex tool or policy. Do not add a third
component to arbitrate between them.

## 3. Runtime model and direct contracts

The contracts below are deliberately small. They provide correlation and
recovery without turning every action into a formal approval ceremony.
The machine-readable file is a codec/interoperability descriptor, not an
allow/deny validator: its generator may produce serde/codecs and frame types,
but must not generate policy, risk or approval decisions. Unknown extension
fields and tool labels remain transport-valid.

### 3.1 Turn and event model

The Agent Host exposes one turn lineage per active connection. A connection
normally carries one turn; concurrent turns use separate connections. The host
and provider preserve:

~~~text
subject -> session -> task -> turn -> tool_call -> observation
~~~

The minimum correlation envelope (not a complete observation object) is:

~~~json
{
  "protocol": "trillionnium.agent.turn.v1",
  "protocol_version": 1,
  "connection_id": "conn-...",
  "turn_stream_id": "stream-...",
  "seq": 1,
  "direction": "host_to_client",
  "client_seq": null,
  "host_seq": 1,
  "session_id": "sess-...",
  "profile_id": "owner-open",
  "task_id": "task-...",
  "turn_id": "turn-...",
  "event_id": "evt-...",
  "kind": "tool_call|tool_chunk|tool_result|model_text|turn_end",
  "tool": "shell.exec|adb.exec|system_api|accessibility|codex_defined",
  "target": "rootlinux|host-linux|android:ZY32JLVHGN",
  "target_id": "android:ZY32JLVHGN",
  "binding_fingerprint": "sha256:...",
  "dispatch_state": "not_started|started_no_response|result_recorded|unknown_after_disconnect",
  "effect_state": "not_attempted|possibly_applied|applied|rejected|unknown",
  "executor": "native_codex|substrate|android_adb|host_process",
  "agent_path": "codex|codex/subagent-1",
  "parent_turn_id": "turn-...",
  "payload": {}
}
~~~

For an observation or terminal record, add the contract-required `scope` and
`status` fields (`frame`, `turn`, `call` or `job` as applicable); call-scope
records also carry the resolved target/dispatch/effect fields. The example
above shows the shared correlation fields only, so it is not a second schema.

IDs and target labels are correlation data, not permission tokens. The host
may append them to an event log, but it must not require a separately signed
plan before delivering a tool call.
The `kind`, `tool` and `target` values above are examples/observability
labels, not a closed catalog. `agent_path` and parent IDs are optional
correlation fields for Codex-native subagents, not principals or permissions.
Codex may create a script, helper or configured
tool name through shell; the transport treats tool names and payload bytes as
opaque and must not reject an unknown future label.

The lifecycle is intentionally limited to transport/liveness facts:

~~~text
started -> model_waiting <-> tool_running -> tool_result
        -> model_waiting (more calls) | completed
        -> interrupted -> resumable
~~~

Control frames are likewise mechanical: `turn.cancel` carries `session_id`/
`turn_id`, `tool.cancel` adds `call_id`, `job.kill` carries `session_id`/
`job_id`, a signal and a grace period (and may be issued by a later turn), and pause/resume/window updates
carry the stream cursor/window with an optional `call_id`. They deliver
signals or backpressure and return `cancelled`/`unknown_after_disconnect`; they
do not ask a policy service for permission to stop or continue. Control-frame
correlation is carried in top-level `turn_id`, `call_id` and `job_id` fields (or
the explicitly documented payload equivalent); missing or ambiguous
correlation is `invalid_frame`. A `call_id` is unique within
`(session_id, profile_id, task_id, turn_id, turn_stream_id)`; a retry after disconnect uses
a new call id. The host retains its local PID/job mapping until a terminal
event. Re-delivery returns the existing stream/result and never spawns a
second local process. After restart, accepted/started/terminal records are
reconciled conservatively (see §3.7); absence of a durable dispatch record is
`unknown_after_disconnect`, not proof of `not_started`. This local rule makes
no exactly-once claim for a remote ADB effect.

The host reports `ok`, `exited_nonzero`, `signalled`, `timed_out`, `cancelled`,
`transport_unavailable`, `target_rejected`, `resource_exhausted`,
`invalid_frame`, `spawn_failed`, `provider_unavailable`,
`unknown_after_disconnect`, `configuration_error`, `io_error`,
`provider_stream_closed`, `reconnect_required` or `resume_unavailable`. The
lifecycle/transport values in the tail of this list are diagnostics, not policy
outcomes. These are wire
status values and are mechanical;
they are not authorization outcomes. It does not label a command
safe/unsafe or committed/uncommitted. Codex can turn any observation into a
user explanation or a follow-up call.

Frames are length-delimited or newline-delimited JSONL, with streaming chunks
and backpressure. A bounded frame is a liveness limit; large output must be
spooled to a file that Codex can read, not silently truncated. Cancellation
propagates to the process group and PTY, then reports what was observed. Client
and host sequence counters are independent: client `seq` is connection-local,
while host `host_seq` is monotonic on the turn stream across reconnects and is
the inclusive replay cursor. `seq` is the serialized direction-dependent alias;
`client_seq`/`host_seq` are optional mirrors. `event_id` remains stable when a
recorded event is replayed, and a reconnect resumes from a caller-supplied host
cursor plus (when needed) a client cursor. A
duplicate frame may be delivered again for observation, but must never execute
the same command a second time merely because the frame was re-delivered.
Keep small request/control-frame limits separate from output-chunk/spool
limits: the legacy 256 KiB request/1 MiB response helpers must not cap a long
ADB pull, build log or binary stdin on the owner-open path. Oversized output is
continued as chunks or a target-scoped spool and only a physically exhausted
buffer returns `resource_exhausted`.

Binary and large observations are explicit transport data, not a hidden
semantic filter. A chunk carries `encoding: utf8|base64|spool_path`, a
monotonic `chunk_seq`, the byte count and (when spooled) the path and digest.
UTF-8 text may be inlined; arbitrary stdout/stderr is base64 or a readable
spool file. The host may cap a single frame for liveness, but it must continue
the stream or expose the complete spool path and never silently truncate a
command result. `status` and `summary` are host metadata for a turn terminal
event; the Codex model output is not forced into a final JSON schema.
When `spool_path` is used, the path is readable from the same target/namespace
that produced it and the event names that target. Codex can read it with a
subsequent `shell.exec`/`shell.command`; P1 may additionally expose
`event.read(call_id, offset, length)` for a non-shared view. A spool path is a
data-transfer primitive, not a redaction or approval boundary.

### 3.2 shell.exec — the primary computer interface

The first-class shell tool has both forms:

~~~json
{
  "tool": "shell.exec",
  "target_id": "rootlinux",
  "mode": "command",
  "command": "set -e; edit-config --apply; systemctl restart demo",
  "cwd": "/workspace",
  "env": {"MODE": "dogfood"},
  "stdin": "",
  "timeout_ms": 120000,
  "pty": false
}
~~~

~~~json
{
  "tool": "shell.exec",
  "target_id": "host-linux",
  "mode": "argv",
  "argv": ["cargo", "test", "-p", "trillionniumd"],
  "cwd": "/data/toshiba-dev/TrillionniumOS",
  "timeout_ms": 900000
}
~~~

`systemctl` in the command example is illustrative only; a headless Root
Linux image may use an init script, a direct process signal or another
owner-configured service command. The shell primitive does not assume systemd.

The snippets are Codex tool shorthand, not complete wire frames. The host
inherits the enclosing session/task/turn/profile and allocates a bookkeeping
`call_id` for a native event when needed; a client `run_turn` frame still uses
the required fields in the machine contract.

Rules:

- exactly one of `command` or `argv` is used. If `mode` is omitted it is
  inferred from the present field; both present or neither present is an
  `invalid_frame` transport error, not a semantic denial.
- A native shell call may omit `target_id`; it then uses the current
  owner-configured Root Linux process target and the host records that target
  in the event. An alias/cross-target call supplies `target_id` explicitly.
  `adb.exec` may supply an Android/recovery target as a routing hint, but it
  may also omit it and execute the ordinary local ADB configuration. The
  absence of a target registry or a connected serial is reported by ADB, not
  converted into a semantic denial; an explicit serial/host/port in argv is
  never rewritten.
- command is passed to the selected shell with normal quoting, pipes,
  redirection, scripts and environment semantics. It is not converted to an
  argv allowlist.
- argv is passed element-for-element when the caller wants exec semantics.
- `cwd: null` means the selected target's configured default cwd. An `env` key
  with a string overrides the inherited owner-open environment and `null`
  explicitly unsets it; unspecified keys are inherited. stdin, PTY, signals
  and inherited descriptors are explicit
  tool inputs. There is no hidden workspace name or hidden read-only mode in
  owner-open.
- rootlinux is a practical, writable Root Linux environment. It includes a
  normal shell/userland and can install or build additional tools. The
  configured owner-open profile may run as Root Linux root.
- Root Linux uid 0 is not a promise to bypass the Android kernel or device
  SELinux. Android-host root/remount/fastboot outcomes are whatever the ADB
  target returns. The substrate passes those bytes/statuses through; it does
  not pre-deny them or claim a privilege the target lacks.
- host uses the configured host account and can use whatever sudo, root or
  credential path the owner has made available.
- Android shell work is normally expressed as adb.exec so the observation
  retains the device serial and transport details.
- `host-linux` and `rootlinux` are separate target/file views unless the owner
  explicitly configures a shared mount. A path on one target is not assumed to
  exist on another; Codex must use an explicit push/pull/copy or shared mount
  when it wants to move a file between them.
- The only automatic limits are owner-configured mechanical liveness limits
  (process, FD, memory, time, network, input/output bytes and spool capacity).
  They are configurable, observable and not a per-command policy decision;
  physical exhaustion is reported as `resource_exhausted`.
- The owner-open execution profile is explicit configuration, not a hidden
  hardening preset: execution UID/GID (normally Root Linux `root`),
  supplementary groups/capabilities, mount/PID/network namespaces,
  `no_new_privs`, seccomp/chroot behavior, environment inheritance and
  provider network routing are all owner-selected. The old fixed 5901/5903
  identities, unconditional capability drop, `no_new_privs`/seccomp deny
  profile, `env_clear` and loopback-only proxy belong to a sealed/legacy
  profile. Android liveness limits still apply globally and a platform SELinux
  denial is returned as the real platform error.
- A command that exits non-zero is a valid observation. The host must not
  replace it with a generic denied response or retry it under another ID.

The existing seven-command shell allowlist, command-string higher-risk
classification, risk_guard and pre-effect deny matrix are migration artifacts.
They must not remain on the owner-open path.

### 3.3 adb.exec — a raw ADB interface

ADB is exposed as a direct command interface, not as a closed typed catalog:

~~~json
{
  "tool": "adb.exec",
  "target_id": "android:ZY32JLVHGN",
  "argv": ["shell", "sh", "-c", "settings put system screen_brightness 80"],
  "stdin": "",
  "timeout_ms": 120000,
  "stream": true
}
~~~

The canonical path is an ordinary adb executable in the Root Linux PATH.
adb.exec is a transparent convenience alias over that executable and may be
removed later without changing what Codex can do in shell.command. Its argv
does not include the program name and is passed element-for-element. The
`target_id` is optional diagnostic/routing metadata, not a call precondition.
When it is absent, ordinary ADB configuration and the exact Codex argv decide
the endpoint; `adb devices`, `adb shell ...` and every future subcommand retain
their normal meaning. The wrapper must not inject `-s`, host, port or a
privilege tier. When a target hint is present, the transport may report the
resolved endpoint, but it must not rewrite explicit `ANDROID_SERIAL`, `-s`,
host or port bytes. The event log retains both the exact Codex argv and the
endpoint ADB actually selected. These calls are all valid owner-open inputs:

~~~text
shell.exec("adb devices")
shell.exec("adb -s ZY32JLVHGN shell id")
adb.exec(["shell", "id"])
~~~

It supports, at minimum:

~~~text
devices, get-state, shell, exec-out, push, pull, sync,
install, install-multiple, uninstall, root, unroot, remount,
reboot, wait-for-device, forward, reverse, logcat, bugreport
~~~

Unknown or future subcommands are passed through so an ADB upgrade does not
require a new OS policy release. Codex can inspect, transfer files, install an
APK, configure USB reverse networking, reboot and recover the target. If the
target rejects root or remount, Codex receives that real ADB response.

Target selection is a mechanical disambiguation rule: when several serials
are connected, adb devices is returned and Codex chooses one. It is not a
security approval. A local-phone optimization may replace the external ADB
process with a native transport only when byte and result behavior is
equivalent and the raw command remains visible in the observation.

For `push`/`pull`, local source and destination paths resolve in the
executor's target namespace (Root Linux by default); the remote path resolves
on the selected Android target. A host filesystem path is reached with an
explicit `host-linux` shell/copy call, never by assuming Root Linux and host
views are shared. This makes cross-target file movement an ordinary Codex
decision.

ADB key material is owner configuration. The transport may supply an inherited
FD, ADB_VENDOR_KEYS path or local ADB server. On the phone, the first dogfood
topology is an ARM64 platform-tools adb in Root Linux connected to the
owner's host ADB server through ADB_SERVER_SOCKET plus adb reverse/TCP, or to
an explicitly enabled local adbd TCP endpoint. The phone does not magically
have /system/bin/adb. By default the configured secret is not echoed into
model text, but this is a logging/display preference rather than a filtering
boundary: the owner may explicitly inspect or `cat` it through shell. In
owner-open, Codex can inspect, create, rotate or remove the configured key
through shell; no hidden redaction or alternate identity is inserted.
An `unauthorized`, `offline` or missing-device state from `adb devices` is
passed through verbatim. The owner may authorize the key through the normal
Android prompt/`adb_keys` path and Codex may rerun the probe; enrollment is
not silently converted into a lease or a different identity.

The first host-backed smoke is concrete:

~~~sh
# HOST (outside Root Linux): use the already running host ADB server.
# Do not execute this line inside the Root Linux namespace.
adb -s ZY32JLVHGN reverse tcp:5037 tcp:5037
# ROOT LINUX (inside the Agent execution namespace): do not start a second
# local server; use the configured bridge/forward to the host server.
export ADB_SERVER_SOCKET=tcp:127.0.0.1:5037
adb devices -l
adb -s ZY32JLVHGN shell id
~~~

ADB reverse state is expected to disappear across reboot. Choose and record one
bootstrap owner: (1) a host-side `adb track-devices`/udev helper that survives
phone reboot and recreates reverse, (2) an independent `host-linux` Codex call
that performs that same mechanical reconnect, or (3) a phone-local adbd TCP/
Unix endpoint that survives Root Linux restart. Only after that transport is
back does Root Linux run `adb wait-for-device`; a dead phone process cannot
recreate its own lost reverse tunnel. A missing bootstrap path returns
`transport_unavailable` and waits for the owner. This is transport plumbing,
not an unstated approval gate.

The example `127.0.0.1:5037` works only when the Root Linux process and the
owner's ADB server share a network namespace or an explicit loopback bridge.
If Root Linux has its own namespace, the implementation must instead provide
an explicit bridge/route or a Unix/inherited-FD transport and show it in the
target record. The P0 probe includes `ip route`, `ss -ltn` and a bounded
`nc -vz`/equivalent connectivity check; a failed check is a transport
observation, not a policy HOLD.

### 3.4 System API and Accessibility

Typed System API and Accessibility calls are convenience tools for operations
where a structured observation is useful. They are not prerequisites for
shell/ADB and they are not a second authority. Codex may use them, replace
them with adb shell, cmd, settings, uiautomator or a script, or create a new
helper itself.

Accessibility is a compatibility route owned by Codex. The Android service
supplies the raw tree/action result and ordinary transport errors; it does not
contain an independent plan executor.
If the service is disabled, not authorized for the current user or its replay
state is unavailable, return `target_rejected`/`transport_unavailable` to
Codex. Never make Accessibility readiness a prerequisite for `run_turn`, raw
shell or raw ADB; Codex falls back to `adb shell`, `uiautomator` or its own
script.

### 3.5 Targets

Targets are named endpoints, not policy domains:

~~~text
host-linux
rootlinux
android:<serial>
android-local
recovery:<serial>
~~~

A target record contains an explicit endpoint, transport, observed build/boot
identity and capabilities reported by that target. host-linux is a configured
development-host endpoint (local, SSH or a shared mount); it does not
implicitly grant an Android process host-root access. rootlinux, android-local,
an external serial and recovery each have their own explicit transport.
Codex may create sequential or parallel calls. `capabilities` are informational
hints for Codex only; the substrate never pre-validates a command against that
list. An unsupported operation reaches the selected target and returns its
`target_rejected` or transport error. Every observation carries the target so
a host result cannot be mistaken for a phone result. The host does not
silently pivot from one target to another. `host` and a bare phone serial are
accepted only as explicit compatibility aliases for `host-linux` and
`android:<serial>`; resolving an alias is recorded and never changes the
selected endpoint. Unknown target labels are transport-valid; if no endpoint
can be resolved, the result is `transport_unavailable`, not a schema or policy
denial. A target hint in a tool descriptor is routing metadata, never an
allowlist.

The Agent Host location is explicit owner configuration:

~~~text
agent_host_location = rootlinux | independent_host_linux_supervisor
~~~

When the Host is inside phone Root Linux, `adb reboot` necessarily kills the
phone-side daemon, Codex process and any phone-side reverse tunnel. The old
turn is marked `turn_end.status=interrupted`; after transport returns, a new
process creates a `resumable` turn with `continuation_of`, the recorded cursor and the same
context (or plainly starts a new turn if the provider cannot resume). It is
incorrect to call that a still-running same process. An independent
host-linux supervisor may keep the provider stream alive across the phone
reboot, but it still reports the phone call as interrupted/unknown until ADB
reconnects. This is lifecycle information, not a policy gate.

### 3.6 Context, memory and egress

Codex owns the meaning and lifetime of its context. The substrate offers
ordinary storage and network primitives:

- transcript/event log;
- Codex workspace and scripts;
- durable memory database/files;
- raw tool-output spool;
- optional provider egress stream.

Codex decides what to retain, summarize, export, delete or redact. The host
must preserve profile/user separation at the filesystem and process level, but
must not run a second taint or prompt-policy engine. Network failures,
authentication failures, rate limits and provider changes are observations for
Codex. There is no hidden local-model fallback.

Provider/model metadata is recorded with a turn for debugging, not used as an
effect gate.

Configuration loading follows the same rule. A malformed or missing
`owner-open.toml` emits `configuration_error` with the failing field/stage,
but the listener remains available with last-known-good or built-in minimal
defaults (`/bin/sh`, current Root Linux target and local spool). A provider
credential/endpoint failure may become `provider_unavailable`; it must not
turn the shell/ADB primitives into a hidden deny path. Config changes carry a
`config_generation` and apply at a turn/job boundary; spawn-time namespace or
identity changes are reported as a restart observation rather than rewritten
under a running process.

### 3.7 Persistence and uncertain effects

The substrate attempts to append the exact request, transport metadata and
returned bytes to an event log. P0 may lose an append on a crash, but must
report that loss honestly; P1 adds fsync/atomic publication, reopen and replay
of already-recorded bytes. It may allocate an operation_id, but must not
pretend to know a remote effect's state after a lost response.

After a process, USB or power failure, `dispatch_state` is one of:

~~~text
not_started
started_no_response
result_recorded
unknown_after_disconnect
~~~

`unknown_after_disconnect` is a useful wire result, not a reason to dispatch a
blind duplicate. The separate remote `effect_state` is
`not_attempted|possibly_applied|applied|rejected|unknown`; it describes what
the target is known to have done, not whether the local process returned a
zero exit code. Codex can inspect the target, retry an idempotent command, undo
it or ask the owner. Exactly-once semantics are promised only for a backend if
that backend itself proves them; the general shell/ADB interface makes no such
claim. The host may locally deduplicate a repeated `call_id`/frame so it does
not spawn a second local process, but that does not prove a remote shell/ADB
effect was not applied before a disconnect; the remote state remains `unknown`
until Codex probes it.

The host records `accepted -> started -> terminal` on a best-effort P0 store
and publishes each record with `request_sha256` when the input is replayable.
The request digest is RFC 8785 JCS over the requested fields
(protocol/version, session/profile/task/turn, tool, config generation, target
hint, mode, cwd, timeout, normalized PTY/stream options and exact
command/argv/env/stdin bytes); client/server request IDs, parent/continuation,
resume/stream/connection/event IDs, sequence mirrors, timestamps and resolved
endpoint are excluded. Omitted mode/PTY/stream/profile/config defaults and
documented target aliases are normalized before hashing, while original bytes
are preserved. After target resolution, persist a separate
`binding_fingerprint` for the endpoint, transport identity, profile and target
boot/serial; same-call deduplication requires both digests. An inherited
FD or a mutable spool is marked non-replayable and is never silently consumed
twice after restart. A later observation can reconcile a remote result by
referring to `related_event_id`/`original_call_id`; reconciliation is an
additional non-terminal observation, not a second terminal event. On restart,
accepted-only, started-without-terminal, terminal and missing-record cases are
handled conservatively: only an explicit no-spawn accepted record may be
`not_started`; otherwise expose `started_no_response` or
`unknown_after_disconnect`, attach/inspect, and never redispatch automatically.
This makes the failure boundary explicit without turning storage into an
authorization service.

The log and operation_id are observability primitives. A caller does not have
to pre-sign, reserve or obtain an approval record before a command starts.
Best-effort logging is sufficient for P0; durable replay inspection is the
P1-02 task. If the event store is unavailable, still dispatch the requested
shell/ADB call and attach `event_log_status=unavailable` to the raw observation;
an I/O logging failure must not become `operation_denied`. Raw shell/ADB does
not need a custom receipt format before it can run.

### 3.8 Long-running and interactive work

Builds, OTA installs and debugging often outlive a single request timeout.
The direct shell surface therefore supports a foreground PTY plus a
background-job form:

~~~text
shell.command(..., pty=true)
shell.job.start(...)
shell.job.status(job_id)
shell.job.attach(job_id)
shell.job.write(job_id, bytes)
shell.job.resize(job_id, rows, cols)
shell.job.close_stdin(job_id)
shell.job.kill(job_id)
~~~

Codex chooses foreground or background and may extend a deadline. A default
timeout is a hint for an abandoned call; only a clearly documented global
liveness ceiling is hard. A job that survives a turn is visible in the event
log and can be attached by a later turn. The shorthand above inherits the
active session/profile/task/turn/turn-stream context; a cross-connection
status, attach, write, resize, close or kill supplies the session/profile and
job identifiers explicitly (plus the inclusive cursor where required).
`attach` is duplex: output chunks flow
back to Codex, while `write`, `resize` and `close_stdin` send raw PTY/input
bytes to the target. These are mechanical primitives; the first owner-open
command/stdout turn may ship before all duplex/job operations are complete.

### 3.9 AiShell ingress

AiShell is a session UI/transport, not an authority. It sends a user message
to the single Agent Host over the existing local UDS/stdio/HTTP ingress and
streams model text, tool-call progress and raw observations back to the user.
The old AiAuthority/action JSON path must not be inserted between AiShell and
Codex. A temporary compatibility adapter may translate its framing, but it
must not make an allow/deny or approval decision.
The owner-open `run_turn` listener accepts a framed local stream after basic
socket ownership/peer information (when available); channel-binding,
agent-id, signed-grant and consent challenges are optional transport metadata,
not prerequisites for a turn. A peer mismatch can produce a transport error,
but it must not be reported as a semantic policy denial. The old challenge and
grant tests remain under `legacy-authority`/sealed profiles.
`RunTurnRequest`/`RunTurnFrame` is a separate owner-open wire type from the
legacy `AgentApiRequest`: `agent_id` is optional correlation data, `run_turn`
is not admitted by the old closed method table, and the listener does not
require a non-empty agent id or a channel-binding challenge. A compatibility
decoder may accept the old envelope, but it must immediately enter the same
open stream rather than the old plan/authority dispatcher.
The Android UI and Root Linux do not automatically share a filesystem UDS.
The P0 default is one Android abstract socket,
`@trillionnium_direct_agent_host_v1`, bound by the single `trillionniumd`
listener in the Android network/AF_UNIX namespace, with the Root Linux chroot
sharing that namespace. AiShell connects to that exact abstract name; the
owner-open daemon's Root Linux event store and Codex child use
`/run/trillionnium/direct-agent-host-v1.sock` only as an optional chroot-local
alias, not as a second listener. Label the abstract endpoint and AiShell peer
in SELinux and record the configured socket name in the owner-open profile. If
the Root Linux profile deliberately uses a separate network namespace, the
only P0 fallback is a mechanical host-side bridge/init forward from that
abstract socket to the chroot UDS (or inherited stdio); choose and document
that bridge before enabling the namespace. The current `BuiltInAgentClient`
abstract-socket name and Root Linux `/run/...sock` name are not interchangeable.
Any bridge translates bytes only and must not add a semantic approval hop.

### 3.10 Mechanical wire and recovery rules

The wire has an optional connection preface and one active turn per transport
connection. All request fields belong in the frame `payload`; top-level
correlation fields are accepted only when they agree with that payload. The
deterministic first-frame sequences are:

~~~text
direct turn: client turn.start(seq=0) -> host turn.accepted(host_seq=0)
preface:     client hello(seq=0) -> host hello.ack(seq=0) [connection control]
             -> client turn.start(seq=1) -> host turn.accepted(host_seq=0)
             -> host events(host_seq=1,2,...)
~~~

Client and host `seq` counters are independent: client `seq` is connection-local,
while host `host_seq` is monotonic on the turn stream across reconnects and is the
inclusive replay cursor. The serialized `seq` field is direction-dependent;
`client_seq`/`host_seq` are optional diagnostic mirrors, and each side serializes
its own writes.
`hello.ack` allocates `connection_id` and a provisional `turn_stream_id`;
hello/hello.ack sequence values are connection-control values outside the
persisted turn cursor. `turn.accepted` confirms the turn lineage and starts
`host_seq=0`. A reconnect hello/turn.start carries
the prior connection, stream and host cursor (plus a client cursor when
needed). Duplicate frames replay recorded events; gaps or out-of-order frames
return `reconnect_required` with both last-contiguous cursors. A compacted
cursor returns `resume_unavailable` and never redispatches a command.

`client_request_id` or a turn request digest makes duplicate `turn.start`
idempotent within `(session_id, profile_id, task_id, turn_id)`; if neither is supplied the
host allocates and records a request id before starting the provider. A
same-id/different-canonical-request conflict is `invalid_frame`, never a second
provider. JSON key order and documented aliases are normalized before this
comparison; the original wire bytes remain available for audit. If the caller
omits correlation IDs on a provider-native or transparent alias event that
already has a valid enclosing stream, the host allocates bookkeeping IDs; those
IDs are not permission checks. Client `turn.start` and control frames still need
an unambiguous frame and documented correlation (or an explicit ingress
allocation), and a parser never invents an empty identifier. When
`prior_connection_id` is supplied, the resume tuple must also contain the
matching stream and exactly one cursor/token.

For each call the host computes `request_sha256` with RFC 8785 JCS over the
requested envelope (protocol/version, session/profile/task/turn, tool,
`config_generation`, target hint, mode, cwd, timeout, normalized PTY/stream
options, environment and exact command/argv/stdin bytes), excluding
host-assigned IDs, sequence, timestamps and the digest field. Before hashing,
omitted mode/PTY/stream/profile/config defaults, target aliases and the current
`config_generation` are normalized while the
original command/argv/stdin bytes are preserved in the record. After target resolution it records a separate
`binding_fingerprint` for the resolved endpoint/transport identity; same
`call_id` deduplication requires both values to match. An FD or mutable spool
is marked non-replayable and is not silently consumed twice. If a restart has
no durable dispatch record, the only honest result is
`unknown_after_disconnect`; Codex probes the target and uses a new call id if it
elects to retry. A supplied `frame_sha256` is checked against the canonical
frame; an omitted digest is computed by the host before same-sequence duplicate
comparison. Same sequence plus identical canonical bytes is replay; same
sequence plus different bytes is `invalid_frame`.
The frame digest excludes only volatile transport fields (`seq`, `client_seq`,
`host_seq`, connection/stream/event/server-request IDs, timestamps and the
supplied digest itself), including any repeated correlation mirrors nested in
the payload; direction (inferred from the transport role when omitted), kind
and all other normalized payload bytes remain in the canonical input.
For an inherited FD or mutable
spool, hash a stable descriptor/identity with `replayable=false` (or tee the
bytes once); never consume a live input twice merely to calculate a digest.

`command` mode is the owner-configured shell with `-c` and exact UTF-8 command
text; `argv` mode is
element-preserving `execve`. Empty argv, NUL-containing command/argv/env and
unknown mode are `invalid_frame`; stdin/PTY remain byte-oriented and may carry
NUL. For PTY, an explicit `env.TERM` wins over `pty.term`; the effective value
is recorded and included in the normalized request digest. PTY output is raw
terminal bytes on the `pty` stream (stdout/stderr are
merged, with owner-configured initial rows/cols and TERM); non-PTY streams
remain separately labelled. Cancellation/timeout sends the configured
process-group signal escalation (TERM, grace period, KILL) and reports whether
the local process stopped; it does not assert that a remote ADB effect stopped.

Output chunks use one name, `chunk_seq`, and carry stream (`stdout`, `stderr`,
`pty`, `model` or `metadata`), encoding, decoded/raw `byte_count` and exactly
one of data or a target-scoped spool path. A full spool returns the chunks
written so far plus `resource_exhausted`; it does not silently truncate or
auto-retry. `turn_end` is the single terminal event for the turn and has
`status` plus a human-readable (or null) `summary`; tool observations are not
forced into that final schema. A late probe emits a `call.reconciliation`
event carrying `related_event_id`, `original_call_id`, `observed_remote_state`
and `observed_at`;
it is non-terminal and never creates a second terminal event. The reconciliation
fields are typed as `related_event_id`/`original_call_id` strings,
`observed_remote_state` an opaque target observation, and `observed_at` a
recorded timestamp. If transport/provider failure happens before a terminal
event, the host emits one durable `turn_end` with `status=interrupted` or
`unknown_after_disconnect` when it can persist that fact. If the best-effort
store is unavailable, reconnect exposes the interrupted/resumable lineage and
does not invent terminal success; a later durable reconciliation may close it.
P1 exposes read-only `operation.inspect`/`event.read` plus an explicit `spool.cleanup`
maintenance primitive; cleanup is owner/Codex initiated and is not an
authorization decision.

The phone-local and independent-host reboot cases are intentionally different:

| Host location | Phone reboot result | Correct continuation |
| --- | --- | --- |
| `rootlinux` | Codex, Host and reverse tunnel die together; in-flight device call is `unknown_after_disconnect` when its state cannot be known. | Reconnect transport, then create a new `turn_id` with `continuation_of`/cursor; no claim of same-process continuation. |
| `independent_host_linux_supervisor` | Provider stream may survive; phone call still loses transport and is marked interrupted/unknown until reconnected. | Host may keep the turn stream, but only Codex decides probe/retry/undo after raw observations. |

This is all transport/lifecycle behavior. None of it is an approval, risk or
privilege decision.

## 4. Minimal substrate to build

The substrate is intentionally smaller than the previous Authority design.
Its modules are mechanisms and should have no business vocabulary:

1. **Launcher/supervisor.** Android init starts one trillionniumd and the
   Codex runtime, restarts a crashed process, exposes a health stream and
   allows a bounded emergency stop. A missing optional manifest must not turn a
   normal owner-open command into a policy HOLD.
2. **Direct event transport.** One local IPC endpoint with length framing,
   stream chunks, cancellation, PTY support and backpressure. The transport
   carries opaque tool payloads.
3. **Process execution.** Spawn/exec, process-group signal delivery, target
   namespace/mount setup and configurable cgroup limits. The owner-open Root
   Linux profile is broad; limits protect Android liveness and are reported
   rather than silently changing a request.
4. **ADB transport.** A real connector around the existing ADB binary/server
   path first, with USB and TCP/reverse support, serial discovery and raw
   stdout/stderr/exit propagation. A native implementation is an optimization,
   not a new semantic layer.
5. **Storage primitive.** Append bytes, fsync, atomic replace, bounded spool,
   reopen and enumerate incomplete operations. The primitive does not decide
   whether to replay.
6. **Credential handles.** Open/close/inherit configured network, ADB and
   signing handles. Keep secrets out of accidental model text, but do not
   introduce a semantic credential broker.
7. **Boot/recovery primitive.** A hardware/ADB/operator path can stop Codex,
   mount recovery state, restore a known image and collect a support bundle.
   It is an emergency lifeline, not a second Agent or policy engine. Stopping
   must have an inhibit/resume mechanism (for example `ctl.stop` plus an
   owner-controlled boot marker/property) so init does not immediately respawn
   a misbehaving service; the marker is an out-of-band recovery control, not a
   per-command authorization gate.

SELinux, UID/GID, namespaces and cgroups are configured to make these
mechanisms possible. They are not a typed action allowlist. In the owner-open
dogfood image, the Codex domain has the access needed to operate Root Linux
and the configured ADB path; a missing allow is reported as a normal platform
error and fixed in platform policy, not hidden behind semantic
operation_denied.

### 4.1 Minimal Android launch graph

The owner-open init graph is intentionally boring and long-lived:

~~~text
mount Root Linux image + writable overlay
  -> verify mount and executable existence
  -> start one long-running trillionniumd/Codex service
  -> restart it on crash; expose health and emergency-stop controls
~~~

The first writable Root Linux topology is explicit: use an overlayfs with a
stable lower rootfs (or a copied writable base), an upper/work directory under
`/data/trillionnium/root-linux/overlay`, and a target-visible merged root. Mount
`/proc`, `/sys`, `/dev` plus `devpts`, `/run` and `/tmp` as needed by the
configured namespace, and place the real ARM64 `adb` at
`/usr/local/bin/adb` in that merged view. The current single RW bind of
`/data/trillionnium/agent-tools` is not enough for package installs, PTYs,
networking or process inspection. A mount/label failure is reported as a
mechanical startup error; it is not converted into a semantic command gate.

There may be a supervisor process and a Codex child, but there is only one
semantic Agent instance. The service is not oneshot and does not wait for
high_water, egress_guard, capability leases, receipt publication or manually
set properties. Those values can be logged for diagnosis. A restart resumes
the session/event stream and never manufactures a successful tool result.
The old `sys.trillionnium.rootlinux.prepare`/`desired` property loop that stops
services, unmounts the root and re-enters a bootstrap phase must be removed or
replaced by one explicit owner-open boot state; it must not repeatedly stop a
running Codex service before `run_turn`.

The concrete Android patch target is
`vendor/trillionnium/prebuilt/common/etc/init/init.trillionnium-system_ext.rc`:
the owner-open graph must make `trillionnium_root_linux_daemon` a normal
long-running, restartable service (not `oneshot`/implicitly `disabled`) with
one explicit `class late_start`/owner-open `start` action, and remove its dependency on
`trillionnium_agent_egress_guard`,
`trillionnium_direct_operation_custody_high_water*` and
`trillionnium_shell_exec_broker` readiness properties. The current
`init.trillionnium-agent-adb-debug.rc` is a debug-only bind fragment; replace
it with the normal userdebug ARM64 ADB client/server or transparent shim in
the Root Linux overlay. Keep legacy unmount/quarantine actions idempotent, but
they must not be a start gate. The smoke is mechanical: kill the daemon,
observe init restart it, reconnect the same Codex session and continue a
shell/ADB call. A manual `start`/`restart` on userdebug is allowed for that
smoke and must be logged as such. Remove the entire old `prepare`/`desired`
property-trigger loop (not just downstream readiness checks); an owner-open
boot action must not stop and unmount a live service as a side effect of a
property transition. Disable/remove every default-variant handler for
`sys.trillionnium.rootlinux.prepare`, `desired`, `agent_egress_guard`,
`high_water_ready`, `shell_exec.ready` and `netd=running`; retain the old
property choreography only in an explicitly selected legacy/sealed init
fragment.

The first dogfood image may use the current userdebug Root Linux rootfs plus a
writable /data/trillionnium/root-linux/overlay. A fresh minimal EROFS,
artifact manifest and signed image are later optimization/release work, not a
P0 prerequisite. If an immutable base is retained, package state and Codex
self-updates live in the overlay and /usr/bin/codex (or its equivalent) is an
explicitly replaceable link.

### 4.2 Resource and lifecycle mechanics

The owner-open profile exposes configurable CPU, memory, process, file-
descriptor, wall-time, input/output-byte, network and spool ceilings. A kernel
or Android survival floor may remain hard, but it is reported with scope,
limit, used value and unit as `resource_exhausted`; it is never converted into
an action-risk denial. Codex may change its configuration, split a job, use a
background job or ask the owner after seeing that observation. Battery,
thermal, lock-screen, user-switch, OTA and provider-connectivity changes are
likewise lifecycle observations that the Agent can react to; only the
out-of-band recovery path may forcibly stop it.

Self-update uses versioned runtime/config directories and an atomic
`current` link (or equivalent exec handoff), retaining the previous generation
and a watchdog rollback marker. A failed update yields a visible restart or
restore observation rather than bricking the only Agent. No snapshot, receipt
or approval ceremony is required before an owner-open update.

## 5. Repository convergence map

| Current area | Revision-3 action |
| --- | --- |
| apps/trillionniumd | Make this the single Agent Host and turn supervisor. Keep session/event storage and provider connection; remove semantic Authority dispatch. |
| `crates/trillionnium-os-types/src/agent_descriptor_registry.rs`, `src/agent_principal_registry.rs` and their generated consumers | These generated registries are pre-r2 admission artifacts, not an owner-open identity service. They currently hard-code `openai-codex`/`agent-codex-direct-v1`, replay namespace, UID/GID 5901, `supervised-codex-cli`, SELinux domain and a `SYSTEM_API`/`ACCESSIBILITY` endpoint allowlist, and expose `PRODUCT_ALLOWLIST`, `from_uid_gid`, `from_registration`, `matches_registration`/`matches_registration_fields` plus the `SAME_CRATE_COUNTERFACTUAL_BUILD_REQUIRED`/materialization HOLD. The owner-open graph must not call those lookups or fixed checks. Replace them with a mechanism-neutral, owner-configured process/correlation descriptor (or regenerate a descriptor with no allowlist), and keep the generated registry only behind `legacy-authority`/`sealed-*`; its materialization HOLD must not enter the owner-open build or startup path. Audit `main.rs`, `providers/codex.rs`, privilege broker, capability/direct-operation and conformance callers so one stale import cannot recreate a hidden Authority. |
| `crates/trillionnium-os-types/src/lib.rs` root exports (`AgentRegistration`, `AgentContextRef`, `AgentPlannedAction`, `AgentPlanSubmission`, `AgentExecutionRequest/Binding`, `AgentNetworkPolicy`, `RiskTier`, `ApprovalRequirement/Lifetime`, `ToolManifest.agent_plan_contract`, `ToolCallInput`, `ToolRunStatus` and validation helpers) | These legacy root-level structs/enums are compiled even when individual registry modules are hidden, so `deny_unknown_fields`, fixed identity, risk/approval/plan and policy fields can leak through a supposedly raw crate. | Emit the owner-open frame/correlation/observation types from the separate `trillionnium-owner-open-types` crate (or cfg-gate the entire legacy root API behind explicit sealed features). Prove the default closure has no `requires_approval`, risk, lease, fixed identity or plan validator; a new raw module beside unconditional exports is not sufficient. |
| crates/trillionnium-tool-runtime/src/supervised_codex.rs | Launch one Codex provider and expose direct shell.exec and adb.exec. Remove read-only/disabled behavior that prevents owner-open operation. Keep a thin MCP alias only if the provider needs it. |
| crates/trillionnium-shell-exec | Replace the seven-command and risk_guard path with command-string plus argv execution, PTY/streaming, process-group cancellation and raw results. |
| crates/trillionnium-shell-exec/src/{lib,mcp_adapter,authorization,product_broker,product_ipc,product_worker,product_paths,android_property,post_exec_admission}.rs and `src/bin/trillionnium_agent_shell.rs` | Do not leave `standard_shell_exec_only`, `RequestDenied`, fixed UID 5903/chroot/workspace/approved-digest/`no_new_privs`, `require_product_post_exec_admission` or ready-property checks on the owner-open path. Reuse only generic spawn/PTY/stream/liveness primitives, or compile the old measured worker behind `sealed-*`/`legacy-*`. |
| crates/trillionnium-agent-direct-tools/src/adb.rs and adb_wire.rs | Turn the inert contract into the real raw ADB connector. Keep framing/transport errors; remove business-action filtering. |
| AOSP `packages/modules/adb/Android.bp` and `vendor/trillionnium/prebuilt/common/linux/agent-direct-tools/trillionnium-agent-adb` | Do not confuse either current artifact with the required Root Linux client: the ordinary AOSP `adb` target is `cc_binary_host` while the existing AArch64 vendor ELF is the typed `AdbRequest`/`BackendUnavailable` helper. Cross-build/repackage a compatible ARM64 userspace platform-tools `adb` plus its runtime libraries/server/USB transport, or provide a byte-transparent relay/native libadb connector. Put the resulting executable in the normal Root Linux PATH and verify `file`/interpreter/libs, `adb version`, `adb devices -l` and a raw target command. Merely adding `PRODUCT_PACKAGES += adb`, shipping `adbd`, or renaming the typed helper does not satisfy W3. |
| `crates/trillionnium-agent-direct-tools/src/adb_transport_boundary.rs`, `risk_guard.rs`, `post_exec_admission.rs` and typed ADB policy modules | Keep `adb_transport_boundary`/`AdbAdmissionPolicy`, `AndroidAdbTier`, key-generation/lease checks and `ProductRiskGuard` only behind `legacy-authority`/`sealed-*`. The owner-open `adb.exec` path invokes the ordinary ADB client or transparent shim and retains only framing, transport and liveness mechanics. |
| `crates/trillionnium-agent-direct-tools/src/adb_wire.rs` nested `transport_boundary` module | Split the pure frame/byte transport codec from the typed admission module. The owner-open `adb.rs` must not re-export or depend on `AdbAdmissionPolicy`/`AndroidAdbTier`; gate the nested legacy module with `legacy-authority`/`sealed-*` so downstream code cannot accidentally select it. |
| `crates/trillionnium-agent-direct-tools/src/lib.rs` JSON helpers | Do not route owner-open frames through fixed `MAX_REQUEST_BYTES`/`MAX_RESPONSE_BYTES`, `valid_atom` or closed request-id/BackendUnavailable validators. Use owner-configured framing with spool/stream support and map malformed frame, spawn and provider failures to the mechanical statuses in the new contract; large/binary input must not be rejected as a business action. |
| `crates/trillionnium-agent-direct-tools/src/system_api.rs`, `accessibility.rs` and `risk_guard.rs` | Make System API/Accessibility convenience wrappers codec/transport-only on owner-open: pass target, user/profile, arguments and raw platform errors to Codex. Their current fixed user, `deny_unknown_fields`, MAX_* bounds, journal, capability and `ProductRiskGuard` admission paths are legacy/sealed and must not be imported by the default direct path. |
| crates/trillionnium-os-types/contracts/direct-effect-v1.json and src/direct_effect.rs | Do not use the typed risk/lease/confirmation contract for owner-open shell or ADB. Replace it with the raw turn/tool-call/observation ABI; retain `DirectEffectRequestV1`, `PolicyRejectedBeforeDispatch`, fixed cwd/output rules and command-string denial only behind `legacy-*`/sealed features. |
| crates/trillionnium-os-types/contracts/direct-agent-host-abi-v1.json and src/direct_agent_host_abi.rs | Replace the wire method `plan` and `plan_id`/approval/authority result fields on the default carrier with `run_turn` streaming events. Add a new generator/input beside `crates/trillionnium-os-types/tools/generate-direct-agent-host-abi.py`; switch `owner_open_agent_api`/`android_agent_api` compatibility boundary and `agent-api-uds` consumers to its generated output. Keep `action_workflow` and the old carrier only as explicitly named compatibility features. |
| `crates/trillionnium-agent-api-uds/src/lib.rs` | Add an isolated raw `RunTurnFrame`/stream module (or a small owner-open UDS crate) and make it the default consumer. The current `AgentApiRequest`/closed method table, `deny_unknown_fields`, fixed 262 KiB frame and channel-binding validators remain whole-module legacy; merely adding `run_turn` to that table still compiles and can route through the old gate. Put the old API behind `legacy-plan-methods`/sealed features and verify the owner-open binary links only framing/correlation/liveness mechanics. |
| schemas/tool-manifest.schema.json and trillionnium-tool-runtime manifest builders | A direct shell/ADB descriptor must not be validated as the old `agent_plan_contract` requiring `requires_approval`, `network_scope` or `undo_contract`. Add a provider-neutral direct-tool schema and keep old manifest validation out of the owner-open call graph. |
| `apps/trillionnium-agent-privilege-broker` and `crates/trillionnium-privilege-broker-protocol` | Do not rename or reduce this binary into the active owner-open path. Its `main()` is itself the pre-r2 Authority: fixed `AF_UNIX/SOCK_SEQPACKET`, one authenticated client, UID/SELinux/executable checks, fixed capabilities and `parse_expected_peer_from_environment()`, while mutations return `mutation_unavailable`. The owner-open default must not compile, link or start either package; mark them `sealed-privilege-broker`/historical (with `required-features` or a separate workspace invocation). The protocol crate's closed/`deny_unknown_fields` types and generated-principal dependency are likewise not owner-open primitives. |
| crates/trillionnium-policy-system and trillionnium-task-registry | Move user policy, task plans and memory semantics into the Codex workspace. Retain only provider-neutral storage/serialization seams needed by the host. |
| direct_operation_* and capability_lease_* | Keep useful event/operation persistence primitives; delete or quarantine issuer/consumer/approval semantics that recreate a second Agent. |
| `crates/trillionnium-os-types/src/agent_direct_permission_model.rs`, `typed_operation_catalog.rs`, `provider_seccomp_contract.rs`; `crates/trillionnium-agent-direct-tools/src/{semantic_identity,risk_guard,post_exec_admission,production_entry_hardening,direct_tool_call_transport,android_operation_replay_ack,operation_replay_sync,device_launch_package_conformance*}.rs`; and `apps/trillionniumd/src/direct_operation_custody/` | These are additional pre-r2 semantic/measurement surfaces: fixed principal and endpoint tables, `permission_disposition`, closed typed operation catalogs, embedded P01 measurements, seccomp/admission/lease checks, replay ACK/HOLD and `BackendUnavailable` paths. The owner-open Cargo default must not compile or import their policy portions. Gate each whole module under `legacy-authority`/`sealed-*`, or extract only genuinely neutral byte/codec helpers into a separate crate. In particular, remove `DIRECT_AGENT_TOOL_NAMES`, `PermissionPrincipal::from_registration`, fixed `EXEC`/`ADB_LAUNCH_SETTINGS_*` catalogs and generated `deny_unknown_fields` validators from the default call graph; a broad `direct_operation_*` cleanup is insufficient if `os-types` still exports these tables. |
| `crates/trillionnium-agent-direct-tools/src/lib.rs` and `crates/trillionnium-os-types/src/lib.rs` module exports | Both crates currently publicly compile a wide set of old `accessibility`, typed `adb`, `mcp`, `operation_journal`, replay/identity, authority, permission-model and operation-catalog modules. Add an explicit `owner-open` feature/module (for example `owner_open.rs` or a small neutral codec crate) and cfg-gate the old public modules under `legacy-authority`/`sealed-*`; prove the owner-open binary cannot import `AndroidGatewayAdapter`, authority peer-pin, `production_agent_tool_allowed`, `execute_builtin_tool`, `DIRECT_AGENT_TOOL_NAMES` or fixed catalog/validator tables. A new raw function beside unconditional legacy exports is not sufficient. Generic byte framing/path-safety helpers may remain shared. |
| `crates/trillionnium-agent-direct-tools/src/lib.rs` unconditional private/public declarations (`canonical_operation`, `android_operation_replay_*`, `direct_operation_runtime_authority_*`, `journaled_call`, `mcp`, `operation_journal`, `operation_replay_sync`, `post_exec_admission`, `risk_guard`, `root_publication_transport`, `semantic_result`, `system_api`, `trusted_context`) | Audit the module declarations themselves, not only their call sites. Several currently compile old typed canonical-operation contracts, replay/authority custody and fixed `BackendUnavailable` helpers even when no product feature is selected. Gate whole modules under explicit sealed/legacy features or move neutral byte codecs into the owner-open crate; do not let `cfg(test)` alone pull them into a default owner-open `cargo test`. A private module that is never called can still pull policy types, build-time constants or tests into the default binary. |
| `crates/trillionnium-agent-direct-tools/Cargo.toml` `[[bin]]` entries (`trillionnium-agent-{system-api,accessibility,adb}`, replay-sync and operation-replay helpers) | These bins are currently buildable in the default package and several emit inert `BackendUnavailable`/measured-legacy behavior when no old feature is selected. Put every typed/System API/Accessibility/replay bin behind an explicit `required-features = ["legacy-authority"/"sealed-*"]` (or a separate sealed package), and add only a raw owner-open host/transport binary if one is actually needed. An unqualified `cargo build` of the owner-open workspace must not compile or ship these stubs; verify bins as well as library dependencies in the feature graph. |
| `foundations/trillionnium-typed-exec-adb-broker/` | This standalone foundation has its own workspace and is historical/non-product material. Its closed typed catalog, fixed 32 KiB frames, `require_userdebug_typed_adb_backend` HOLD and generated-principal imports must not be promoted or used as an owner-open fallback. The raw shell/ADB path in the canonical tree remains the only first-class implementation. |
| root `Cargo.toml` workspace members/default-members and feature unification | Unqualified workspace builds currently pull old privilege-broker, stdio-proxy, direct-tools, task-registry, policy-system and audit-sqlite members. Define the owner-open host/runtime as the default member and put legacy binaries/modules behind `required-features`/explicit `sealed-*` targets, or document an equivalent graph split. A crate being a workspace member is harmless only when it is not linked into the owner-open binary; verify the resolved dependency graph so feature unification cannot leak an Authority/typed validator into the direct path. |
| `crates/trillionnium-privilege-broker-protocol/src/lib.rs` legacy state constants (`PROTOCOL_FREEZE_READY`, `FOUNDATION_MUTATIONS_ENABLED`, `mutation_unavailable`) and their callers | These constants describe the intentionally inert pre-r2 foundation. The owner-open host must not read them, branch on them, or translate them into a startup/tool denial. If the old crate remains for sealed tests, keep the constants and `mutation_unavailable` vocabulary inside that feature only; a direct shell/ADB failure must be the real process/ADB observation. |
| apps/trillionniumd/src/android_agent_api.rs and action_workflow.rs | Make AiShell enter the raw `run_turn` stream directly. Move `method=plan`, `prevalidate_plan`, `plan_validated`, `consume_validated_egress_grant`, empty-plan checks and action-list/approval workflow behind `legacy-authority`; they cannot run before a direct tool call. |
| `apps/trillionniumd/src/owner_open_agent_api.rs` (new, or equivalent small `direct_turn.rs`) | Prefer a small owner-open listener/adapter with raw `run_turn` frames over editing the 14k-line legacy API in place. `main` compiles this module by default; the existing `android_agent_api.rs` and its tightly coupled plan/egress/action workflow are whole-module legacy/sealed compatibility. |
| crates/trillionnium-tool-runtime/src/lib.rs and src/supervised_codex.rs | Ensure `built_in_manifests`/`local_shim_manifests` do not inject the old plan validator, and provide an owner-open provider constructor with full-access Codex, direct network and no egress-consent admission. `new_bound`/post-exec admission may remain sealed/legacy only. |
| `crates/trillionnium-tool-runtime/src/lib.rs` Android gateway/provider exports and `execute_builtin_tool` path | The crate still compiles/exposes `AndroidGatewayAdapter`, `commit_android_authority_boot_peer_pin`, `system_default_gateway_peer_policy_from`, `production_agent_api_manifests`, `LocalShimAdapter`, `validate_manifest`/call/output and `DEFAULT_ANDROID_AUTHORITY_SELINUX_DOMAIN`. Put the Android gateway, authority peer-pin, production manifest validators and LocalShim behind `legacy-authority-effects`/`sealed-*`, or split neutral codecs out. The owner-open provider must depend only on the raw direct-host module; verify no `production_agent_tool_allowed` or `execute_builtin_tool` path is linked even when the workspace is built with legacy members present. |
| `apps/trillionniumd/src/providers/codex.rs`, `providers/replay.rs` and `providers/egress_journal.rs` | Add the same owner-open provider constructor/config path here; the current `SupervisedCodexProvider::new_bound` and replay/egress-journal constructors must not be reached by default startup. Split or feature-gate the modules rather than relying on `main.rs` to avoid one bound call. The owner-open `invoke` implementation must be a distinct raw-stream path: do not merely set `effect_admission=None`, because the current invoke path still unconditionally calls issuer/capability binding, cloud-egress/intent/context-taint checks, fixed temp/schema/final-output validators, egress proxy, post-exec activation, terminal-event validation, bounded-final parsing and direct-tool evidence collection. Those checks are sealed/legacy; raw Codex JSONL/tool events and observations flow through unchanged. |
| `apps/trillionniumd/src/builtin_provider_identity.rs`, `capability_hardening.rs` and `direct_operation_binding_inbox.rs` | Gate the `env!(TRILLIONNIUM_P01_*)`/`include!(OUT_DIR/...)` measurement, fixed identity and capability-hardening code behind `sealed-*`/legacy. Owner-open must compile without P01 environment/artifacts and use the owner-configured Codex process profile. |
| `apps/trillionniumd::bind_agent_api_listener`, `AgentConnectionPool` and `handle_agent_api_stream` | Add the separate owner-open listener with configurable socket path/permissions and basic framing. Keep mechanical symlink/race, inode/path and frame-boundary safety, but do not require legacy peer executable/identity measurement, channel-binding challenge, fixed UID queue admission or semantic metadata before `run_turn`; those identity checks are sealed/legacy diagnostics. |
| `apps/trillionniumd/src/main.rs` argument dispatch and `vendor/trillionnium/prebuilt/common/bin/trillionniumd.sh` | Add an explicit `--owner-open --run-turn` runtime selector and pass it from the owner-open init service. Do not infer the profile from build environment or let the no-argument/default branch enter the legacy `--agent-api-uds` plan dispatcher. Keep `--agent-api-uds` as an explicitly named legacy/sealed selector until the direct listener is the only default. |
| `crates/trillionnium-tool-runtime/src/supervised_codex.rs` and `src/lib.rs` fixed-MCP/result helpers | On owner-open, bypass or feature-gate `CODEX_DIRECT_MCP_IDENTITIES`/`TOOL_NAMES`, `authorized_direct_mcp_identity`, `sanitize_direct_mcp_terminal`, `direct_mcp_structured_result`, `collect_direct_tool_call_evidence`, `validate_shell_exec_first_slice_arguments`, `validate_manifest`, `validate_tool_call` and `validate_tool_output`. The active parser keeps framing, correlation and raw bytes only; unknown tools, command strings and raw ADB are valid. |
| `apps/trillionniumd/src/context_memory.rs` and `ContextMemoryService::open_from_env()` | Add an owner-open storage/key mode that uses ordinary owner-configured event/memory storage (or an explicitly absent key) and does not discover AndroidAuthority metadata, call `prevalidate_authority_boot_key`, commit a peer pin or construct `AndroidAuthorityMemoryKeyCustody`. Keep authority-backed custody behind `legacy-authority`/`sealed-*`; a missing AiAuthority key must not prevent the first Codex turn. |
| crates/trillionnium-dbus and its callers | Keep D-Bus only for legacy UI compatibility. The active AiShell→Agent Host path is UDS/stdio/raw stream and must not validate `requires_approval` drift before a direct call. |
| `apps/trillionniumd/Cargo.toml`, workspace features and `apps/trillionniumd/build.rs`/`crates/trillionnium-tool-runtime/build.rs` | Make legacy D-Bus/policy/task/privilege/effect dependencies optional and define an `owner-open` default. Do not inject frozen P0 runtime digests, receipt/admission generators or legacy descriptors into that profile; keep those build-script branches under `legacy-*`/sealed features. In particular, remove the unconditional `trillionnium-dbus -> legacy-authority-effects` and `trillionniumd -> shell-exec(root-linux-mcp-adapter)` edges or split them into explicit sealed features. |
| `crates/trillionnium-shell-exec/Cargo.toml` and `crates/trillionnium-tool-runtime/Cargo.toml` | Add an `owner-open` raw process/PTY/command feature (or a small replacement crate) and make `android-product`, `root-linux-mcp-adapter`, broker/worker and host-conformance features explicit sealed/legacy choices. The default provider must not pull a restrictive broker merely because the crate is present. |
| `apps/trillionnium-agent-stdio-proxy` (the existing proxy; any future Codex System API carrier is a new neutral module, not an assumed path) | Exclude the current fixed-FD/SEQPACKET/nonce/closed-frame binary from the owner-open default (or put its `[[bin]]` behind an explicit sealed/legacy `required-features` target). If a new transparent owner-open alias is useful for the installed Codex CLI, implement raw opaque streaming in a separately named module (not `*-stdio-proxy`, which is reserved/sealed) and verify it carries the same command bytes, target configuration and observations as the native path. Native Codex shell remains valid without any proxy; do not maintain two divergent implementations. |
| `crates/trillionnium-agent-direct-tools/src/mcp.rs` and `apps/trillionnium-agent-stdio-proxy/src/lib.rs` | Do not use their current single closed tool schema, fixed packet/request caps, nonce/control-FD/packet-hash binding or BackendUnavailable lane for owner-open. Either add a raw opaque streaming mode in a separately named neutral carrier or keep both modules out of the default graph; native Codex shell plus ordinary `adb` remains the canonical first path. |
| tools/package_current_rootfs.py and shell-exec payload manifests | Add an owner-open packaging variant that does not require `shell-exec-standard-allowlist.v1.json`; the old payload is sealed/legacy material, not a Root Linux direct-tool prerequisite. |
| docs/contracts/agent-exec-adb-windows-product-boundary-v2.json | Mark as transition history and add the owner-open contract in P0-01. Do not let v2 risk/approval fields block direct dogfood calls. |
| Android init/SELinux/product files | Start and connect the real Agent Host, Root Linux shell and ADB path. Replace the debug-only bind with the owner-open connector and keep only mechanical lifecycle policy. |
| Owner-open runner/launcher branch | The current `trillionnium-root-linux-run.sh` hard-rejects commands other than `/usr/bin/trillionniumd`, while `trillionniumd.sh` pins Codex 0.144.1 and typed/P01 paths. Bypass or replace those wrappers for owner-open so init directly execs the configured Codex/full shell/ADB host; merely adding `--owner-open` to a rejecting wrapper is not enough. Keep the old wrappers as sealed/history targets. |
| `vendor/trillionnium/prebuilt/common/etc/init/init.trillionnium-system_ext.rc`, `.../bin/trillionniumd.sh`, `.../bin/trillionnium-root-linux-run.sh` and `.../bin/trillionnium-root-linux-bootstrap.sh` | Add an explicit owner-open bootstrap/run branch that does mount/executable/filesystem checks and starts a restartable daemon without fixed digest/manifest/journal/DPKG/ADB-placeholder admission. Remove the wrapper's single-daemon/UID 5901/rootfs-555 assumptions from the owner-open path; the current oneshot/high-water/egress chain and `legacy_v6` materializer are sealed/legacy, not the default service. The existing `trillionnium_root_linux_bootstrap` init service is itself a disabled oneshot materializer: do not start it in the owner-open graph unless it is replaced by a simple mechanical mount helper; otherwise it can mutate or gate the rootfs before the direct daemon. |
| `vendor/trillionnium/prebuilt/common/src/trillionnium_agentd_capability_launcher.cpp` and its `Android.bp` `trillionniumd` launcher | Replace or profile-gate the launcher that hard-codes `/system_ext/bin/trillionniumd-wrapper`, 5901-style capability/securebits/ambient/bounding checks and exit-70 exactness. Owner-open must directly exec the configured host/Codex (or a transparent launcher) and report platform errors; the measured capability launcher is sealed/legacy. |
| `vendor/trillionnium/prebuilt/common/Android.bp` and `tools/android_p01_device_conformance.py` | Decouple `trillionnium-root-linux-manifest-verified`, capability-lease/high-water/operation-journal gate modules and device-conformance receipts from the owner-open launch/build graph. They may produce release provenance or diagnostics, but a `HOLD`/`read_only_verdict`/absent authority bit must not prevent a userdebug Codex turn. |
| `vendor/trillionnium/prebuilt/common/tests/{agentd_peer_identity_contract_test.sh,agentd_no_rootfs_mutation_test.sh,agentd_production_tcb_test.sh,rootfs_bootstrap_transaction_test.sh,rootfs_bootstrap_v9_branch_contract_test.sh,rootfs_state_migration_test.sh,rootfs_v2_*_test.sh,retired_agent_provider_absence_contract_test.sh,agent_direct_product_contract_test.sh}` | These pre-r2 tests encode fixed peer identity, no-rootfs-mutation, P01/receipt, retired-provider, transaction-branch and typed direct-product assumptions. Rewrite the applicable tests as owner-open lifecycle/transport probes (daemon starts/restarts, writable overlay, raw shell/ADB, honest transport errors), or move them to an explicitly invoked `sealed-*`/legacy test suite. Do not preserve a semantic startup gate merely to keep a historical test green; tests that still assert a fixed UID, digest, allowlist, approval or `BackendUnavailable` are not owner-open acceptance criteria. |
| `vendor/trillionnium/prebuilt/common/tests/shell_exec_v1_android_product_wiring_test.py` and similar `*_product_wiring*`/`*_conformance*` tests | The current wiring test asserts `PASS_SOURCE_WIRING_ONLY`, `android_shell_fallback=false`, `adb_transport=false`, a 27-role receipt stage and fixed P01 modules. Mark it sealed/legacy or rewrite it to assert that the normal owner-open product contains a real ARM64/transparent ADB path and raw shell/ADB turn; its old “no transport”/receipt assertions must not fail or block owner-open builds. |
| `vendor/trillionnium/config/common.mk` and product package lists | Define an explicit owner-open package set: one `trillionniumd`/Codex host, Root Linux runner, real ARM64 ADB client/shim and thin AiShell. Remove `TrillionniumAgentPrivilegeBroker`, `TrillionniumCapabilityLeaseIssuer`, AiAuthority, egress-guard/launcher, high-water/ready-gate, operation-journal, measured-manifest and receipt-stage packages from the default owner-open `PRODUCT_PACKAGES`; keep them only in `sealed-*`/legacy variants. Do not rely on `PRODUCT_PACKAGES_DEBUG` to provide the product ADB path. |
| `packages/apps/TrillionniumAiAuthority/Android.bp` and `trillionnium-sdk/Android.bp` | The installable `TrillionniumAiAuthority`/`TrillionniumCapabilityLeaseIssuer`, identity-product and capability-lease-binder static libraries, descriptor registries and their source filegroups are a closed Authority closure. Exclude the whole closure from owner-open Soong `module-info`/APK class graphs; retain it only under an explicit sealed profile. A neutral frame codec must use a separately named owner-open module. |
| `device/motorola/fogos/trillionnium_fogos.mk`, `trillionnium_fogos_compat.mk`, `BoardConfig.mk`/`BoardConfigSoong.mk` and the `common_*` product includes | Select an explicit profile before the common product import expands `PRODUCT_PACKAGES` (for example a registered single-value `PRODUCT_TRILLINNIUM_AGENT_PROFILE` or an exported build-profile input set before `inherit-product`; a bare `TRILLINNIUM_AGENT_PROFILE` assigned late in a product file is not sufficient). `PRODUCT_TRILLINNIUM_AGENT_PROFILE` is not currently registered in AOSP's frozen product-variable lists; if that name is used, register it in `build/make/core/product.mk` before `.KATI_READONLY` freezes the lists, or use an environment/Soong-config input exported before product parsing. A late BoardConfig assignment cannot retroactively change `common.mk` conditionals. `common.mk` and `sepolicy.mk` consume the early value during product/config evaluation; the late Trillionnium BoardConfig/BoardConfigSoong hook re-asserts it and emits a dedicated `trillionnium_agent_profile` for Soong. Only a sealed profile may derive a P01 build variant. If the common SDK closure has no neutral split yet, use a profile-conditional `TARGET_DISABLE_TRILLINNIUM_SDK := true` (or an equivalent explicit neutral-SDK switch) before it is inherited. Verify `module-info.json`, `PRODUCT_PACKAGES(_DEBUG)`, init services and compiled policy all derive one matching profile. Missing/unknown/mismatched profile is a build configuration error, not a runtime turn gate. Do not infer the owner-open graph from `TARGET_BUILD_VARIANT` or `TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT`; phone/tablet/TV/car products remain legacy unless they opt in explicitly. Give any compat product a distinct product identity or explicit sealed profile. Keep the old Authority/P01 package graph behind a separately selected `sealed-*` profile. |
| `packages/apps/TrillionniumAiShell/src/org/trillionnium/aishell/{AiShellActivity,BuiltInAgentClient,DirectAgentResult,AiProtocol,WorkflowStoreProtocol,DirectAgentHostAbi}.java` and its `Android.bp` | Make AiShell a text/session UI that sends `run_turn` frames and renders streaming model/tool/observation events. Move `sendToProviderAndPlan`, frozen-plan dispatch, grant/challenge/consent verification and old AiAuthority imports to a legacy source set; they must not run before an owner-open shell/ADB call. |
| `packages/apps/TrillionniumAiShell/Android.bp` Java globs/filegroups | Narrow the owner-open `srcs`/filegroups (for example to an `owner_open/` source set) so the old Authority/Workflow/DirectAgentResult classes are not still compiled through a broad `src/**/*.java` glob. Update static-library and test dependencies together; merely moving files without changing the glob leaves the old consent/lease path in the default APK. |
| `trillionnium-sdk/Android.bp` and `vendor/trillionnium/config/trillionnium_sdk_common.mk` (`org.trillionnium.platform`, `trillionnium-agent-identity-product`, `trillionnium-capability-lease-binder-api`, descriptor filegroups) | Remove these generated closed identity/lease libraries and registry source filegroups from the owner-open AiShell/platform closure; put them behind the explicit sealed/legacy profile with their contract tests. Split or profile-gate the common `org.trillionnium.platform` static library itself, because its current unconditional dependencies reintroduce the lease/identity closure. Add only a neutral owner-open frame/codec dependency, and inspect Soong `module-info`/APK class closure so a broad SDK include cannot reintroduce an Authority or lease client even when the old modules remain defined. |
| `frameworks/base/services/core/Android.bp` (`services.core.unboosted` → `org.trillionnium.platform.internal`) and `trillionnium-sdk/Android.bp` internal module | Audit the compile-time Soong closure, not just installable packages: the framework service currently resolves `org.trillionnium.platform.internal`, whose defaults pull the legacy SDK identity/lease sources. Profile-gate or replace that edge with a neutral owner-open codec module, and verify `module-info.json`/services class closure has no Authority, lease, replay or policy implementation. A module that is not installed but is still linked/resolved through `services.core` is still graph drift. |
| All current unconditional `org.trillionnium.platform`/`org.trillionnium.platform.internal` edges (including `frameworks/base/services/Android.bp`, `frameworks/base/services/core/Android.bp`, `frameworks/base/services/usb/Android.bp`, `frameworks/base/packages/SystemUI/shared/Android.bp`, `frameworks/base/packages/SettingsProvider/Android.bp`, `packages/apps/SimpleSettingsConfig/Android.bp`, `packages/apps/Profiles/Android.bp`, `packages/apps/FlipFlap/Android.bp`, `packages/apps/Settings/Android.bp`, `packages/apps/TrillionniumParts/Android.bp`, `packages/apps/SetupWizard/Android.bp`, `packages/apps/Launcher3/Android.bp`, `trillionnium-sdk/Android.bp`, `trillionnium-sdk/packages/TrillionniumPreferenceLib/Android.bp`, `trillionnium-sdk/packages/TrillionniumSettingsProvider/Android.bp` and `vendor/trillionnium/config/trillionnium_sdk_common.mk`)| The legacy identity/lease/replay SDK can remain in the selected Soong resolver and framework/app class closure even when `AiAuthority` is absent from `PRODUCT_PACKAGES`; checking only one framework edge or final APKs therefore gives a false clean result. | Treat this as one aggregate closure to neutralize: before the owner-open profile evaluates common products, remove/profile-gate every listed edge or replace it with a separately named neutral frame/codec library. Do not leave a same-named compatibility shim that still exports identity/lease classes. Enumerate each source/dependency edge with `rg`/Soong query, then verify `module-info.json`, resolved service/app classpaths, framework jars/APKs and target-files contain no `org.trillionnium.platform*` identity/lease/replay closure. A module not installed but resolved or linked is still non-converged; a source comment match in sealed/history material is not by itself a failure. |
| Framework source/resource consumers of the SDK (for example `frameworks/base/services/core/java/com/android/server/{wm/ActivityTaskManagerService.java,policy/PhoneWindowManager.java,BatteryService.java,notification/NotificationAttentionHelper.java,power/PowerManagerService.java,biometrics/sensors/fingerprint/aidl/FingerprintProvider.java}` and `frameworks/base/services/java/com/android/server/SystemServer.java`) | These are live imports and `R`/resource references, not dead Soong metadata: `TrillionniumActivityManager`, `TrillionniumButtons`, `ActionUtils`, `TrillionniumBatteryLights`, `TrillionniumNotificationLights`, `TrillionniumSettings`, device-key helpers and `config_*` resources keep the legacy platform/internal classes in always-built framework services. Simply removing the SDK jar or Authority APK will either fail compilation or preserve the semantic SDK closure. | Before selecting owner-open, split each framework integration into a neutral platform/resource API or select a profile-specific source/resource set that does not import identity, lease, replay or policy code. Preserve unrelated hardware/UI behavior only through neutral primitives. Verify both Java source/resource compilation and the resulting `services.core`/`services` jars against the forbidden closure; a compile-only shim with the old package/classes is not convergence. |
| `packages/apps/TrillionniumAiShell/AndroidManifest.xml` and authority/capability-lease static libraries | Remove or make legacy the `REQUEST_EGRESS_CONSENT`, `REQUEST_CONTEXT_CAPTURE`, `REQUEST_CAPABILITY_LEASE`, authority intents and lease-binder dependencies in the owner-open APK. Replace “after confirmation”/Deny/Archive/Resume authority UI with direct Codex text input and streaming result display; the UI must not become a hidden approval client. |
| `device/trillionnium/sepolicy/common/private/{trillionnium_rootlinux,trillionnium_shell_exec,trillionnium_agentd,trillionnium_agent_direct_tools,trillionnium_direct_operation_custody_high_water,trillionnium_agent_egress_guard}.te`, `file.te`, `file_contexts`, `users` and policy source lists | Create one owner-open Codex/Root Linux domain and labels for the writable overlay, real ADB, PTY/network/mount/process operations and the AiShell↔Agent Host socket. Remove or rewrite the old `neverallow` rules that forbid generic Root Linux data writes, TCP/raw sockets, ADB entrypoints or transitions; add the new abstract/filesystem socket `connectto`/peer rules. Move fixed 5901/5903 worker, high-water, egress-guard, ready-property, receipt and `trillionnium_agent_shell_tool`/`trillionnium_agent_shell_exec` transitions plus shell mountpoint labels out of the default policy; retain them only in sealed/legacy policy modules. |
| `device/trillionnium/sepolicy/common/private/trillionnium_verified_data_exec.te` and related generated policy lists | The current `neverallow` rules also forbid the Root Linux domain from executing files in the writable/data overlay (`trillionnium_shell_exec_payload_file:file no_x_file_perms` and the `data_file_type` execution prohibition). An owner-open shell must be able to create and execute scripts/binaries in its configured workspace. Add a distinct owner-open overlay/payload type and explicit transition, or rewrite these `neverallow` rules for the owner-open domain while preserving the sealed worker restriction. Verify the actual compiled policy and a runtime `sh -c 'write; chmod +x; exec ...'` probe; an allow rule that still loses to a `neverallow` is not a valid implementation. |
| `device/trillionnium/sepolicy/common/sepolicy.mk` and `common/private/` directory inclusion | The current make graph unconditionally compiles old Authority, capability-lease, replay, high-water, egress, shell-broker/worker and fixed `agent_shell_*` `.te`/file-context rules even when packages are removed. Split those policy sources into an explicit sealed directory and select `SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS` (or the equivalent) from `TRILLINNIUM_AGENT_PROFILE`; the owner-open compiled CIL/types/transitions must contain only direct Host/Root Linux/ADB mechanics. A source grep or removed package is not sufficient evidence. |
| `crates/trillionnium-shell-exec/src/lib.rs` and product broker/worker docs | Mark `standard_shell_exec_only`, `RequestDenied`, fixed timeout/argv/output bounds and measured-worker promotion checks as sealed/legacy. The owner-open implementation retains configurable global liveness and raw process/PTY mechanics. |
| `crates/trillionnium-shell-exec` raw path and `mcp_adapter.rs`/`durable.rs` | Build or select a separate owner-open streaming implementation; do not accidentally call `read_request`/`write_response` fixed 256 KiB/1 MiB caps, `SHELL_EXEC_MAX_RAW_OUTPUT_BYTES`, first-slice timeout/effect-count limits, packet/peer/registration checks or fixed durable snapshot caps. These are liveness/profile choices only when owner-configured and must not become command denial. |
| supervised_codex_legacy_plan.rs and legacy-* features | Keep only as explicit history tests until the new path is live, then archive. Never link them into the default runtime. |

The supported AOSP invocation must use the Trillionnium `envsetup/lunch`
path that exports `TRILLINNIUM_BUILD` before the custom BoardConfig hook runs.
Record the selected product/profile and verify that `common.mk` sees the same
owner-open value; a plain AOSP `lunch` that skips the vendor hook is not a
valid owner-open graph probe. This is build-input plumbing, not a runtime
approval gate.

The direct-build path must enforce the same invariant: AOSP
`build/make/core/config.mk` currently includes
`vendor/trillionnium/config/BoardConfigTrillionnium.mk` only when
`TRILLINNIUM_BUILD` is non-empty. A direct Soong/Kati invocation or a cached
build that omits that input must either make the hook unconditional for the
selected Trillionnium product or fail early with a configuration error; it must
not silently evaluate the old/common package graph and rely on a late mismatch
check. Validate `TRILLINNIUM_BUILD` and the early profile input before product
imports, then record the resolved value in the Soong config and target-files.

The Android product graph must make the owner-open connector a normal
userdebug product input, not a PRODUCT_PACKAGES_DEBUG-only placeholder. Replace
the current debug ADB ELF/init bind and the rootfs empty placeholder with one
ARM64 adb executable plus its explicit transport configuration. Remove
AiAuthority/CapabilityLeaseIssuer/action-workflow modules from the runtime
graph; a compatibility build may retain them only outside the default target.
Concretely, audit packages/apps/TrillionniumAiAuthority (including its
`leaseissuer/` module), packages/apps/TrillionniumAiShell and their
common.mk/Android.bp registrations, plus the broker/high-water/egress init
services. AiShell may remain as a thin session UI, but it must call the single
Agent Host and must not ship a second semantic lease/approval service.

Use bounded, recoverable moves for retired code. Do not reset the dirty
worktree or mix the old rootfs/data estate into the active source tree.

### 5.1 Current implementation delta (historical source snapshot, audited 2026-08-26)

The following are observed source facts, not hypothetical design concerns. The
2026-08-27 selected-graph audit in §5.2 is the current convergence check; this
table preserves the earlier source snapshot so an implementer can remove the
old boundary rather than adding another adapter around it.

| Observed source behavior | Why it is wrong for owner-open | Required change |
| --- | --- | --- |
| supervised_codex.rs launches with a read-only sandbox, disables the built-in shell/apps/browser/multi-agent tools and exposes only two fixed MCP tools; its prompt says Android shell/ADB/root are unavailable. | Codex cannot operate the machine it is meant to be the OS Agent for. | Start Codex with the owner-open workspace, enable the direct shell and ADB tools, and make the prompt/tool description truthful. Keep optional convenience tools behind the same direct transport. |
| The shell-exec crate accepts only the standard exact-argv profile, rejects command strings and shell interpreters, and carries a seven-command list. | Pipes, scripts, package managers, compilers and ordinary debugging are impossible; the list becomes a second policy engine. | Make command-string and argv modes first-class, remove the business allowlist/risk guard, and retain only process-group, PTY, output and liveness mechanics. |
| adb.rs execute_production and adb_transport_boundary.rs return a fixed BackendUnavailable/TransportUnavailable result; the Android rootfs only has a placeholder and a userdebug bind fragment. | ADB is advertised as a product capability but Codex can never call it. | Build the real connector, put the ADB binary/server in the owner-open Root Linux PATH, and pass raw ADB arguments/results through. |
| init.trillionnium-system_ext.rc waits for high-water custody, a ready gate, shell-broker readiness and egress-guard properties before starting the Root Linux daemon. | A chain of semantic gates recreates the rejected Authority OS and prevents useful dogfood. | Keep mount/exec checks, service restart and watchdog; remove semantic property preflight from the owner-open service start. |
| trillionniumd and the Android API path still carry plan_id, authority_called, approval and action-list fields. | The wire model tells implementers that a hidden planner owns the turn. | Add the turn/tool_call/observation ABI and retain old fields only in an explicit legacy compatibility module. |
| `crates/trillionnium-os-types/contracts/direct-effect-v1.json`, `direct_effect.rs` and their shell-exec tests still require `risk_class`, `policy_sha256`, confirmation leases, workspace-only cwd, interpreter denial and `PolicyRejectedBeforeDispatch`. | The current generated validator structurally rejects command strings, arbitrary cwd and raw ADB before Codex can see them. | Generate the default owner-open ABI from `codex-sovereign-direct-tools-v1`; move the typed effect contract, validators and tests behind `legacy-*`/sealed features and leave only mechanical framing/liveness on the direct path. |
| `direct-agent-host-abi-v1.json`/`direct_agent_host_abi.rs` still name the direct method `plan`; `android_agent_api.rs` routes it through `prevalidate_plan`, `plan_validated`, egress-grant consumption and `action_workflow`. | A direct request still traverses the old plan/approval control plane even if a new tool schema exists. | Add the default `run_turn` streaming ingress from AiShell to the single provider; keep `plan` and all preflight/approval/action branches legacy-only. |
| `CodexBackend::requires_network_approval()` and `supervised_codex`'s `new_bound`/egress proxy path remain active by default. | The provider can be refused before it ever emits a shell/ADB call. | Add an owner-open constructor/config with full-access Codex and owner-configured direct network; no egress consent or effect-admission hop. Keep bound/approval constructors only in sealed/legacy profiles. |
| Production feature flags and receipt builders fail closed before any physical effect. | Source receipts become a substitute for using the Agent. | Let owner-open execute and log the real result. Keep artifact/signing/rollback checks for the later public profile. |

The exact source anchors currently checked are
supervised_codex.rs around the Codex launch configuration, shell-exec
validation in crates/trillionnium-shell-exec, execute_production and
ProductionAdbTransport in crates/trillionnium-agent-direct-tools, and the
Root Linux service stanzas in the Android init fragment. Line numbers are
allowed to move; the behavior above is the invariant to remove.

The default call graph must converge in this order:

~~~text
AiShell UDS/stdio
  -> trillionniumd run_turn stream
  -> Codex provider (owner-open constructor, direct network)
  -> raw shell.exec / shell.command / adb.exec
  -> mechanism substrate
  -> observation back to the same turn
~~~

The old `android_agent_api` `method=plan` branch, `CodexAdapter::plan_attempt`
path, egress-grant preparation/consumption and action-workflow validators are
not allowed to sit in front of this stream. They are moved behind a
default-off `legacy-authority` feature or removed from the default Soong/Cargo
graph. Similarly, `direct-effect-v1`, `direct-agent-host-abi-v1`, the old
`agent_plan_contract`, and their generated tests are not the owner-open ABI;
the new raw contract is the generated source of truth.

The dirty working tree currently contains a large typed android.adb.* enum,
AndroidAdbTier/confirmation fields and a ProductionAdbTransport that always
returns HOLD. Those files are useful migration evidence but cannot be linked
into owner-open. Replace them with the raw AdbExecRequest contract or move
them to an explicit legacy/sealed feature. Likewise, the recent
supervised_codex hardening that forces ignore-user-config, ignore-rules,
ephemeral mode, read-only sandbox, fixed MCP and loopback-only egress belongs
to a future sealed profile if it is still wanted; it must not be the default
Codex launch.

### 5.2 Default-graph reconciliation (must be checked after graph edits)

The owner-open graph is not considered converged because a source file is
labelled “legacy”. The resolver, package list, init triggers, compiled labels
and target-files output must all agree. The current audit is intentionally
recorded as **not converged**:

| Surface | Current observation (2026-08-27) | Required owner-open result |
| --- | --- | --- |
| Cargo | `workspace_default_members` still includes `trillionnium-agent-privilege-broker` and `trillionnium-agent-stdio-proxy`; the protocol crate remains a workspace dependency. | Default members/closure contain only the owner-open Host, raw direct tools and neutral codecs. Broker/protocol/proxy require an explicit sealed/history invocation. |
| Soong/product | `vendor/trillionnium/config/common.mk` still installs `TrillionniumAiAuthority`, `TrillionniumCapabilityLeaseIssuer`, egress guard/launcher/probe, operation-journal/replay contracts, P01 artifacts, and userdebug high-water/ready-gate/`trillionnium-agent-shell`/shell broker/worker; `PRODUCT_PACKAGES_DEBUG` still adds the typed ADB helper. | The default owner-open product contains one Host, Root Linux runner, real ARM64/transparent ADB and thin AiShell; every listed semantic/typed node is absent. |
| Framework/SDK compile closure | `org.trillionnium.platform(.internal)` is still referenced by the standard framework services/apps and `trillionnium-sdk`; live framework Java/resource consumers also import Trillionnium settings, key, light and activity classes. | Profile-gate or replace the complete edge/source-consumer set before claiming convergence; verify Soong `module-info`, service/app classpaths and compiled framework jars, not only installed APK names. |
| init | `init.trillionnium-system_ext.rc` still has `rootlinux.prepare` property choreography and starts egress → high-water → shell broker → `trillionniumd --agent-api-uds`. | One restartable `trillionniumd --owner-open --run-turn` service; no old property/start chain or fixed control-FD proxy. |
| generated image | The latest dogfood `product_packages.txt`/`.installable_files` contains the old APKs, binaries and init fragment. | Rebuild after graph edits, then inspect the new target-files output; stale output is evidence of the old image, never proof of convergence. |

Use a negative-set check, not only a grep over source comments. The following
is an optional post-build convergence audit for the integrated product; it is
never part of the developer bootstrap/direct-smoke path.

~~~sh
# Rust graph
cargo metadata --no-deps --format-version 1 \
  | jq '.workspace_default_members, .packages[].name'
cargo tree -e features -p trillionniumd
cargo_graph="$(cargo tree -e features -p trillionniumd --features owner-open 2>/dev/null)" || {
  echo 'owner-open Cargo graph could not be resolved' >&2
  exit 2
}
if printf '%s\n' "$cargo_graph" \
  | grep -Eiq 'AiAuthority|CapabilityLease|privilege[-_]broker|agent[-_]egress|egress[-_](guard|launcher|probe)|high[-_]water|trillionnium[-_]agent[-_]shell|shell[-_]exec[-_](broker|worker)|operation[-_]journal|trillionnium[-_]p01|p01[-_]|agent[-_]adb|org\.trillionnium\.platform'; then
  echo 'forbidden owner-open Cargo dependency reachable' >&2
  exit 1
fi

# AOSP graph (after envsetup/lunch for the selected product)
get_build_var PRODUCT_PACKAGES
get_build_var PRODUCT_PACKAGES_DEBUG
resolved_root="$OUT_DIR/target/product/$TARGET_PRODUCT"
test -f "$resolved_root/product_packages.txt" || { echo 'product_packages.txt is missing; build the selected product first' >&2; exit 2; }
test -f "$resolved_root/.installable_files" || { echo '.installable_files is missing; build the selected product first' >&2; exit 2; }
grep -Eiq 'AiAuthority|CapabilityLease|privilege[-_]broker|agent[-_]egress|egress[-_](guard|launcher|probe)|high[-_]water|trillionnium[-_]agent[-_]shell|shell[-_]exec[-_](broker|worker)|operation[-_]journal|trillionnium[-_]p01|p01[-_]|agent[-_]adb|org\.trillionnium\.platform' \
  "$resolved_root/product_packages.txt" "$resolved_root/.installable_files"
package_match_rc=$?
case "$package_match_rc" in
  0) echo 'forbidden owner-open package/installable present' >&2; exit 1 ;;
  1) : ;;
  *) echo 'could not read selected package/installable output' >&2; exit 2 ;;
esac

# Source audit only: sealed/history fragments may legitimately match. Do not
# use this source scan's exit status as the owner-open convergence result.
rg -n 'trillionniumd --owner-open --run-turn|trillionniumd --agent-api-uds|agent_egress_guard|high_water|trillionnium-agent-shell|shell_exec_broker|rootlinux\.prepare' \
  vendor/trillionnium/prebuilt/common/etc/init device/trillionnium/sepolicy || true

# Blocking check: inspect only the selected product's resolved init/policy
# artifacts after the owner-open profile has been built.
test -d "$resolved_root" || { echo 'selected target-files output is missing; build it first' >&2; exit 2; }
for resolved_dir in "$resolved_root/system/etc/init" "$resolved_root/system_ext/etc/init" "$resolved_root/vendor/etc/init" \
  "$resolved_root/system/etc/selinux" "$resolved_root/system_ext/etc/selinux" "$resolved_root/vendor/etc/selinux"; do
  test -d "$resolved_dir" || { echo "resolved artifact directory is missing: $resolved_dir" >&2; exit 2; }
done
rg -n 'trillionniumd --agent-api-uds|agent_egress_guard|high_water|trillionnium-agent-shell|shell_exec_broker|rootlinux\.prepare' \
  "$resolved_root/system/etc/init" \
  "$resolved_root/system_ext/etc/init" "$resolved_root/vendor/etc/init" \
  "$resolved_root/system/etc/selinux" "$resolved_root/system_ext/etc/selinux" "$resolved_root/vendor/etc/selinux"
resolved_match_rc=$?
case "$resolved_match_rc" in
  0) echo 'forbidden owner-open node present' >&2; exit 1 ;;
  1) : ;;
  *) echo 'could not read selected init/policy output' >&2; exit 2 ;;
esac
~~~

The expected owner-open result is zero forbidden package/service/installable
matches in the selected resolved graph and exactly one long-lived direct Host
entrypoint. A non-zero result
means “graph not converged”; it blocks the **integrated-path claim**, but never
blocks the developer bootstrap lane or a direct shell/ADB diagnostic. Rebuild
and rerun this check after every Cargo/Soong/init change. Do not silence it by
renaming a legacy module or by retaining it in `PRODUCT_PACKAGES_DEBUG`.

## 6. Ordered implementation work

The phases are an implementation sequence, not a collection of approval gates.
A phase can be exercised in a local or userdebug environment as soon as its
inputs exist.
P0-01 is contract/convergence work and does not block the first runnable
milestone. An implementer may begin P0-02/P0-03 immediately by launching the
installed `codex exec --dangerously-bypass-approvals-and-sandbox --json` inside
Root Linux with `/bin/sh`
and a real `adb` on `PATH`; use a transparent JSONL/stdio event carrier until
the generated codec lands. The carrier swap must preserve raw command bytes and
observations, not delay direct shell/ADB access.

The first runnable owner-open turn is intentionally this small (no generated
receipt, BOM, approval screen or static PASS is required):

~~~text
inside Root Linux:
  DEVICE_SERIAL="${ANDROID_SERIAL:-ZY32JLVHGN}"  # discovery/default lab hint, not wrapper injection
  codex exec --dangerously-bypass-approvals-and-sandbox --json \
    "Run pwd; id; command -v adb; adb version; create/read /workspace/probe; run adb devices -l and adb -s $DEVICE_SERIAL shell id; return every raw observation."
  # The arrows below are events emitted by this one provider turn, not
  # separate operator or host-side commands.
  -> shell: pwd; id; command -v adb; adb version
  -> shell: printf owner-open > /workspace/probe && cat /workspace/probe
  -> shell: adb devices -l
  -> shell: adb -s "$DEVICE_SERIAL" shell id
  -> return raw events to the same Codex turn
~~~

If the CLI's native shell is not local to Root Linux, the same commands are
issued through the transparent direct alias; this changes transport plumbing,
not the Agent's available command surface.

### P0-01 — Publish the owner-open contract and remove semantic duplication

Deliver:

- docs/contracts/codex-sovereign-direct-tools-v1.json describing the single
  Codex principal, off-device inference, raw shell/ADB tools, target records,
  event envelope and owner-open profile.
- A generated descriptor whose descriptive/default entries include
  `shell.exec` and `adb.exec`; entries are documentation/codec metadata only.
  Their absence, an unknown tool label or a future extension must never reject
  a direct call or rebuild a closed tool catalog.
- ABI names that describe turn, tool_call, observation and resume. Old plan_id,
  authority_called and plan_submitted_for_execution fields are legacy-only and
  cannot appear on the direct path.
- The owner-open ABI is generated from
  `docs/contracts/codex-sovereign-direct-tools-v1.json`, not from
  `crates/trillionnium-os-types/contracts/direct-effect-v1.json`,
  `direct-agent-host-abi-v1.json` or `schemas/tool-manifest.schema.json`'s
  `agent_plan_contract`. Regenerate the default `ToolCallRequest`/
  `Observation`/`run_turn` carrier so command strings, arbitrary raw ADB argv,
  binary streaming and target records are representable. Compile the old
  `DirectEffectRequestV1`, `DirectEffectTerminalKindV1`, `plan` carrier,
  `requires_approval`/`risk_class`/lease fields and policy-denial terminals
  only behind `legacy-*` or sealed features; they must be absent from the
  default Cargo/Soong call graph.
- Add the new generator/input and generated Rust/JSON outputs as a three-part
  change: the generator, the `run_turn`/raw-tool carrier, and all owner-open
  consumers (`owner_open_agent_api`, `agent-api-uds`, `tool-runtime`, AiShell
  and init probes) switch together. `action_workflow` is legacy-only. The
  existing generator that reads
  `direct-agent-host-abi-v1.json` must not continue emitting a `plan` method.
  Generate a small Java/Kotlin frame codec for AiShell, or use an independent
  JSONL parser with the same open fields; the old `DirectAgentHostAbi.java`,
  `DirectAgentResult.java` and closed-world Java tests move to legacy.
  The Rust outputs are written under the control-plane tree and the Java/Soong
  output under the separate canonical AOSP tree
  `/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/android/lineage-fogos`;
  invoke the generator with explicit roots (or stage then copy/review). Never
  create a phantom `packages/` tree inside the Rust repository or mix the two
  estates implicitly.
  This convergence work is not a prerequisite for the first dogfood turn: a
  transparent JSONL/stdio carrier with the same open fields may run first, and
  the generated codec can replace it later without changing tool bytes or
  event meaning.
- One configuration location for Codex behavior, memory and targets:
  `$CODEX_HOME/trillionnium/owner-open.toml` (with explicitly documented
  environment overrides for secrets and ephemeral paths). It contains the
  Codex binary/flags, provider endpoint and credentials, Root Linux root and
  overlay, host/ADB server and serial defaults, resource ceilings, network and
  namespace choices, and event-log/spool paths. It is Agent/owner-owned data
  and reloadable at a turn boundary. Built-in minimal defaults (`/bin/sh`, the
  current Root Linux cwd/PATH, local event spool and the current process
  target) keep dogfood bootable when the file is absent. A malformed file or an
  explicitly requested override is reported as a raw startup/configuration
  error/warning, never translated into a semantic deny or a reason to hide
  shell/ADB.
  `turn_boundary` reload applies new provider, target, memory, logging and
  resource values to the next turn/job. UID/GID, namespaces, mounts, SELinux
  domain and inherited network handles are spawn-time properties; an already
  running process is not rewritten in place. If a changed spawn-time value
  requires a restart, the host emits an extension event `kind=config_changed`
  (or a restart event) carrying a canonical mechanical `status` such as
  `configuration_error`/`reconnect_required` and `error.stage=config`; Codex
  decides when to stop, resume or leave the old job running. The event kind is
  an opaque extension, not a new authorization status or configuration gate.
  The host sets `CODEX_HOME` to this dedicated profile and materializes or
  translates its Codex CLI `config.toml` (and any rules file) with an explicit
  precedence; it must not accidentally merge the operator's unrelated
  `~/.codex` profile. Whether user rules are loaded or ignored is an explicit
  Codex configuration choice, not a substrate authorization mechanism.
- Removal or quarantine of AiAuthority, plan-to-Authority translation,
  risk_guard, fixed action allowlists and compile-time BackendUnavailable on
  the owner-open feature.
- Make the feature split real in both `trillionnium-os-types` and
  `trillionnium-agent-direct-tools`: the default `owner-open` modules expose
  only the raw turn/tool/observation codecs and process/transport primitives;
  old public authority, permission, typed-catalog, replay-ACK and gateway
  modules are cfg-gated behind explicit `legacy-authority`/`sealed-*` features.
  Because Cargo features unify across a package, the robust choice is a small
  `trillionnium-owner-open-types`/`direct-tools` crate (or a separately built
  owner-open host package) containing the raw codecs, leaving the legacy
  `os-types` graph in old binaries; a package-wide cfg split is acceptable only
  if the resolved graph proves the same isolation. Use `cargo tree -e features`
  and a separate workspace invocation where necessary. Do not count a new
  wrapper around an unconditionally compiled legacy module as convergence.
- Do not route owner-open calls through the current `DirectEffectRequestV1`
  limits (120-second timeout, fixed argv/output sizes, workspace-only cwd,
  interpreter denial or `standard_shell_exec_only`). Move those checks to the
  sealed/legacy feature; owner-open keeps only configurable global liveness
  ceilings and exposes background jobs for work that outlives a turn.
- In `trillionnium-agent-direct-tools/src/lib.rs`, split the raw owner-open
  frame/process exports from the unconditional `read_request`, `valid_atom`,
  `valid_request_id`, typed `adb`/System API/Accessibility and `risk_guard`
  modules. The legacy exports may remain for compatibility, but the default
  provider must not import them or their fixed 256 KiB/1 MiB helpers; retain
  only generic framing, symlink/path safety, byte streaming and liveness.
- In `crates/trillionnium-shell-exec/src/bin/trillionnium_agent_shell.rs`,
  `crates/trillionnium-shell-exec/src/mcp_adapter.rs`,
  `crates/trillionnium-shell-exec/src/authorization.rs` and
  `crates/trillionnium-agent-direct-tools/src/post_exec_admission.rs`, remove
  the owner-open calls to
  `require_product_post_exec_admission`, `validate_first_slice_arguments`,
  fixed `DirectEffectModelArgumentsV1` decoding and `harden_entry`'s
  privilege-deny behavior. A parent-death signal and process-group cleanup may
  remain as liveness mechanics; `no_new_privs`, measured post-exec admission
  and `RequestDenied` are sealed/legacy behavior.
- A truthful Codex launch configuration: no read-only sandbox, no
  actions-maxItems-zero schema, no prompt prohibition on shell/ADB/root, and
  no second fixed-MCP whitelist that hides the direct tools. The provider may
  retain a thin MCP transport, but it must expose the same shell.exec and
  adb.exec implementation.
- This is a call-graph change, not just a prompt/manifest edit: the owner-open
  event path must bypass or feature-gate the fixed
  `CODEX_DIRECT_MCP_IDENTITIES`/`TOOL_NAMES`,
  `authorized_direct_mcp_identity`, `sanitize_direct_mcp_terminal`,
  `direct_mcp_structured_result`, `collect_direct_tool_call_evidence`,
  `validate_shell_exec_first_slice_arguments`, `validate_manifest`,
  `validate_tool_call` and `validate_tool_output` helpers. Keep framing,
  correlation, byte encoding and liveness checks; unknown tools, command
  strings and raw ADB must reach Codex as observations rather than a generic
  schema or policy denial.
- Keep the first slice single-process if useful, but do not make
  `--disable multi_agent` a substrate or release gate. Browser, apps,
  image-generation and Codex-native subagent capabilities are owner
  configuration choices. If native subagents are enabled, they remain under
  the same Codex principal and observable direct-tool event stream (native
  shell or transparent adapter); an independent Agent runtime is still
  forbidden. Do not confuse semantic singleton with single-process: a
  supervisor and Codex child processes are fine.
- Add an owner-open provider constructor/configuration that does not call
  `CodexBackend::requires_network_approval()`, `prepare_egress`,
  `consume_validated_egress_grant`, `new_bound`,
  `validate_capability_binding`, `BoundedConnectProxy` or post-effect
  admission. The owner-open path must also remove `ALLOWED_ACTIONS`,
  final-output-only schema and capability/taint preflight from the provider
  invocation.
  `CODEX_HOME`, endpoint, credentials, CA and direct network are passed as
  owner configuration. Those bound/approval paths may remain default-off
  legacy/sealed implementations.
- Switch `apps/trillionniumd/src/main.rs::codex_provider()` from its current
  unconditional `CodexAdapter::new_bound(...)` construction to the owner-open
  constructor by default; move the constructor assertion in `main.rs` tests and
  the `new_bound` capability-identity path behind the same sealed/legacy
  feature. A new owner-open provider must be able to start when the old
  capability identity or egress-grant state is absent.
- Remove from the owner-open execution call graph the hard-coded
  `prepare_isolated_child_process` assumptions (UID/GID 5901/5903, unconditional
  capability drop, `no_new_privs`, fixed seccomp/chroot/executable-digest
  checks, `env_clear` and loopback proxy). Replace them with the explicit
  owner-open execution profile described in section 3.2; retain only global
  Android liveness limits. A sealed profile may re-enable those restrictions.
- Migrate the existing supervised_codex tests that assert
  ignore-user-config, ignore-rules, ephemeral mode, read-only sandbox,
  output-schema actions=[] or BackendUnavailable. Add an owner-open mode
  first, then move those assertions to an explicit legacy feature; the
  migration search is not itself a release gate.
- Update or mark legacy the tests that currently import the v2 permission
  model (including test_agent_exec_adb_windows_product_boundary.py,
  test_agent_direct_permission_model.py, test_agent_typed_operation_catalog.py
  and the Rust agent_direct_permission_model module). The new owner-open
  contract is the default reference; v2 tests may remain only as historical
  compatibility tests.
- Move `android_agent_api.rs`'s `method=plan`/`prevalidate_plan`/
  `plan_validated` branch and `action_workflow.rs`'s empty-plan, approval and
  egress-grant checks behind `legacy-authority` (or delete them from the
  default graph). AiShell must enter the new `run_turn` stream directly; a
  compatibility adapter may translate frame syntax but may not make a
  semantic decision.
- Because the legacy Android API is tightly coupled to grant/recovery state,
  implement the default path as a new small `owner_open_agent_api.rs`/
  `direct_turn.rs` module (or an equivalent isolated replacement) and switch
  `main` to it. Do not rely on a partial `cfg` around one `match` arm while
  old `spawn`/reaper/preflight code can still run during startup.
- Add the owner-open `run_turn` arm before the old
  `is_product_agent_api_method`/state-change dispatcher and give it its own
  stream listener. The existing `run_tool`/`plan` branch requires task/plan/
  action IDs and must remain legacy-only; merely renaming its wire string does
  not remove that gate.
- Do not construct owner-open requests as the legacy `AgentApiRequest::new`:
  its non-health methods currently require a non-empty `agent_id`, closed
  method-table membership and (for several methods) a channel-binding
  challenge before the daemon sees the payload. `RunTurnRequest`/frames have
  their own parser and listener; `agent_id`/peer data are optional correlation
  metadata and raw transport failures remain observable.
- Implement a distinct `handle_owner_open_run_turn(stream)` that does only
  frame-boundary/size handling, optional peer diagnostics, correlation and
  stream forwarding. It must not reuse the legacy
  `handle_agent_api_stream` prelude (`enable_unix_message_credentials`, peer
  executable/identity measurement, `is_enabled_agent_api_method`, request-id
  validator or replay-store admission). The legacy handler stays wholly under
  `legacy-authority`/`sealed-*` until an explicitly selected sealed profile.
- Update `tools/verify_init_agent_activation.py` and its tests to discover the
  owner-open contract and `run_turn` path. The old checks that load
  `direct-agent-host-abi-v1.json` or the v2 permission/typed-operation
  contracts become legacy conformance tests, not default init validation.
- Remove or feature-gate the old Android ingress initialization as one unit:
  `EgressGrantState::open_from_env`, `ActionWorkflowJournal::open`,
  `reconcile_action_workflows`, the egress-expiry reaper and the
  `main.rs` `action_workflow` module must not be required for owner-open
  startup. A missing legacy state directory therefore cannot abort the new
  direct turn.
- Split the `run_agent_api_uds()` startup sequence in `apps/trillionniumd/src/
  main.rs` by profile. Owner-open keeps socket binding, filesystem setup and
  an owner-open `ContextMemoryService` storage/key mode, but must not abort on
  `compiled_measurement_is_exact`, `harden_android_agentd_from_env`,
  `load_os_agent_manifests`/`require_android_builtin_manifests` or capability/
  egress admission results. Those checks can log diagnostics or run in a
  sealed/release feature; a missing manifest or measurement must not stop the
  raw `run_turn` listener.
- Make the `main.rs` module declarations and dependency edges profile-aware,
  not merely the final dispatch arm. `action_workflow`, `android_agent_api`,
  `direct_operation_binding_inbox`, `direct_tool_call_transport`,
  `direct_operation_custody`, `direct_tool_call_allocator`, `egress_journal`
  and authority/provider-contract modules may compile only for
  `legacy-authority`/`sealed-*`; owner-open links the small
  `owner_open_agent_api`/`direct_turn` implementation and its ordinary byte
  store. A legacy module that is never called can still fail startup through a
  constructor, build script or static validator, so leaving it unconditionally
  compiled is not sufficient.
- If the existing `trillionniumd` crate cannot be cleanly split without
  pulling the old graph, create one explicitly named owner-open host binary
  (for example `trillionnium-agent-host-owner-open`) and switch init to it;
  this is a packaging boundary, not a second running Agent. Do not ship both
  binaries active or let Cargo feature unification link the legacy broker into
  the owner-open executable.
- Give owner-open startup explicit writable state and socket paths. Its
  `default_audit_path()`, `AgentService::from_store_after_exclusive_startup`,
  `AgentApiReplayStore::open_from_env()` and listener bind path must not inherit
  legacy HOME/XDG, replay, UID/GID/mode or peer-auth assumptions that can abort
  before `run_turn`. Use a simple owner-configured byte/event store and
  mechanical Unix-socket setup; retain strict audit/replay/peer checks only in
  `legacy-authority`/`sealed-*` profiles.
- Audit `ContextMemoryService` all the way through its constructor: the
  current `open_from_env()` discovers AndroidAuthority key metadata, calls
  `prevalidate_authority_boot_key`, commits a peer pin and constructs
  `AndroidAuthorityMemoryKeyCustody::system_default()`. Those calls, the
  `DirectPlanCustodyCandidate`/`action_workflow` type dependency, Android
  Keystore custody and UI/grant replay state must be absent from owner-open.
  Use a plain file/owner-configured key primitive or a minimal ordinary byte
  store for the first turn; an I/O or key error is a mechanical observation,
  not a semantic startup gate.
- Define explicit feature ownership in Cargo/Soong during this migration:
  `owner-open` is the default and links the raw turn stream, direct shell/ADB,
  storage and lifecycle primitives; `legacy-authority`,
  `legacy-plan-conformance`, `sealed-worker` and `sealed-release` are
  default-off. Make `trillionnium-dbus`, policy/task registries, the privilege
  broker, `root-linux-mcp-adapter` and measured effect workers optional or
  split into those features. A workspace member or an optional dependency
  must not be pulled into the live owner-open call graph accidentally.
- Remove unconditional `env!(TRILLIONNIUM_P01_*)`/`include!(OUT_DIR/...)`
  dependencies from the owner-open compile path (including the provider
  runtime digest, launcher binding, system-api digest and direct-operation
  inbox). Use `option_env!` only for diagnostic metadata, or put the whole
  legacy function/module behind `sealed-*`; a missing release artifact must
  not stop an owner-open build or turn into `BackendUnavailable`.
- Audit dev-dependencies and integration-test targets as well: Cargo feature
  unification must not pull `legacy-authority` into the owner-open binary just
  because a test imports it. Mark legacy tests with
  `required-features = ["legacy-plan-conformance"]` (or separate targets) and
  keep a no-legacy-dependency direct-turn smoke target. This prevents test
  plumbing from becoming a hidden runtime dependency; it is not a gate on
  running Codex.

Practical check:

~~~sh
# Primary owner-open checks (use the actual package/feature names after the split)
cargo check -p trillionniumd --no-default-features --features owner-open
cargo tree -e features -p trillionniumd --features owner-open
cargo check -p trillionnium-tool-runtime --no-default-features --features owner-open
cargo check -p trillionnium-agent-direct-tools --no-default-features --features owner-open
# Optional migration diagnostics; these may intentionally compile sealed code.
cargo check -p trillionnium-tool-runtime -p trillionnium-agent-direct-tools
rg -n 'plan-to-Authority|risk_guard|allowed_actions|authority_called' \
  apps crates --glob '*.rs'
~~~

The search is a migration aid. A hit in a clearly labelled legacy test or
custody archive is acceptable; a hit on the runtime call path is not. The
feature-tree/check commands are fast feedback for graph drift, not a formal
precondition for an owner-debug command. If the workspace has not yet exposed
an explicit `owner-open` feature, use its default feature set and record that
fact; a feature-name mismatch must not block a direct turn.
The owner-open compile must also succeed with all `TRILLINNIUM_P01_*` variables
unset and without any `include!(OUT_DIR/...)` release artifact. A failure here
is a graph/build defect to fix, not a reason to route the turn through the old
Authority. Legacy P01 checks may be run separately with an explicit sealed
feature.

### P0-02 — Make one Codex turn work on the host

Deliver:

- Provider connection with streaming model text and tool calls.
- Session/task/turn event append and resume after a provider reconnect.
- Choose one practical provider lifecycle: a long-lived Codex/app-server
  child (the same Codex runtime/session lineage, supervised by this one
  Agent Host), or one `codex exec --json` per turn with the CLI's
  `resume`/thread facility. `app-server` is a transport/lifecycle mode, not a
  second model or OS Agent. Store the provider thread/session id and last event cursor in the
  owner-open byte store; after reconnect, resume from that cursor or start a
  new turn with the recorded context. Do not pretend a fresh process is the
  same turn when the CLI cannot resume it.
- Launch the Codex process in a tracked session/process group (`setsid` or an
  equivalent supervisor primitive); the host/subreaper follows descendants and
  propagates `turn.cancel`/daemon stop to the whole group. This is the one
  required liveness guarantee for native full-access shell, not a command
  policy gate.
- shell.exec(target=host-linux) with command and argv forms plus raw
  stdout/stderr streaming. Inherited stdin, PTY resize and background jobs are
  incremental mechanics; an owner-open command/stdout turn must not wait for
  their complete implementation.
- A small codex_direct_smoke runner that invokes the same interface used by
  the provider; it is not a parallel test-only backend.
- The default host may use a minimal `DirectTurnHost` with a plain event-log
  and workspace store. Do not instantiate the legacy
  `AgentService::from_store_after_exclusive_startup(AuditStore::open(...))`
  merely to reach `run_turn`: that constructor brings D-Bus, policy/task
  registries, manifest and approval recovery into the startup path. Keep
  `AgentService`/`AuditStore` behind `legacy-authority` or replace them with
  the owner-open byte store; storage failures are reported as I/O observations.
- Expose shell/ADB either through Codex's native full-access shell (the
  canonical path when the Codex process and executor run inside the configured
  Root Linux target and the provider emits tool-call/result events into the
  same turn stream) or through the Agent Host's transparent direct-tool alias
  (MCP, stdio or an equivalent CLI bridge). The adapter is optional plumbing,
  not a prerequisite or a semantic gate. In either form every call runs in the
  selected target and its raw observation returns to the same turn. A native
  shell that would execute on a remote/provider host instead of Root Linux is
  not a direct target; select the transparent alias and report the target in
  the event. This is mechanical target plumbing, not an approval gate. In the
  integrated product turn, never create an unobserved provider-side shell, a
  divergent second implementation, or a fake tool that returns
  BackendUnavailable. A developer bootstrap may run a native call best-effort
  when the CLI exposes no event metadata, but it must mark that call
  non-replayable and must not alias-redispatch it. If both native and alias
  forms are shipped, they must share the same configured cwd, identity,
  network, target and event recording; one may be the default without making
  the other a required startup dependency.
- Review the actual installed Codex CLI help before choosing flags. Do not
  assume `ignore-user-config`, `ignore-rules` or ephemeral mode are either a
  security boundary or a streaming requirement: use an explicit owner-
  configured `CODEX_HOME` and keep/remove those flags according to the
  observed CLI semantics. Remove only settings that actually suppress the
  owner-open workspace or continuing tool loop, including a final-output-only
  schema. Keep JSON only as an event stream if useful. Native subagents may be
  disabled for the first slice or enabled by owner configuration, but they
  must use the same Codex principal and observable direct-tool event stream;
  an adapter is optional and they cannot become a separate OS Agent.
- For a native shell event, the Host assigns/records `call_id`,
  `request_sha256`, the resolved target, `event_id` and `turn_stream_id` before
  forwarding chunks. Missing metadata is filled from the configured Root Linux
  context or marked `best_effort`; it never pre-denies a command. If durable
  replay is needed, select a separately named transparent raw carrier before
  dispatch. Once a native effect has started, never invoke an alias as a
  fallback; correlate the native result only.
- When `codex --json` is used, treat the installed CLI's JSONL item/event kinds
  (`thread.*`, `turn.*`, `item.*` and future kinds) as an opaque versioned
  stream. Preserve unknown items and map native shell results to the raw
  observation envelope; do not feed them through the old MCP-only sanitizer or
  require a fixed final schema.
- Replace the old final JSON shape that requires summary/actions/refusal_reason
  with a streaming turn result whose only required terminal *payload* fields
  are `status` and `summary`; the `turn_end` envelope still carries its
  required `kind`, `event_id`, `seq` and stream-correlation fields. Tool calls
  and observations are first-class events, not a side-channel hidden from
  Codex.
- Make the provider environment explicit: CODEX_HOME, provider endpoint,
  credentials, CA settings and direct network mode are configured by the
  owner-open profile. Do not clear the environment into a loopback-only proxy
  or silently install a local-model fallback.

For the currently installed Codex CLI, verify the exact spelling with
`codex --help` and select its full-access owner-open mode (the observed 0.149.1
CLI provides `-s danger-full-access` and an equivalent
`--dangerously-bypass-approvals-and-sandbox` option). For the observed 0.149.1
binary, use one of those full-access forms; it does not expose an
`--ask-for-approval` option. A future CLI may have a differently spelled
non-interactive flag, but use it only when that installed binary's help shows
it. Never make an unsupported flag a startup prerequisite. Native
subagents may be disabled for the first smoke or enabled by
owner configuration; when enabled they remain under the same Codex principal
and observable direct-tool event stream (native or transparently adapted),
never a second OS Agent.
Do not pass both a full-access mode and the old read-only/approval flags, and
do not make a future CLI flag a hidden runtime prerequisite: discover the
supported spelling and record it in the owner configuration.

The first implementation may use `codex exec --json` as a one-turn stream or a
long-lived Codex/app-server process when that is available. In either case the
Codex executable itself is launched inside the configured Root Linux namespace
for native shell calls; host-linux and Android targets are reached through
their explicit direct-tool alias/transport. A provider-host shell is never
silently treated as Root Linux. The JSON mode is an event transport, not a
final-answer schema.
If the installed CLI calls its native tool simply `shell`, the host maps that
event to canonical `shell.exec` with `mode=command` or `mode=argv`; this is a
name/codec mapping only. `adb` invocations remain ordinary shell commands (and
may also be surfaced as the transparent `adb.exec` alias), so Codex never
depends on a fixed MCP tool-name catalog.
AiShell exposes a direct Stop/Cancel control that sends `turn.cancel` or
`tool.cancel` and renders the returned `cancelled`/`unknown_after_disconnect`
state. It is a transport signal and emergency affordance, not a consent or
approval UI.

The first visible proof is one turn that (on `host-linux` through its configured
endpoint, or on a Root Linux workspace copy—not an implicit shared
`/data/toshiba-dev` mount):

1. runs pwd, reads a source file and creates a file;
2. compiles or tests a touched component;
3. observes a failure, edits the command and continues;
4. ends with a human-readable result and an event log.

There is no per-command approval prompt. The owner can stop the process with
the emergency control if it misbehaves.

### P0-03 — Put Codex in the Android-managed Root Linux environment

Deliver:

- For the first dogfood turn, use the current userdebug Root Linux image with a
  writable /data/trillionnium/root-linux/overlay (using the explicit lower /
  upper/work/merged topology above) and ensure it has /bin/sh,
  core utilities, networking and a Codex workspace. Rebuild a fresh practical
  ARM64/lean image after the turn is useful; that rebuild is P1/release work,
  not a new P0 gate.
- Install a runnable ARM64 Codex CLI/runtime in the writable overlay (with a
  replaceable `/usr/bin/codex` link), rather than retaining the current empty
  or pre-r2 placeholder. The installed 0.149.1 distribution may be a Node/JS
  launcher plus an ARM64 optional native package, so ship a compatible ARM64
  Node/runtime and package set (or a verified equivalent), not an assumed
  standalone `/bin/codex.real` ELF. Check interpreter/libraries,
  `codex --version` and provider connectivity from inside Root Linux; these are
  direct runtime diagnostics, not a signed-artifact gate.
- Android init launch of trillionniumd and the Codex runtime without a
  semantic high-water/Authority admission hop.
- Make the init service invoke an explicit `trillionniumd --owner-open
  --run-turn` (or a separately named owner-open binary) and bind
  `@trillionnium_direct_agent_host_v1` as the default AiShell ingress. The
  no-argument/`--agent-api-uds` legacy dispatcher must never be selected by
  accident; if a separate namespace is chosen, install the documented
  mechanical bridge before enabling it.
- Do not start the existing `trillionnium_root_linux_bootstrap` oneshot,
  high-water, egress-guard, ready-gate or shell-broker services in this graph.
  Replace the bootstrap oneshot with a small idempotent mount helper if it is
  still needed; a helper may report mount/exec errors, but it must not copy a
  manifest, materialize a placeholder or set a semantic readiness property
  that the direct daemon waits for.
- Replace the current `vendor/trillionnium/prebuilt/common/etc/init/
  init.trillionnium-system_ext.rc` and
  `vendor/trillionnium/prebuilt/common/bin/trillionniumd.sh` default path,
  which currently exits on fixed digest/SELinux/mount/manifest/journal/DPKG
  checks and starts a oneshot high-water/egress chain. The owner-open branch
  performs only mount existence, executable existence, basic filesystem
  ownership and service lifecycle setup. Hash, manifest, egress and journal
  checks may be logged for diagnosis but must not prevent an owner-open service
  from starting; the old branch is sealed/legacy.
- Replace or bypass the current `trillionnium-root-linux-run.sh` and
  `trillionnium-root-linux-bootstrap.sh` owner-open path as well. They still
  restrict execution to `/usr/bin/trillionniumd`, force a 555/read-only
  rootfs and UID/GID 5901, validate a legacy AgentManifest/archive and
  materialize an empty ADB placeholder. The owner-open runner must execute the
  configured Codex/command entrypoint with the owner-selected identity,
  writable overlay, normal `/bin/sh` and real `adb`; only mount, executable and
  process-liveness mechanics remain mandatory.
- Do not copy the runner's silent `mount ... || true` behavior into the new
  branch. Mounting `/proc`, `/sys`, `/dev`/`devpts` and the writable overlay
  must either succeed or return an explicit degraded mechanical status. The
  owner-open runner also removes the current `/usr/bin/trillionniumd`-only
  command check, `NO_ROOTFS_MUTATION=1` setting and fixed Codex home; Codex's
  selected command and workspace are passed through unchanged.
- Audit the Soong module chain around `Android.bp`'s `trillionniumd-wrapper` /
  `trillionniumd` pair (currently selecting
  `bin/trillionniumd-p01-userdebug.sh` for userdebug), the
  `trillionnium-agentd-payload-p01-userdebug-verified`/payload modules, the
  `trillionnium-agent-adb-verified` pinned typed ELF and the debug init
  bind. The owner-open module must exec the configured Rust Agent Host/Codex
  and real `adb` directly or through a transparent launcher; no required
  wrapper may reintroduce P01 receipt, fixed digest, high-water or typed-ADB
  admission.
- The owner-open userdebug graph must not select
  `bin/trillionniumd-p01-userdebug.sh` or source `trillionniumd-p01-core`:
  that wrapper currently enforces runtime.env/manifest/key-order/digest,
  authority/journal/ACK and P01 profile checks before exec. Switch the C++
  launcher, shell wrapper and `Android.bp` selection together to the direct
  owner-open entrypoint; leave the P01 chain as an explicit sealed/legacy
  variant.
- Update the AiShell client path as well as the daemon: the current
  `BuiltInAgentClient`/Activity `SystemUserBoundary.requireSystemUserUid()` and
  workflow stores reject secondary/work-profile users before a request reaches
  UDS. In owner-open, basic app/socket permissions remain platform mechanics,
  while user/profile selection is Codex target data; remove the user-0-only
  check from the direct `run_turn` client or keep it only in a sealed/legacy
  profile. A deployment may choose user 0 for the first smoke, but that is a
  stated platform scope, not an Agent approval gate.
- Configurable mount, PID, user and cgroup setup that gives owner-open Codex
  broad Root Linux control while preserving Android host liveness. The
  configured execution identity may be root and may retain the capabilities
  needed by the owner (including the capabilities required by the selected
  mount/network profile); do not inherit the old fixed UID/GID, capability
  list, `no_new_privs`, seccomp or capability-drop preset from the sealed
  worker. If SELinux denies a requested capability, surface that platform
  error and fix the owner-open domain/policy rather than adding a semantic
  command gate.
- Define one owner-open SELinux domain/transition whose platform permissions
  cover the configured Codex/Root Linux profile and labels the writable
  overlay, `/usr/local/bin/adb`, provider/ADB networking, PTY/process-group
  signals, `/dev/bus/usb`/USB-FFS or the configured host TCP socket, DNS/epoll,
  writable `~/.android` key/server state and any mount operations the selected
  profile needs. Root Linux UID/
  GID may vary inside that domain. Prefer reusing the existing
  `trillionnium_rootlinux` domain (or a single
  domain derived from it) for Codex and the direct adapter rather than keeping
  a separate `shell_exec_worker` transition. The current
  `trillionnium_codex_agent`/`trillionnium_rootlinux` rules are tied to the
  measured 5901/5903 worker and may emit an AVC even when the Unix UID is root.
  Fix that platform plumbing rather than masking it with a semantic denial;
  Android-host root/remount capability is still reported by the selected
  target's real ADB/SELinux result.
- shell.exec(target=rootlinux) that can run scripts, install a package, edit
  files, start/stop a service and inspect /proc.
- Put /bin/sh, coreutils, package/build tools and adb in the actual Root Linux
  image and PATH. A placeholder binary or a debug-only bind mount is not a
  direct-tool implementation.
- Give the Root Linux process direct, owner-configured network access for both
  provider egress and ADB transport. A loopback-only proxy or an egress guard
  that is required for startup is not the owner-open design. Provider outage
  and TLS/429 errors are returned to Codex as observations.
- When the Root Linux network namespace is isolated, configure a real bridge,
  route or inherited transport to the host ADB server; `127.0.0.1` is not a
  magic cross-namespace address. Record the chosen topology and verify it with
  `ip route`, `ss -ltn` and a bounded connectivity probe from inside Root
  Linux.

Device/lab proof:

~~~text
Codex turn:
  shell.exec({"target_id":"rootlinux","mode":"command","command":"id; uname -a; printf ... > /workspace/probe"})
  shell.exec({"target_id":"rootlinux","mode":"command","command":"if command -v apt-get >/dev/null; then apt-get --version; fi; ./build-or-test.sh"})
  shell.exec({"target_id":"rootlinux","mode":"command","command":"cat /workspace/probe"})
~~~

The object form above is illustrative ABI syntax: `target_id` is optional for
native Root Linux and is never a hidden serial/privilege injection. An
implementation may use the equivalent `argv` form or the Codex CLI's native
shell event, provided the exact command bytes and target observation are
preserved.

The proof is complete when the result comes back to the same turn and init
restarts the daemon after an intentional crash. A source receipt or a
listening socket without this turn is not completion.

The concrete restart probe is deliberately bounded feedback (not a formal
release gate). It must prove a new process and a usable stream, rather than
passing because two property reads happened to say “running”:

~~~sh
DEVICE_SERIAL="${ANDROID_SERIAL:-ZY32JLVHGN}"
OWNER_DAEMON="${TRILLINNIUM_DAEMON_PROCESS:-trillionniumd}"
old_pids="$(adb -s "$DEVICE_SERIAL" shell pidof "$OWNER_DAEMON" | tr -d '\r')"
old_pid="$(printf '%s\n' "$old_pids" | awk '{print $1}')"
case "$old_pid" in ''|*[!0-9]*) echo "no numeric $OWNER_DAEMON pid: $old_pids" >&2; exit 1;; esac
adb -s "$DEVICE_SERIAL" shell "kill -TERM $old_pid"
gone=0
for _ in $(seq 1 50); do
  live_pids="$(adb -s "$DEVICE_SERIAL" shell pidof "$OWNER_DAEMON" 2>/dev/null | tr -d '\r')"
  case " $live_pids " in *" $old_pid "*) ;; *) gone=1; break;; esac
  sleep 0.2
done
test "$gone" = 1
connected=0
for _ in $(seq 1 60); do
  if adb -s "$DEVICE_SERIAL" get-state 2>/dev/null | tr -d '\r' | grep -qx device; then
    connected=1
    break
  fi
  sleep 0.5
done
test "$connected" = 1
new_pids="$(adb -s "$DEVICE_SERIAL" shell pidof "$OWNER_DAEMON" | tr -d '\r')"
new_pid="$(printf '%s\n' "$new_pids" | awk '{print $1}')"
case "$new_pid" in ''|*[!0-9]*) echo "no numeric restarted $OWNER_DAEMON pid: $new_pids" >&2; exit 1;; esac
test "$new_pid" != "$old_pid"
adb -s "$DEVICE_SERIAL" shell id
# The final assertion is made in the Codex stream, not by this host script:
# send run_turn and observe a new event/boot id plus a shell result.
~~~

If the Host is phone-local, a phone reboot cannot satisfy a same-process
  continuation assertion: use the `interrupted -> resumable` new-turn rule above.

### P0-04 — Implement direct ADB before adding more typed APIs

Deliver:

- A real adb.exec transport in the Agent Host/Root Linux path.
- USB, adb connect and adb reverse support. Keep the owner-authorised
  ZY32JLVHGN lane as the first target.
- Perform the one-time owner setup for USB debugging (pre-provision the
  owner ADB public key or complete Android's RSA authorization dialog). If
  `adb devices` reports `unauthorized`, preserve that exact raw transport
  state and let Codex/owner finish enrollment; do not turn it into a typed
  permission denial or claim that ADB is ready. Likewise, `offline` and
  `no permissions` are observations for the Agent to diagnose.
- Raw command and stdout/stderr handling. Preserve serial, transport state,
  exit code and stderr in the observation. A first native Codex turn may send
  binary `exec-out`/pull data to a target-readable file and return its path;
  base64/chunk framing for inline binary is an incremental P1 transport feature,
  not a reason to delay arbitrary ADB commands.
- ADB key/server configuration visible to the owner-open runtime, with an
  explicit `server_mode` (inherited host server, owner-selected local server,
  or explicit remote endpoint). In reverse topology do not let `adb` silently
  auto-start a second local server; surface server-start/connect failure to
  Codex.
- No action parser that rejects root, remount, install, reboot, forward,
  reverse or future commands.
- Remove the current inert transport constructor and the json-stdin-only
  placeholder path. The first implementation may exec the owner-configured
  adb binary/server from Root Linux; a native libadb connector is optional.
- Do not wrap the owner-open call in the old `AdbRequest` tagged enum/
  `deny_unknown_fields`, `validate_request` eng-token/build-type checks,
  `serial_args`/path validators, `command()` `env_clear`, `.apk` extension
  check, fixed `DEFAULT_TIMEOUT`/`MAX_OUTPUT_BYTES` or
  `execute_production` `BackendUnavailable`. Those symbols are legacy/sealed;
  the raw argv process returns the actual ADB result and mechanical error.
- Make adb.exec (raw argv), shell.exec (argv) and shell.command (command
  string) visible in the Codex tool catalog. Do not require a typed
  android.adb.* operation schema for a command to be usable.
- The raw request shape is optional target_id plus argv, stdin, environment,
  timeout and PTY/stream options. argv excludes the program name and is never
  filtered for subcommand, host, port or privilege tier. A typed AndroidAdbTier,
  user_confirmation_required or key-rotation field is not part of this
  owner-open request.
- For P0, install an owner-provided ARM64 adb client or transparent shim at
  /usr/local/bin/adb in the writable Root Linux overlay. Do not copy the
  host-only x86_64 AOSP adb and do not require the large immutable-rootfs
  packager to change before the first turn. Promote the same binary into the
  packaged rootfs in P1. The direct smoke may run `file`, `readelf`/`ldd` and
  `adb version` from inside Root Linux to catch an incompatible interpreter or
  library; these are compatibility diagnostics, not a release receipt gate.
- Replace the current `vendor/trillionnium/prebuilt/common/linux/
  agent-direct-tools/trillionnium-agent-adb` typed Rust helper and its pinned
  `Android.bp` genrule/`PRODUCT_PACKAGES_DEBUG` bind. It is not the platform
  `adb` client. The owner-open path needs a real ARM64 platform-tools client or
  transparent host-server shim in the normal Root Linux PATH; the old helper
  may remain only as a legacy compatibility binary.
- Do not assume adding the AOSP `adb` module to Android `PRODUCT_PACKAGES`
  solves this: the usual AOSP client is a `cc_binary_host`, while the device
  side builds `adbd`. Supply/cross-build an ARM64 userspace `adb`, use a
  verified compatible package, or use a transparent host-server/ADB relay;
  `adbd` alone is not a Root Linux client.
- Treat `adb reboot` as an expected transport interruption: record
  `unknown_after_disconnect`, then restore transport and let Codex probe the
  target before deciding what to do. With host-server plus `adb reverse`, the
  reboot also kills phone Root Linux and removes the reverse tunnel, so a
  small mechanical host-side reconnect helper (or a Codex call on the
  independent `host-linux` target) must rerun
  `adb track-devices`/udev detection followed by
  `adb -s SERIAL reverse tcp:5037 tcp:5037` after USB reappearance. Only then
  does Root Linux run `adb wait-for-device` and, in P1, `operation.inspect`.
  A local adbd TCP mode avoids this dependency. If no independent reconnect
  path exists, return `transport_unavailable` and wait for the owner; never
  claim that the dead phone process can rebuild its own tunnel or blindly
  repeat the reboot.

The minimum live turn performs three direct-tool calls (one Root Linux
`shell.exec` and two `adb.exec` calls; only the latter two touch the device):

~~~text
command -v adb; adb version
adb devices -l
adb -s ZY32JLVHGN shell id
~~~

`ZY32JLVHGN` in these examples is only the currently observed lab default.
The runner uses an explicitly configured `ANDROID_SERIAL` or discovery result;
neither the shell wrapper nor `adb.exec` may inject or rewrite a serial.

The remaining commands below are a recommended diagnostic recipe, not a
prerequisite or a release gate:

~~~text
adb -s ZY32JLVHGN shell getprop ro.build.version.incremental
adb -s ZY32JLVHGN shell settings get system screen_brightness
adb -s ZY32JLVHGN push <small-file> /data/local/tmp/
adb -s ZY32JLVHGN shell cat /data/local/tmp/<small-file>
adb -s ZY32JLVHGN pull /data/local/tmp/<small-file> <workspace>
adb -s ZY32JLVHGN logcat -d -t 100
~~~

`which adb`, `adb devices -l` and `adb shell id` must be issued by the same
Codex turn from inside the Root Linux Agent environment, not only on the
development host. If Root Linux uses the host ADB server, the
turn must show the configured ADB_SERVER_SOCKET/reverse transport and the same
serial in the returned observation. This proves the actual topology rather
than a host-side operator probe.

In the same or a subsequent Codex turn, optionally exercise an owner-authorised
mutation, such as settings put, APK install or reboot, and verify it with a
subsequent direct ADB observation. This is diagnostic ordering only: owner-open
does not require `adb devices`/`id` success before it may issue arbitrary raw
ADB argv, including install or reboot. A failed command is visible as a failed
command, not converted into an OS policy denial. Cancelling the local ADB
client does not imply that a remote shell/install/reboot stopped; distinguish
`cancelled` (client signal delivered) from `unknown_after_disconnect` (remote
state cannot be determined) and let Codex probe or undo it.

### P0-05 — Add Android System API and Accessibility conveniences

Deliver:

- Thin typed wrappers that return structured observations but share the same
  event/transport path as shell and ADB.
- Accessibility snapshot/action calls with a raw fallback through ADB.
- On owner-open, these wrappers are codec/transport conveniences only: they
  pass the selected target, Android user/profile, arguments and raw platform
  errors back to Codex. The existing `system_api.rs`, `accessibility.rs` and
  `risk_guard.rs` paths that impose a fixed user, `deny_unknown_fields`,
  MAX_* limits, journal/capability preflight or `ProductRiskGuard` admission
  are `legacy-authority`/`sealed-*` and must not be imported by the default
  path. `adb_transport_boundary`/`AndroidAdbTier` has the same status for raw
  `adb.exec`.
- No requirement that a typed action exist before Codex can operate the
  underlying Android service.

Acceptance is a user task, not a schema count: Codex changes a setting,
launches an app, reads the resulting UI/state and explains the result. If a
typed wrapper is incomplete, the Agent can use adb shell, cmd, settings,
uiautomator or a script immediately.

### P1-01 — Unify targets and cross-target turns

Deliver:

- Target discovery and a small target record containing target_id, endpoint,
  transport, observed identity, capabilities and last-seen time.
- Sequential and parallel tool calls in one turn with explicit target labels.
- Host-to-phone workflows: build on host, adb push/install, run in Root Linux
  or Android, collect logcat and patch source based on the result.
- Reconnect behavior when USB or TCP changes without changing target_id.

Acceptance scenario:

~~~text
host shell: build an APK or helper
adb:        push/install it on ZY32JLVHGN
  adb shell:  run the helper and collect output
host shell: inspect the output and modify the source
Codex:      continue in the same live turn (or create an explicit resumable
           new turn after a host/phone restart)
~~~

No route planner is introduced; Codex emits the sequence.

### P1-02 — Make persistence useful for Agent recovery

Deliver:

- Append-only event log and output spool with atomic publication.
- Reopen and enumerate incomplete calls after trillionniumd or Codex restart.
- Explicit `unknown_after_disconnect` and transport sequence numbers.
- A Codex-visible operation.inspect/event.read primitive so the Agent can
  decide whether to probe, retry, undo or ask.
- Tests for daemon kill, provider disconnect, USB unplug, reboot and ENOSPC.

Do not add a mandatory exactly-once or Android ACK ceremony to every command.
Use backend-specific idempotence where it exists; otherwise preserve the
uncertain state and let Codex reason from observations.

Prefer a small append/fsync/reopen/spool primitive for this path. Existing
journal/ACK/high-water code may be mined for byte/storage routines, but its
issuer, risk, lease and admission vocabulary must stay out of the owner-open
call graph. A journal record is evidence and a recovery input, not permission
to issue the command.

### P1-03 — Enable self-development and iteration

Deliver:

- Codex can read and edit the active source tree, run targeted tests, build
  Root Linux/Android artifacts and restart its own userland. The active source
  lives on the configured host endpoint or a shared mount; the phone Root
  Linux target must not assume that /data/toshiba-dev is locally mounted.
- Codex-owned policy, target and memory files have versioned schemas and a
  simple migration command.
- Provide a snapshot/restore command that Codex may call before an image or
  rootfs change. The substrate does not require that call and must not reject
  an owner-open change merely because no snapshot exists.
- The Agent can produce a support bundle containing turn/event log, target
  identity, build ID and raw errors without a separate evidence service.
- Add duplex PTY/job mechanics (`shell.job.write`, resize, close-stdin and
  kill) and target-scoped spool reads where the native CLI does not already
  provide them. These extend the direct surface; they do not gate the first
  command/stdout dogfood turn.

The iteration loop is:

~~~text
observe -> edit -> build -> install/update -> reboot if needed
        -> inspect -> keep or restore
~~~

### P1-04 — Dogfood OTA and physical recovery

Deliver:

- OTA/target-files generation from the active Android tree.
- Codex invokes install, waits for the target, re-establishes ADB and validates
  the new build. For a host-server/reverse topology, a mechanical host-side
  reconnect helper (or an independent `host-linux` call) watches USB/device
  return and recreates the reverse tunnel before phone Root Linux resumes; the
  phone process is not expected to repair a tunnel that reboot killed. The
  owner-authorised device lane may mutate. The normal path
  is init-managed, while owner-debug shell/ADB may start or restart a service;
  the event log must state what actually happened and must never fabricate a
  successful result.
- A/B rollback or known-good restore through the out-of-band recovery
  primitive.
- Fault exercises: process crash, provider timeout, USB loss, reboot during a
  call, full output spool and low free space.

The dogfood success criterion is “Codex can get the device back and explain
what happened”, not a documentary receipt claiming exactly-once semantics.

### P1-05 — Iterate Codex behavior without adding a policy engine

Keep a small owner-owned golden-task corpus and let Codex run it through the
same direct path: host build → Root Linux edit → raw ADB push/install → Android
inspection, a failed command followed by correction, reboot/reconnect, unknown
tool labels, large output/spool, and an intentional transport loss. Record the
raw prompt, tool bytes, observations and final explanation. Track tool-choice
accuracy, unnecessary destructive calls, recovery success and turn latency as
diagnostics for prompt/tool/configuration iteration. These metrics guide Codex
updates and may be improved by Codex itself; they are not OS admission gates or
claims of safety.

### P2-01 — Optional sealed/public profile

Only after owner-open dogfood is productive, consider signed production images,
AVB/rollback indexes, multi-user isolation, narrower credentials, mandatory
consent for a public distribution, hardware-backed key rotation and a sealed
tool profile. These are release properties on the same substrate, never a
second planner or a blocker for owner-open development.

### P2-02 — Windows research (deferred)

Keep WindowsCompat out of Android packages and init. If revisited, implement it
as another target for the same Codex direct-tool model, not as a second Agent,
Wine command broker or hidden local model.

## 7. Practical validation policy

Validation is proportional to the thing changed. A check is useful when it
finds a regression; it is not useful merely because it creates a receipt.

| Change | Required feedback | Not required before continuing |
| --- | --- | --- |
| Rust/tool logic | Formatter, touched package tests and one local direct-tool call. | Full workspace, Android and archive suites on every edit. |
| Shell/ADB transport | Targeted transport tests plus one live command on the owner-authorised device or a reproducible fixture. | Signed BOM, hardware attestation or approval ceremony. |
| Android product/init/SELinux | Relevant Soong target, install/reboot smoke and a Codex turn using the changed path. | Release-signing package or public-release review. |
| Rootfs/OTA | Build, install, reconnect and one representative cross-target task. | Exact historical hashes or a clean worktree for dogfood. |
| Recovery/storage | Fault injection and inspection of the resulting event log. | Exactly-once claim where the backend cannot prove it. |
| Public release | Full source/BOM/signing/AVB/rollback/multi-user/fault review. | — |

Fast feedback commands (from the control-plane tree):

~~~sh
cargo fmt --all -- --check
cargo test -p trillionnium-agent-direct-tools
cargo test -p trillionnium-shell-exec
cargo test -p trillionnium-tool-runtime
CARGO_BUILD_JOBS=2 cargo check --workspace --locked
~~~

When an Android input changes, add the smallest relevant Soong/OTA and live
smoke command. When only documentation changes, do not rebuild or flash an OTA
just to satisfy a form.

### 7.1 Explicitly rejected development gates

The following must not block an owner-open turn:

- a clean Git worktree or a new commit for every command;
- a generated SHA/BOM/manifest before local execution;
- a model-facing risk class, fixed action allowlist or mandatory approval UI;
- a second Authority, dispatcher or route planner;
- hardware KeyMint/rollback proof before userdebug dogfood;
- a full historical test suite when a targeted test answers the question;
- a PASS receipt produced by a script that did not run the physical effect;
- silently replacing direct ADB/shell with a typed-only mock.

Hashes, BOMs and formal release evidence remain valuable when publishing an
image. They document what was shipped; they do not decide what Codex may do in
the development environment.

### 7.2 Failure vocabulary

Every layer uses a small, honest vocabulary:

~~~text
ok
exited_nonzero
signalled
timed_out
cancelled
transport_unavailable
target_rejected
resource_exhausted
invalid_frame
spawn_failed
provider_unavailable
unknown_after_disconnect
configuration_error
io_error
provider_stream_closed
reconnect_required
resume_unavailable
~~~

target_rejected means the target itself rejected the command. It must not be
renamed to operation_denied by an intermediate policy service. Codex decides
the next action from the raw observation.
`invalid_frame`, `spawn_failed` and `provider_unavailable` are likewise
mechanical transport/provider outcomes, not semantic denials. `status`,
`dispatch_state` and `effect_state` are orthogonal: a local timeout/cancel may
leave `dispatch_state=started_no_response` and
`effect_state=possibly_applied`, while a target rejection is
`dispatch_state=result_recorded` plus `effect_state=rejected`. A configuration,
provider or event-store error carries `error: {stage: ...}` (canonical field
`error.stage`); an unavailable event store never changes the direct call into
`io_error` or prevents dispatch.

### 7.3 Fault matrix (feedback, not a dogfood gate)

| Injected condition | Required raw observation | Effect/retry rule |
| --- | --- | --- |
| Event store unavailable or read-only | `event_log_status=unavailable`, call still runs | Codex may continue; no automatic retry caused by logging failure. |
| Spool fills during output | partial chunks + `resource_exhausted`, `effect_state` reported | No silent truncation or automatic duplicate; Codex may inspect/clean and issue a new call. |
| Provider EOF/timeout | `provider_stream_closed` or `provider_unavailable` with `error.stage=provider` | `turn_end.status=interrupted`; resume only with an explicit cursor/new turn. |
| Host daemon kill | `turn_end.status=interrupted` plus call `reconnect_required`/`unknown_after_disconnect`; PID/boot id changes | Reconnect the stream; never spawn a duplicate for an unproven call. |
| USB loss or `adb offline/unauthorized` | exact ADB transport state, `transport_unavailable` or `target_rejected` | Codex/owner diagnoses enrollment/reconnect; no typed permission denial. |
| `adb reboot` | `unknown_after_disconnect` when remote effect is indeterminate | Probe after reconnect; use a new call id. RootLinux host requires a new resumable turn. |
| Malformed frame/config | `invalid_frame` or `configuration_error` with stage | Keep listener/defaults alive where possible; do not hide raw shell/ADB. |

These checks validate honesty and recovery mechanics. They are not release
receipts and do not authorize a second policy engine.

## 8. Current state and immediate queue (2026-08-27)

The canonical external estate is mounted at /data/toshiba-dev. The latest
owner-authorised dogfood OTA observation on ZY32JLVHGN booted successfully on
slot _a with incremental 1787707748, SELinux Enforcing, the Accessibility
service bound and USB reverse networking available. The Agent/System
API/replay sockets observed in that image were legacy-image services, not proof
of the owner-open direct socket or a live `run_turn`; this observation proves
only the Android build/transfer/install/startup substrate.

The current source still has an inert ADB adapter, a seven-command shell
scaffold and compile-time BackendUnavailable/authority holds. No live Codex
turn has yet executed a physical shell or ADB effect through the installed
Agent Host. Under this revision those are implementation gaps, not reasons to
retain a second policy OS. The next work is therefore:

1. W0: remove the old broker/issuer/P01 nodes from the default Cargo, Soong,
   init and SELinux graph; the current `cargo metadata` and target-files
   observations are known failures of this step;
2. W1/W2: make `trillionniumd` launch one truthful full-access Codex turn in
   Root Linux with a writable overlay and restartable lifecycle;
3. W3: connect the real ARM64/transparent ADB client and run the first
   same-turn device smoke;
4. W4: add typed System API/Accessibility conveniences only after raw tools
   work (they remain optional fallbacks);
5. W5: add event-log recovery, spool inspection and Codex-driven OTA/reboot
   iteration; keep all release-only evidence separate.

The device is a userdebug/unlocked dogfood target. Do not call it a public
release, and do not fabricate physical evidence. A failed or missing
mechanical primitive should be reported plainly and fixed in the substrate.

### 8.1 Documentation closeout and execution handoff (2026-08-27)

This revision is closed as a planning/contract package. “Closed” here means
that the direction, vocabulary, file-level queue and observable acceptance
criteria are fixed; it does not mean that the owner-open runtime has already
been built or that a device effect has been observed.

| Surface | Current state | What the state permits |
| --- | --- | --- |
| Plan + owner-open contract | `2026-08-27-r3`, mutually aligned and machine-readable | Use this plan and `codex-sovereign-direct-tools-v1.json` as the only active semantic specification. |
| Developer bootstrap | **OPEN NOW** | Start Codex in the configured Root Linux/host shell and issue ordinary shell/ADB commands as soon as `/bin/sh`, the CLI and a real/transparent `adb` path are present. No generated ABI, BOM, OTA or approval screen is needed. |
| Cargo/Soong/init/SELinux graph | **IMPLEMENTATION NEXT** | Perform W0–W2 graph edits. The existing legacy members, package edges and property choreography are known non-convergence observations, not a denial of the bootstrap lane. |
| ARM64 ADB transport | **IMPLEMENTATION NEXT** | Perform W3 with a real userspace `adb` or a byte-transparent relay. The typed `trillionnium-agent-adb` helper and host-only AOSP `adb` do not satisfy this row. |
| Integrated same-turn device effect | **NOT CLAIMED** | Claim it only after one Codex turn returns raw shell and ADB observations from the Android-managed Host/Root Linux path. Host-only probes and legacy sockets do not count. |
| Recovery/event spool | **P1 NEXT** | Add inspectable records and conservative `unknown_after_disconnect`; do not introduce an exactly-once or ACK ceremony as a prerequisite for the first direct call. |
| Signed/public release | **DEFERRED** | Keep AVB, KeyMint, rollback, multi-user and formal power-loss evidence in W6/P2. None can block owner-open dogfood. |

The current audit has deliberately recorded `owner_open_graph_converged=false`:
the selected Cargo defaults still name legacy broker/stdio roots, the AOSP
common product still expands the old Authority/lease/P01/shell nodes, and the
framework/SDK closure still has live `org.trillionnium.platform(.internal)`
edges. These facts select the next implementation work; they do not change
the direct-tool contract and must not be translated into `operation_denied`,
`mutation_unavailable` or a provider startup gate.

The next implementation handoff is therefore one linear, inspectable bundle:

1. **W0 graph split:** introduce the explicit owner-open Cargo/Soong profile
   before product-variable freeze, isolate legacy modules/features, and remove
   old init/policy nodes from the selected graph. Re-run the negative-set audit
   in §5.2; a failure blocks only the integrated-path claim.
2. **W1/W2 direct turn:** add the isolated `run_turn` listener/provider,
   owner-configured full-access launch, writable Root Linux overlay and a
   restartable Host. Exercise the bootstrap smoke in §6 before waiting for a
   generated codec or release artifact.
3. **W3 raw ADB:** place a verified ARM64 client/server or transparent relay
   in the Root Linux PATH, preserve exact argv and bytes, and run the
   same-turn `adb devices -l` / `adb -s <serial> shell id` probe. Preserve
   `unauthorized`, `offline`, root/remount/install/reboot errors as raw
   observations.
4. **W4/W5 follow-on:** add optional System API/Accessibility codecs, durable
   event/spool inspection and reboot/USB recovery only after the raw path is
   useful. They extend the direct surface; they do not gate it.

For every step, record the selected profile, source revision and actual
observation in the status ledger. A source grep, generated receipt, stale
target-files tree or manual daemon start may document a lead, but cannot be
promoted to a live capability claim. If an implementation choice changes the
raw command/observation semantics, update this plan and the machine contract
in the same change and advance the revision; otherwise keep this r3 lock
stable.

## 9. Definition of done

### Minimum useful owner-open dogfood

The first useful milestone is observable in one Codex-controlled system when
these direct capabilities work; no durability receipt or release artifact is
required before using them:

1. Codex starts without a second Agent or plan translator.
2. One turn can use host shell, Root Linux shell and raw ADB.
3. Shell command strings, argv and stdout/stderr streaming work; stdin, PTY,
   duplex jobs and cancellation are added incrementally without changing the
   raw command contract.
4. Codex can issue arbitrary ADB argv for inspect, push/pull, shell, install and
   reboot; each capability is marked observed only when raw ADB success/failure
   and reconnect behavior are actually seen on the target.
5. Observations return to the same live turn while its stream/process survives,
   and a restart instead yields `turn_end.status=interrupted` plus an explicit
   resumable/new turn with its cursor; Codex can continue after failure.

### Owner-open iteration hardening (P1)

The dogfood loop becomes resilient when a daemon/provider/USB restart leaves an
inspectable event log and an honest unknown state when the effect cannot be
determined, and Codex can edit/build/update its own userland and recover the
phone through the emergency path. These are the next implementation outcomes,
not prerequisites that gate the first direct shell/ADB turn.

### Public release (later, optional)

Only a separately named release profile may claim signed production images,
hardware rollback, multi-user isolation, formal power-loss evidence or a
sealed safety policy. Those claims need corresponding physical tests. They do
not redefine the owner-open product contract.

## 10. Change control and source custody

- The active implementation graph is this Rust tree, the canonical AOSP tree
  and their declared manifest inputs. The external disk is the only
  development estate; do not fall back to deleted internal Android roots.
- Generated target/, out/, logs, OTA packages and caches are outputs. Keep
  them when useful, but never treat an output as source authority.
- Retired OpenClaw, Hepta, Mobian, desktop and Windows material is recoverable
  custody, not an input and not a second plan.
- A dirty tree is acceptable for owner-open dogfood. Before a public artifact,
  record the exact tree diff, source BOM, build ID, target serial and image
  hashes in one release record.
- Use bounded, recoverable operations for cleanup. Never use a broad recursive
  delete, reset another contributor's work or remove an untracked file merely
  to make a gate green.

This document remains the single sequencing authority. If implementation
reveals a missing primitive, add that primitive here and to the owner-open
contract; do not create a parallel roadmap or reintroduce a semantic OS
authority.
