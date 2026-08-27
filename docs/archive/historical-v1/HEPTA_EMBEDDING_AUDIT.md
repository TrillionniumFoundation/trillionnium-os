# Hepta Embedding Audit and Runtime Adapter Boundary

> **SUPERSEDED (2026-07-13):** this document records the earlier Hepta-first
> design investigation. Hepta is not the canonical Trillionnium OS runtime.
> If integrated, it must implement the same provider-neutral Agent API as Codex
> and OpenClaw. See `docs/CURRENT_STATE.md` for the active architecture.

## Boundary decision

Historical decision (no longer active): Hepta was treated as the canonical
agent runtime and Trillionnium OS as the OS substrate around it:
D-Bus/session integration, Command Center, approvals, audit persistence,
policy hooks, Phosh/mobile packaging, and future Waydroid/platform bridging.
The first desktop and mobile targets are now explicit as `platform/debian` +
`profile/desktop-gnome` and `platform/mobian` + `profile/mobile-phosh`, but
those slices are only passive readiness evidence and must not change runtime
execution, sidecar state, audit persistence, D-Bus registration, package/base
state, or phone flashing/ROM paths. Trillionnium OS must not grow a
second competing runtime.

The current `trillionnium-tool-runtime` crate is therefore an OS-side adapter/shim. Its
M2 built-ins (`system.status`, `demo.approval_echo`) are only a fallback/test
harness for the D-Bus + policy + approval + audit loop until direct native Hepta
embedding is wired.

Canonical source inspected read-only:

```text
/home/qian-qi/Dropbox/hepta/Hepta-source-20260511-135047-db4e203f66e6/
```

No files under that Dropbox source were edited.

## Platform profile boundary

`trillionnium-command-center doctor --profile desktop`, text `status`, and the
Command Center UI expose Debian/GNOME readiness evidence: platform/profile files,
Debian dependency list, GNOME UI density/adaptive metadata, session hints,
freedesktop commands, and xdg-desktop-portal user-service visibility.

`trillionnium-command-center doctor --profile mobile`, text `status`, and the
Command Center UI expose Mobian/Phosh readiness evidence: platform/profile files,
Mobian dependency list, Phosh UI density/adaptive metadata, session hints,
ModemManager, NetworkManager, and power-service visibility. `doctor --profile
all` runs both readiness profiles as one passive matrix. These probes are
read-only (`PATH`, environment, metadata files, `systemctl is-active`, and
`systemctl --user is-active` only). They do not install packages, migrate the
host base, start/stop services, write audit rows, emit D-Bus signals, invoke
Hepta tools, register native tools, repartition, flash, or unlock devices.

## Source inventory

The audited Hepta workspace members are:

- `apps/hepta`
- `crates/hepta-core`
- `crates/hepta-runtime`
- `crates/hepta-memory`
- `crates/hepta-intelligence`
- `crates/hepta-gateway`
- `crates/hepta-cli`
- `crates/hepta-plugins`

Important public contracts found in `hepta-core`:

- `tools.rs`
  - `RiskTier`, `ExecutionProfile`, `FilesystemScope`, `WritePathScope`
  - `ToolExecutionMetadata`, `ToolSchema`, `ToolContext`
  - `ToolCallRequest { name, input_json }`
  - `ToolResult { content, structured_json }`
  - `trait Tool { name, risk_tier, execution_metadata, schema, async invoke(...) }`
- `policy.rs`
  - `ApprovalRequirement`, `PolicyDecision`, `PolicyRule`
  - `PolicyEvaluationContext`
  - `trait PolicyEngine::evaluate_tool(...)`
- `runtime_types.rs`
  - `AgentId`, `SessionId`, `TaskId`, `CorrelationId`
  - `EventKind`, `Event`
- `memory.rs`
  - session storage boundary: `SessionStore`, `SessionRecord`
  - transcript storage boundary: `TranscriptStore`, `TranscriptEntry`,
    `TranscriptQuery`, `TranscriptQueryReport`
  - memory storage boundary: `MemoryStore`, `MemoryReportStore`,
    `MemoryRecord`, `MemoryQuery`, `MemoryQueryReport`
  - recall/snapshot/report helpers for context retrieval, transcript provenance,
    and additive-only restore previews

Important public runtime APIs found in `hepta-runtime`:

- `RuntimeKernel::new()` constructs the runtime kernel.
- Discovery / contracts:
  - `tool_names()`
  - `tool_descriptors()`
  - `provider_names()` / `provider_catalog()`
  - `validate_tool_input(tool_name, input_json)`
  - `validate_tool_output(tool_name, output_json)`
- Policy / approvals:
  - `policy_report().await`
  - `add_policy_rule(...)`, `remove_policy_rule(...)`, `reset_policy_rules()`
  - `approval_snapshot()` / `approval_snapshot_for_session(...)`
  - `approve_tool(...)` / `approve_tool_in_session(...)`
- Sessions / snapshots:
  - `active_session_id()`, `switch_session(...)`, session fork/merge/diff/export/import
  - `save_snapshot(...)`, `load_snapshot(...)`
- Events / telemetry:
  - `boot_event()`
  - `events(limit)`
  - `query_events(limit, kind, session_id)`
  - `query_events_report(...)`
  - internally emitted `EventKind`s cover session/model changes, tool invokes,
    approvals, policy updates, memory writes, task/agent lifecycle, write locks,
    and rollback flows
- Higher-level execution:
  - `run_demo_turn(input).await`
  - `run_demo_turn_in_session(session_id, input).await`
- Worker/supervisor APIs:
  - `spawn_worker_task*`, `run_worker_task`, `run_ready_worker_tasks`,
    `operator_console`, `worker_task_*` inspection/promotion/rollback APIs

Important `hepta-runtime` internal APIs:

- `ToolRegistry` is private to `hepta-runtime/src/lib.rs`.
- `ToolRegistry::invoke(...)` is private.
- `RuntimeKernel::invoke_tool_with_validation(...)` is private.
- Built-in Hepta tools include `echo`, `read_file`, `write_file`, `list_dir`,
  `search_text`, `disk_junk_audit`, `json_get`, skill proposal/scan/apply-plan,
  tool-manifest validation, and tool stub generation.

Important `hepta-cli` APIs:

- `CliApp` wraps `RuntimeKernel::new()`.
- `CliApp::tool_descriptors()` forwards runtime tool descriptors.
- `CliApp::events(...)` and `query_events(...)` forward runtime event queries.
- `CliApp::execute_command(raw).await` is a broad CLI command surface.
- Some channel adapters call `runtime.run_demo_turn_in_session(...)`.

## Embedding finding

The audited Hepta snapshot already has rich runtime, policy, event, memory,
worker, and CLI command surfaces. It does **not** currently expose a small,
stable public `invoke_tool(name, input_json)` / `run_tool_call(...)` API suitable
for Trillionnium OS to call directly while preserving Hepta-owned policy/session/event
state.

Because the direct invoke boundary is private, Trillionnium OS should not copy Hepta's
private `ToolRegistry` logic or promote the M2 shim into another runtime. The
safe current shape is:

1. Keep OS-facing D-Bus/task/approval/audit state in Trillionnium OS.
2. Keep the tiny `LocalShimAdapter` only for deterministic smoke and OS-status
   fallback tools.
3. Keep `UnsupportedHeptaRuntimeAdapter` explicit until one of these is chosen:
   - Hepta exposes a narrow public native tool-call API on `RuntimeKernel`; or
   - Trillionnium OS intentionally embeds `hepta-cli::CliApp` for CLI-command-level
     delegation; or
   - Trillionnium OS spawns the canonical Hepta app/runtime as a supervised sidecar and
     talks over a stable RPC/socket boundary.

## Current Trillionnium OS adapter code

`crates/trillionnium-tool-runtime/src/lib.rs` now defines:

- `trait HeptaRuntimeAdapter`
- `LocalShimAdapter`
- `UnsupportedHeptaRuntimeAdapter`
- `execute_with_adapter(...)`

`trillionniumd` and `trillionnium-dbus` execute M2 tools through `LocalShimAdapter`, not by
claiming this crate is the canonical runtime. The temporary built-in manifests
use `ToolExecutorKind::LocalShim` rather than `Native`, and D-Bus `ListTools`
reports the active adapter name alongside the tool manifest list.

## Runtime readiness and contract surfaces

`trillionnium-command-center runtime probe` reports the current execution truth:
LocalShim is ready and canonical native Hepta execution is not yet ready. This is
also embedded in the status dashboard and in `doctor` as `runtime adapter readiness`.

`trillionnium-command-center runtime contract` exposes the draft next-boundary
contract without executing through it. `trillionnium-command-center runtime
native-adapter` exposes the manifest-only NativeHeptaRuntimeAdapter skeleton:
default builds report feature-disabled, while builds with `--features
native-hepta-runtime-adapter` construct `hepta_runtime::RuntimeKernel`, map public
Hepta descriptors into Trillionnium `ToolManifest`s, validate those manifests,
and prove `execute_tool` still returns `CanonicalHeptaRuntimeUnavailable`.
LocalShim remains the default adapter and native D-Bus registration stays
disabled. The normal `status` dashboard and GTK/libadwaita UI also surface this
native-adapter snapshot read-only so dogfood users can see the manifest gate
without running the standalone CLI. `trillionnium-command-center runtime catalog` adds the first
feature-gated native catalog probe: default builds report the feature as
disabled, while builds with `--features hepta-catalog-probe` construct
`hepta_runtime::RuntimeKernel`, read `tool_descriptors()`, map them into
Trillionnium read-only summaries, and still set `execution_enabled=false`.

`trillionnium-command-center runtime schema-crosswalk` is the descriptor-to-OS
compatibility gate. It uses the same `--features hepta-catalog-probe` boundary,
constructs Hepta descriptors, parses and compiles every input/output schema, and
builds manifest-shaped `NativeCatalogOnly` validation reports. Registration stays
disabled (`runnable_registration_enabled=false`) so this can catch schema/policy
shape drift without exposing Hepta tools over D-Bus.

`trillionnium-command-center runtime sidecar-mock` validates the next supervised
sidecar envelope before any real process is launched. It creates deterministic
JSON frames for `list_tools`, `validate_tool_input`, blocked `invoke_tool`, and
`query_events`, echoes `request_id`/`correlation_id`, advances mock event cursors,
and keeps both `execution_enabled=false` and `registration_enabled=false`.

`trillionnium-command-center runtime sidecar-noop` upgrades that envelope into a
real lifecycle smoke: Command Center spawns a no-op child process, waits for its
temporary Unix socket, exchanges newline-delimited JSON health/query/invoke/shutdown
frames, verifies `execution_disabled_noop_sidecar` for `invoke_tool`, and confirms
clean child exit. `runtime sidecar-supervise` moves the same child to the canonical
`$XDG_RUNTIME_DIR/trillionnium-os/hepta-runtime.sock` path, exercises separate
client connections, and refuses to overwrite either non-socket paths or an active
socket. The dogfood packaging now renders a disabled-by-default
`trillionnium-hepta-sidecar-noop.service` user unit template for this same blocked
child process; it intentionally has no `[Install]` section and is not enabled by
`install-dev.sh`. `runtime sidecar-status` is the read-only inspector for that
boundary: it checks systemd state, socket shape/connectivity, and, only when the
socket is already live, sends `health` and `query_events` without `shutdown` or
`invoke_tool`. `runtime sidecar-events` is the next preview-only bridge: it turns
read-only `query_events` output into cursor/limit-controlled Trillionnium audit-shaped summaries, can export them as JSON/JSONL/Markdown/CSV, but does
not write the audit database or emit D-Bus signals. The Command Center dashboard
and GTK/libadwaita UI surface this preview as cursor/count metadata plus
read-only audit-shaped rows; the UI also exposes command-hint buttons for current
preview, next cursor, and JSONL export. It still does not load or call Hepta
runtime internals.

`trillionnium-command-center runtime sidecar-invoke-probe` is the first
feature-gated real sidecar invocation gate. Default builds report
`feature-disabled` and spawn no child. With `--features
hepta-sidecar-invoke-probe`, Command Center spawns an ephemeral child on a
temporary Unix socket, constructs Hepta `RuntimeKernel`, serves `health`,
`list_tools`, `validate_tool_input`, echo-only `invoke_tool`, `query_events`, and
`shutdown`, and verifies one low-risk `echo` invocation through Hepta's public
`run_demo_turn_in_session` path. The probe installs local child-only policy that
denies all risk tiers unless `echo` is explicitly allowlisted, uses
`ReadOnlyTools`, and still keeps D-Bus registration, packaged sidecar service
state, Trillionnium audit DB writes, and default LocalShim execution unchanged.
It is not the production adapter; it is evidence that the supervised sidecar RPC
shape can carry a tightly gated Hepta invocation.

`trillionnium-command-center runtime ollama-toolcall` is the next, still gated,
local smoke. With `--features hepta-ollama-toolcall-probe`, it writes a temporary
Hepta local-import manifest for `http://127.0.0.1:11434/v1`, selects the local
Gemma/Ollama model, switches the smoke session to Hepta `ReadOnlyTools`, installs
a provider-scoped deny policy for all risk tiers, allowlists only `echo`, and
runs one `RuntimeKernel::run_demo_turn_in_session` tool loop. It is evidence that
Ollama can emit an OpenAI-compatible tool call that Hepta executes safely; it is
not the production Trillionnium executor and does not register Hepta tools on
D-Bus.

The current contract requires either a stable public direct API shaped like:

- `RuntimeKernel::tool_descriptors() -> stable tool catalog`
- `RuntimeKernel::validate_tool_input(tool_name, input_json) -> ValidationResult`
- `RuntimeKernel::invoke_tool_call(session_id, correlation_id, tool_name, input_json) -> ToolResult`
- `RuntimeKernel::query_events_after(cursor, session_id, limit) -> ordered Event stream`
- `RuntimeKernel::approval_snapshot_for_session(session_id) -> Hepta-owned approval state`

or a supervised sidecar RPC boundary. The recommended sidecar transport is a
local Unix-domain socket under `$XDG_RUNTIME_DIR/trillionnium-os/hepta-runtime.sock`
with length-delimited JSON frames. Sidecar requests carry protocol version,
request id, optional Hepta session id, Trillionnium correlation id, method, and
method payload; responses echo the request id and return `ok`, `result` or a
stable error, plus an optional event cursor.

Hard invariants:

1. LocalShim remains the deterministic default smoke adapter until the gate is met.
2. Trillionnium OS does not copy or fork Hepta's private `ToolRegistry`.
3. Hepta retains ownership of native runtime policy/session/event internals.
4. Trillionnium audit records OS-side correlation and mirrored event summaries,
   not a duplicate Hepta event store.
5. Offline Command Center views stay read-only.

## Next implementation slice

Recommended next safe slice:

1. Keep the echo-only sidecar invoke probe feature-gated and extend its report
   with stricter event/correlation checks before considering broader tools.
2. Keep the manifest-only NativeHeptaRuntimeAdapter skeleton feature-gated and
   extend it only with additional validation/deny-path checks until a production
   invoke gate is promoted.
3. Keep the Ollama/Gemma smoke as a feature-gated test-only harness: expand it
   only with safe/read-only tools and explicit provider policies.
4. Add an opt-in write-gated event mirror that can persist sidecar event summaries
   to Trillionnium audit only after the preview shape is stable.
5. Only execute through native Hepta as a production adapter after a stable public
   invoke API exists or after the sidecar/RPC boundary is implemented and
   explicitly supervised.
5. Bridge Hepta `EventRecord` into Trillionnium OS audit/D-Bus signals without merging
   or duplicating Hepta's internal event store.
