# ADR: Direct Agent Native OS Architecture

Date: 2026-07-20

Status: **SUPERSEDED on 2026-08-06**

Superseded by: `2026-08-06-codex-native-direct-shell-adb.md`. This document
remains historical evidence for the typed-only, dual-Agent boundary and is no
longer the current product direction.

Accepted amendment: **2026-08-02 — P0-1 Direct permission / typed broker boundary**

Supersedes: `2026-07-11-trillionnium-agent-api-v1.md` and every
Mobian/Phosh/local-model or plan-to-Authority execution design

Normative product-boundary contract:
[`../contracts/agent-exec-adb-windows-product-boundary-v1.json`](../contracts/agent-exec-adb-windows-product-boundary-v1.json).
Revision 4 of the contract freezes the built-in-Agent, Direct MCP, typed
exec/ADB and Windows decisions below in a machine-readable form. Changing it
requires a newer accepted ADR or explicit accepted amendment and matching
`CURRENT_STATE.md` and contract updates; source presence, a debug build or an
evidence file cannot widen this boundary.

The revision 4 permission model is measured as
`2d34b16408edab77d43721258465d1cdcfd112c89ecf4f953ed8f983f9a5350d`;
the complete typed-operation catalog is measured as
`51bd8a05047642a4dc24dfae1d159bf8c14fb754834e4a45d7c61e99263b39ac`.
Both are non-authorizing source HOLDs.

## Context

Trillionnium must let built-in AI Agents operate Android without turning a
model, provider runtime, or compatibility environment into the OS security
authority. Earlier development lines described a local model stack, a
Mobian/Phosh-first phone, or an immutable plan approved and executed by
TrillionniumAiAuthority. None matches the current Android Direct implementation.

The implementation now embeds measured Codex and OpenClaw runtimes in an
Android-managed Root Linux rootfs. During an Agent turn, those runtimes call
independently measured System API and Accessibility adapters. The adapters
connect directly to narrow Android backends and return strict evidence. The
former Authority action executor has been removed.

## Decision

### 1. AI-native describes the OS/Agent contract, not inference placement

Trillionnium is AI-native because the OS can host an approved Agent and expose
native, policy-controlled phone capabilities to it. Current provider inference
is outside the phone. The Host/Tool contract is inference-location-agnostic,
so a future deployment-topology change could not change the phone's
authorization boundary. No phone-local LLM runtime is a product target,
requirement, or release gate.

### 2. Agents are built-in measured principals

An Agent is an OS-provisioned identity with a closed descriptor: provider and
Agent IDs, UID/GID, SELinux domain, measured launcher/runtime closure, prompt
contract, allowed egress, direct-tool closure, and evidence codec. The current
product has exactly Codex and OpenClaw. A future descriptor registry must be
OS-signed and product-allowlisted; it is not an untrusted plugin discovery
mechanism.

An Agent never receives ambient adb or root, an arbitrary shell, `sh -c`, a
caller-selected executable path, unrestricted Binder access, Android backend
identity, or any OS/OTA/AVB/APK, policy, enrollment, attestation or
receipt-signing key.

### 2.1 Direct MCP is the Agent UX; the OS remains the effect authority

This is a frozen product boundary, not an implementation suggestion. Codex and
OpenClaw invoke OS tools directly through MCP during their measured turn. That
is the Agent-facing tool UX and invocation ownership; it does not give the
Agent the Android backend identity, a privileged transport, an execution
credential, or effect-signing custody. A Direct MCP adapter either reaches a
narrow OS-owned typed Android backend or submits a canonical typed request to
an OS-owned broker. It cannot become a privilege executor merely because the
Agent invoked it directly.

The only admissible shell-like execution surface is an **OS-owned typed exec
broker**. The Agent request contains a closed, versioned OS-allowlisted
operation ID and arguments from that operation's closed typed schema. OS policy
selects a signed execution descriptor containing the exact measured executable
and `argv[0]`, a fixed argument template with typed value slots, UID/GID/SELinux
identity, cgroup/seccomp/capability profile, environment, filesystem/network
scope, absolute deadline, output limits, and descendant policy. The broker
materializes each validated typed value as a distinct argv element. A generic
caller-supplied `Vec<String>`/argument vector, option vector, executable path,
command string, shell interpreter, `sh -c`, environment/PATH injection,
caller-selected credentials, or opaque file descriptor is not typed argv and
is forbidden.

The only admissible ADB form is an **OS-owned typed ADB broker** using the same
closed request, OS-selected descriptor, admission, durability and fail-closed
contract. In addition, the OS owns the fixed local-device target, transport,
adbd key/enrollment custody and allowed service. The Agent cannot select a
serial, host, port, raw ADB command/argument vector, `adb shell` command string,
`root:`, `remount:`, or an unknown service. Engineering/recovery and future
user-product descriptors remain separate. The retained debug adapter and its
caller-supplied `Shell { argv }` request do not satisfy this contract.

For both brokers, the OS authenticates the measured Agent at the process
boundary, resolves the product-signed operation descriptor, canonicalizes the
request, applies risk policy and any required one-shot lease before effect,
and binds one delivery attempt. PREPARED-before-effect, terminal-result-before-
return, exact response replay, durable outer ACK, restart/response-loss
recovery, and rollback-resistant epoch/high-water evidence are mandatory.
Unknown or ambiguous outcomes are indeterminate and cannot be blindly retried.

One exact source-candidate catalog now freezes three no-argument
Settings-launch descriptors: typed exec, user-product typed ADB, and a
disjoint engineering/recovery typed ADB descriptor. Raw ADB is operator-only
outside every Agent closure. The shared permission model and catalog are not
product-signed, expose no typed Direct MCP tool and explicitly grant no effect
authority. No general typed exec or typed ADB broker, product catalog,
production constructor, or physical-device closure is currently implemented.
The source-only `trillionnium-agent-privilege-broker` containment and custody
foundations do not implement this typed operation surface. Both brokers remain
product HOLDs. A conforming user-product broker may be promoted under this ADR
only after every frozen gate passes; changing any request, authority, custody,
or durability rule requires a newer accepted ADR or explicit accepted
amendment. Android actions continue to prefer typed System APIs, with typed
Accessibility as a compatibility fallback. Model output, provider payloads and
Agent processes never directly hold broker privilege, transport, backend
identity or signing custody.

### 3. Agent Host API and OS Tool API are different planes

The **Agent Host API** is the lifecycle boundary by which the OS invokes,
supervises, cancels, and collects a direct result from an Agent. It binds the
manifest, runtime lifecycle, user/context provenance, egress consent and
limits, invocation attempt, and strict result/evidence contract. It does not
execute phone tools on the Agent's behalf. The AiShell-to-daemon carrier is
versioned as `trillionnium.direct-agent-host.uds.v1`; it is not an Authority
effect executor.

Built-in Android and kernel Agent API carriers share the generated
`org.trillionnium.direct-agent-host.abi.v1` lifecycle/result contract, frozen by
raw contract SHA-256
`97f3cc966459fcac92dc84f658f97283a30d4d3a9d923212e09211bc13d6aeae`.
They publish the same task states, terminal states, Direct outcomes, result v1,
receipt v2 and effect-authority facts, while retaining distinct protocols,
sockets, authentication and replay domains. The result contract has 44 exact
fields and the commitment has 26. `tool_invocation_owned_by_agent=true` and
`tool_backend_owned_by_os=true` do not make the daemon an effect executor;
`daemon_is_effect_executor=false` and
`contract_confers_effect_authority=false` are independently bound. The built-in
carrier's historical `plan` wire name is an explicit mapping to
`run_direct_turn`, not plan-to-Authority semantics.

The **OS Tool API** is the action boundary called by the Agent during that
turn. Each tool has a closed, versioned schema. Its effect authority is either
a narrow OS-owned Android backend or, for a future typed exec/ADB operation,
an OS-owned broker satisfying section 2.1. The adapter authenticates its fixed
Agent identity from the process boundary, validates and canonicalizes the typed
action, applies risk policy before backend I/O, and validates the bound
response. Model text cannot choose a backend, executable, argv template,
identity, transport, limits, or policy tier.

```text
Android user + AiShell
        |
        | OS UI / Agent Host control
        v
    trillionniumd
        |
        | measured lifecycle, context, egress, cancellation
        v
 Codex or OpenClaw Agent turn
        |
        | MCP stdio OS Tool API (Agent-facing UX)
        +------------------------------+
        |                              |
        v                              v
 measured System API adapter    measured Accessibility adapter
        |                              |
        v                              v
 Android System backend         AccessibilityService v2 backend
        \______________________________/
                       |
          strict tool evidence/direct result

 Future, currently absent/HOLD:
 measured typed exec/ADB adapter -> OS-owned typed broker -> fixed executor
                                      |
                          strict result/replay/ACK evidence
```

The generic `trillionnium.agent-api.uds.v2` task/data server remains present,
but current built-in Direct Agents do not use it as their host carrier. Its
default production surface retains identity, health, task lifecycle,
cancellation, and Context/Memory grants, with an empty generic executor
catalog. Plan submission, action-run, and Authority effects exist only behind
an explicit non-product legacy conformance/test feature. They are not an
alternate OS Tool API. The next Host ABI must generalize Direct invocation,
not reactivate those retired methods. Retired names may remain in negative
prompt rules and historical-state quarantine parsers without becoming live
methods. Client construction and daemon ingress share one enabled-method
allowlist; its invariant product subset excludes the retired methods even when
legacy vectors are compiled.

The consumed egress lifecycle owns one cancellation token shared with either
provider adapter. Cancellation latched before child start is checked only after
the exact lifecycle, broker and private provider session are bound, so both
Codex and OpenClaw can publish typed teardown evidence without spawning a child.
There is no second provider-specific cancellation channel that can miss a
cancel between the outer check and adapter start.

### 4. Direct tool execution is canonical

The current user closure contains exactly:

- `trillionnium_system_api` via
  `trillionnium-agent-system-api` and `org.trillionnium.agent-system-api.v1`;
- `trillionnium_accessibility` via
  `trillionnium-agent-accessibility` and
  `org.trillionnium.agent-accessibility.v2`.

Both are MCP stdio tools with strict structured-content binding. They use
fixed abstract Android sockets and have no broker, dispatcher, Authority
effect hop, PATH fallback, or alternate backend. The System API currently
offers package launch and URI open. Accessibility offers explicit
metadata/full-text snapshots and typed click, text, scroll, global, gesture,
and batch actions.

Typed exec and typed ADB are frozen future OS Tool API classes, not members of
this current two-tool closure. There is no product MCP schema, operation
catalog, broker route or backend for either. The existing development ADB
request and inert ADB wire state machine are engineering research inputs only;
they cannot be relabeled as a conforming typed broker.

Production-durable adapters accept only `semantic` or `mcp`. The former
no-argument raw backend-wire input is removed from production and exists only
in the explicit non-product development-compatibility lane. The measured
adapter, not the Agent or model, authors protocol, Android user and replay
identity before serializing the fixed Android backend ABI. Provider packaging
and result attestation bind the same semantic input and validated adapter
evidence rather than trusting caller-authored envelope fields.

The current risk policy defaults only metadata snapshot, package launch,
scroll, Back, and Home to ALLOW. Sensitive and critical actions require an OS
session lease; because no trusted product issuer exists, they are denied
before backend connection. This fail-closed state is accurate but not a
complete general phone-control product.

The committed safety chain is deliberately fail-closed. A
`ProviderEffectAdmission` is bound to the exact Codex or OpenClaw principal,
and production dedicated-UID health probes must satisfy the same post-exec
containment predicate as a real turn. The daemon's source-only Direct
tool-call transport holds a pidfd for the authenticated adapter and sandwiches
each process re-observation with liveness checks; it revalidates boot identity,
start time, executable, fixed cgroup, SELinux domain and identity digest again
before each allocator mutation edge. Stored PREPARED ACKs are returned only
after the adapter journal revalidates their external operation-epoch lineage;
missing or drifted lineage is a HOLD.

The fixed cgroup is a closed topology, not one shared provider leaf. Each
built-in provider owns a process-free parent with exactly three direct child
leaves: `runtime`, `system-api`, and `accessibility`. Provider containment binds
the final runtime to `runtime`; the two adapters execute only in their sibling
leaves. Parent membership, child names, depth/descendant limits, dying counters,
and final leaf membership must all be observed under one broker-owned retained-
FD custody. The existing childless two-leaf lifecycle cannot produce that proof
and remains an explicitly rejected source-only legacy model.

These source closures do not make Direct effects available. Production
provider admission has no constructible post-exec authority, the adapter
connector/provider delivery route and rollback-resistant high-water are not
wired, and secure first use plus Android epoch/replay ACK remain absent.
Product turns therefore stop before provider or phone effects.

### 5. Authority is custody, not effect execution

TrillionniumAiAuthority is not on the direct tool path. Its root gateway has a
seven-method closed set for receipt-key metadata, Context capture resolution
and recovery, and Memory key wrap/unwrap. It may host user-facing Context and
egress-consent ceremonies. It must not regain `execute`, `undo`,
`recover_execution`, or a generic action capability.

OS action consent for direct tools will be issued by a narrowly scoped OS
lease service. A lease binds the exact Agent, tool, canonical action digest,
user, boot generation, risk ceiling, monotonic validity window, and one
delivery attempt. It authorizes only the adapter's pre-effect risk guard; it
does not move execution back into Authority.

### 6. Root Linux is an Android-managed Agent runtime

Root Linux is the verified, headless chroot/rootfs used to host the daemon and
Agent runtimes. Android init, SELinux, measured bind mounts, immutable
launchers, persistent state mounts, and the egress guard own its lifecycle. It
is not a replacement mobile distribution, Phosh session, desktop environment,
local-model product, or general root workspace. The product runner accepts
only `/usr/bin/trillionniumd`; it has no argument-free `/bin/sh` or manual
root-shell fallback.

Root Linux source/product integration is real, but release promotion remains
blocked by the intentional daemon archive/pin mismatch, missing zstd/builder
custody, inactive direct-operation journal hot path, and absent clean
build/device/OTA evidence.

### 7. WindowsCompat is not a current product capability

Wine/QEMU-related assets, a materialized overlay, and historical
WindowsCompat scripts are retained in vendor source as research inputs only.
They have no installable/runtime Soong module, init entry, package/inherit
path in any product variant, production supervisor, AgentDescriptor, typed OS
Tool API, or device/release conformance. A host absence-contract test may read
the retained files as data. Windows support must not be described as
implemented. Productization remains paused until the Android Direct
Codex/OpenClaw main loop has real effect, durable ACK/replay recovery and
locked-device evidence.

If work restarts, WindowsCompat must be redesigned as a small OS-supervised
service fed by a signed declarative application allowlist. Its entire Agent
surface is a closed typed `launch` / `inspect` / `stop` API. State, network,
filesystem, clipboard, display, audio, persistence, recovery, update, action
lease, journal and evidence boundaries must use the same Direct architecture.
The historical shell matrix, a generic shell bridge, raw Wine/QEMU command
forwarding and Agent-owned runtime supervision are forbidden restart designs.

## Security invariants

1. Caller-declared Agent, provider, tool, user, backend, or risk tier is never
   an authentication factor.
2. Agent identity is bound to kernel UID/GID/domain and measured immutable
   runtime/tool artifacts.
3. Egress authority and phone-action authority are separate and single-use.
4. Context, Memory, prompts, URI/text values, and tool results remain bounded
   and privacy classified; password subtrees are permanently redacted.
5. Unknown schema fields, ambiguous integers/JSON, identity drift, replay
   conflict, response loss, crash ambiguity, or missing custody fail closed.
6. A successful model turn is not proof that a phone effect occurred; strict
   backend evidence and outer result custody are required.
7. Host tests, package hashes, and source commits are not device or release
   receipts.
8. No Agent or provider payload may obtain ambient root/ADB, a command-string
   shell, `sh -c`, unrestricted Binder, Android service identity or signing-key
   custody.
9. A typed exec/ADB/compatibility service is OS authority: it must authenticate
   the Agent at the process boundary, resolve a product-signed closed operation
   descriptor, select executable, typed-argv template, backend identity and
   limits from OS policy, and durably bind request, policy, lease, effect,
   result, replay and ACK.
10. Direct MCP gives the Agent invocation UX, not ambient or delegated
    privilege. An adapter may carry only the canonical typed request and cannot
    hold, mint, widen or replay broker authority on the Agent's behalf.

## Consequences

- The old plan/approval/Authority execute/undo documentation is historical.
- `PlanningRequest`, `plan_attempt`, `plan_dispatched`, and local-plan-saga
  identifiers are migration debt and should be renamed to invocation/result
  language only through an explicit durable replay/storage migration, without
  weakening stored-state quarantine.
- Generic UDS plan/action execution and dormant tool-runtime Authority effects
  are absent from default production and retained only by an explicit legacy
  conformance/test feature. That feature should disappear after its historical
  vectors have Direct replacements.
- New phone capabilities should be typed semantic OS APIs (notifications,
  settings, intents/share, documents, media, foreground/window state).
  Accessibility remains a fallback for UI surfaces without a semantic API.
- Closed typed exec/ADB operations are admissible only where a semantic Android
  API is unavailable or an explicitly reviewed recovery operation requires
  them. Passing a raw argument vector through MCP is not a typed operation.
- Adding a third Agent should become a descriptor/manifest operation within a
  signed allowlist, not a coordinated Rust/Java/provider-ID code edit.
- The shell/ADB and Windows product boundary is versioned by the normative
  contract linked above. A source-only broker, debug adapter, retained payload
  or host smoke cannot silently widen it.
- No Root Linux, WindowsCompat, device, OTA, or release claim advances until
  its explicit row in [`../CURRENT_STATE.md`](../CURRENT_STATE.md) is PASS.

## Rejected alternatives

- **Phone-local LLM as the platform core:** inference location does not provide
  Android capability, authorization, durability, or audit.
- **Agent receives ambient root/adb, a command-string shell, `sh -c`,
  unrestricted Binder or signing keys:** collapses OS policy, identity and
  custody boundaries into untrusted model output.
- **Authority as generic effect executor:** recreates the retired duplicate
  gateway and forces every tool through an unrelated app ceremony.
- **Accessibility as the only native API:** useful fallback, but too generic
  for stable semantic policy and evidence.
- **Mobian/Phosh plus Waydroid as the active product:** does not describe the
  current Android-hosted implementation or its security boundary.
- **WindowsCompat assets imply Windows support:** retained research artifacts do not
  establish an OS service, Agent API, or release contract.
