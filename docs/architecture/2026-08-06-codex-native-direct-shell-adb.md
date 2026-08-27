# ADR: Codex-native direct shell and ADB architecture

Date: 2026-08-06

Status: **ACCEPTED DIRECTION; amended for owner-open implementation by
canonical plan revision 2026-08-27-r3**

Supersedes the retired 2026-07-20 dual-Agent/direct-boundary route for the
built-in Agent set and shell/ADB product boundary. The superseded source files
were removed from the active tree on 2026-08-26; their hashes and recovery
location are recorded in the development-tree inventory. Earlier evidence
remains historical and cannot authorize a current product capability.

Transition machine-readable boundary (superseded for owner-open):
[`../contracts/agent-exec-adb-windows-product-boundary-v2.json`](../contracts/agent-exec-adb-windows-product-boundary-v2.json).

Current owner-open contract:
[`../contracts/codex-sovereign-direct-tools-v1.json`](../contracts/codex-sovereign-direct-tools-v1.json).

## 2026-08-26 owner-open amendment

The canonical development plan revision 2026-08-27-r3 is the active
implementation authority. It changes this ADR's earlier implementation
constraints: Codex is the only semantic authority, the development profile is
owner-open, and shell/ADB are raw first-class tools. The substrate provides
mechanisms only (launch, IPC, process/transport, storage, liveness and
recovery); it does not perform risk classification, approval, target routing
or a typed action allowlist. The sections below remain historical context
where they describe mandatory risk/confirmation/Authority gates. They must not
be used to block an owner-open Codex turn.

## Context

Trillionnium is an AI Agent native OS, not a phone-local model appliance. A
Codex-class Agent is part of the OS and must be able to operate the phone
through first-class OS tools. Requiring a second general-purpose Agent runtime
or treating ADB/shell as permanently outside the Agent closure contradicts
that product model.

The previous canonical ADR correctly kept inference off-device and placed
security authority in the OS. It incorrectly froze two built-in Agents and
made shell/ADB unavailable except through a future closed typed catalog. The
current source and device state therefore cannot satisfy the new product
direction without an explicit boundary change.

## Decision

### 1. Codex is the only built-in Agent

The product registry contains exactly one active Agent principal:

- provider: `openai-codex`
- Agent: `agent-codex-direct-v1`
- runtime: OS-launched and kept-alive Codex runtime; measurement is
  diagnostic/release provenance in owner-open, not an admission gate

Codex-native subagents are optional owner configuration under that principal;
they are not additional OS Agents and must use the same observable direct-tool
event stream (native or transparently adapted).

OpenClaw is retired. It has no product descriptor, request path, runtime,
launcher, SELinux execution domain, network identity, cgroup, package or
effect authority. UID/GID and storage identifiers required to migrate old
devices remain non-reusable tombstones until physical OTA cleanup is proven.

### 2. No phone-local LLM

Current model inference is off-device. The phone contains the Codex Agent
runtime, conversation/tool protocol and OS integration, but no local LLM
weights, local inference scheduler or release gate for local model execution.

### 3. Codex directly owns tool invocation

Codex receives first-class tools for:

- Android System APIs;
- Accessibility compatibility actions;
- shell execution;
- ADB operations;
- root/developer/recovery targets that Codex selects directly; the substrate
  reports the target's real result or error.

There is no plan-to-Authority executor and no second Agent translating Codex
output. The Codex turn selects and invokes the tool and receives its result.
In the owner-open profile the substrate is semantic-policy-blind; it exposes
the requested command and the target's real response.

“Direct” describes invocation ownership and latency. It does not require the
model process to own the adbd private key, Android service identity, SELinux
policy, signing key or a permanent unrestricted root credential. Those remain
OS assets, just as syscall authority remains a kernel asset when an
application invokes it directly. In owner-open, “OS asset” means an
owner-configured handle or file that Codex may inspect and operate through
shell; it is not an admission barrier or a reason to hide a command.

### 4. Shell is a product capability

The primary interfaces are `shell.command(command, options)` and
`shell.exec(argv, options)`. Command strings, pipes, scripts, normal
environment/cwd semantics, PTY, deadlines and cancellation are all first-class.
There is no business-command allowlist or automatic risk classification in the
owner-open profile.

Execution endpoints/profiles are distinct metadata/configurations, not typed
authorization tiers:

- standard Root Linux/Android shell;
- owner-configured Root Linux or elevated execution (which may be persistent
  for dogfood and does not require a lease or confirmation);
- recovery/developer execution.

The substrate starts the selected target profile, applies only the mechanical
process/IPC/liveness setup, records the request/result when configured, and
returns the real outcome to the same Codex turn. It must not silently fall back
from one target or privilege to another.

### 5. ADB is a product capability

Codex may directly call arbitrary ADB operations, including shell semantics.
The canonical owner-open path is a normal adb client in Root Linux; target
selection is an explicit transport binding and the remaining argv is passed
unchanged. User, developer and recovery endpoints may be selected by Codex.
Root, remount, reboot, sideload, install/uninstall and flashing are not hidden
semantic gates; if the target accepts or rejects them, that exact result is
returned to Codex.

On-device implementations may optimize a local-phone ADB call into a direct
privileged Android backend when bytes and result semantics are equivalent.
Evidence-equivalence checks belong to a sealed/public release profile, not to
owner-open invocation. This is an implementation detail; Codex still sees a
stable ADB tool contract.

### 6. Mechanism durability and honest failure

Each call may carry a turn ID and operation ID for observability, bounded
process/transport resources and restart information. A lost response is
reported as unknown; the substrate does not invent a commit or retry. Codex
decides whether to inspect, retry, undo or ask. Credential/key exposure is an
owner configuration and hygiene concern, not a semantic approval service.

This ADR rejects two extremes:

- a permanently unavailable, catalog-only shell/ADB surface that prevents the
  built-in Agent from operating the OS;
- an unbounded, unrecoverable process with no owner emergency path. Owner-open
  dogfood may intentionally grant broad configured Root Linux/device access;
  process liveness, transport failure reporting and out-of-band recovery still
  remain substrate mechanics, not semantic command restrictions.

### 7. Windows remains absent

Windows compatibility is `research_only_not_implemented`. Wine/QEMU custody
files do not constitute a product feature and must not enter target-files.
Productization remains a separate milestone after the Android Codex main loop
and release pipeline close.

## Required implementation work

1. Publish the owner-open direct-tools contract and migrate old plan/approval
   fields to a legacy feature.
2. Start one long-running Codex Agent Host in Root Linux.
3. Enable direct shell.command/shell.exec and a real ARM64 adb client or
   transparent host-server shim.
4. Prove one same-turn host, Root Linux and Android task on the owner device.
5. Add useful event-log recovery and Codex-driven OTA/reboot iteration.

These are implementation milestones. They are not a requirement to obtain a
formal approval or release receipt before owner-open dogfood can run.

## Consequences

- The dual-Agent registry and OpenClaw-specific code/assets must be removed
  from the active product graph.
- Typed System API operations remain preferred where they give stronger
  semantics, but typed-only catalogs no longer block Codex from having a real
  shell/ADB tool.
- Existing proof/custody code should be simplified around one working vertical
  slice before additional abstract carriers are added.
- Old devices require an explicit OpenClaw state/mount cleanup migration; UID
  5902 remains a retired tombstone until that migration is physically sealed.
  This cleanup is postulated migration/release work and does not block
  owner-open shell/ADB operation on a userdebug device.
