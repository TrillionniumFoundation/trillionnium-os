# Trillionnium OS AI-Native Shell v1

Date: 2026-05-30

## Decision

Trillionnium should now be treated as a new AI-native personal operating system,
not as an Android app, Android launcher, Linux office launcher, or debug command
center.

The current Android + Linux stack is the substrate:

- Android owns hardware integration, verified boot, OTA, app compatibility,
  permissions, input, sensors, radios, and mobile power/runtime behavior.
- Root Linux owns desktop software, CLI workflows, package management,
  automation, and long-running production applications.
- Trillionnium OS owns the user-facing work model, AI collaboration model,
  session lifecycle, trust surface, receipts, and brand.

Bridge, DisplaySurface, noVNC, init modes, and root-Linux scripts remain valuable
engineering parts. They should stop being the product vocabulary.

## Why This Pivot

Bridge v2.3 and DisplaySurface v0.5 prove that a Linux GUI application can be
launched from the Android-hosted system layer, receive Android share input,
display through a phone-facing surface, and stop cleanly with receipts and
process cleanup. That is a substrate milestone.

It does not define the product.

If the next increments keep adding Office-specific buttons and Writer-specific
paths, the project will drift into an office launcher. That would underuse the
runtime stack and conflict with the intended OS identity. The next design must
make Linux applications, Android compatibility, files, automation, and AI agents
all appear as parts of one Trillionnium workspace.

## Brand Boundary

### User-Facing Names

- Product: `Trillionnium OS`
- Main surface: `Trillionnium Shell`
- AI collaborator: `Trillionnium Agent`
- Running work item: `Session`
- Launchable capability: `App`
- Action record: `Receipt`
- Policy surface: `Trust`

### Internal Names

These may remain in code during migration but should not be exposed as primary
UI language:

- `CommandCenterActivity`
- `Command Center Bridge`
- `RootLinuxBridgeProvider`
- `DisplaySurface`
- `ShareIngressActivity`
- `profile-display-libreoffice`
- `Xvfb`, `x11vnc`, `websockify`, `noVNC`
- Android init property names

### Rebrand Rule

The user should experience "I am in Trillionnium OS." They should not experience
"I am in Android launching a Linux noVNC session."

## AI-Native OS Principles

### 1. Intent First

The primary entry point is user intent, not an app grid.

Examples:

- Write a document from shared text.
- Continue the last spreadsheet task.
- Open this file with the best available app.
- Summarize these PDFs.
- Run a command and keep the result.
- Build a project.
- Clean up downloads.

Apps are chosen by the shell, by the user, or by an agent policy after the intent
is understood.

### 2. Sessions Are First-Class

A session is the central OS object. It can contain:

- an app adapter
- an open file or imported payload
- a display backend
- a process group
- a workspace directory
- an AI context summary
- current status
- receipts
- stop/resume/recover actions

Writer, Terminal, Files, Browser, Calc, and future tools are all session
implementations.

### 3. Agent As OS Collaborator

The AI agent is not a chat bubble bolted onto a launcher. It is an operating
collaborator that can:

- inspect allowed session state
- read selected files
- propose or execute shell actions
- launch apps
- run Linux commands
- transform files
- explain receipts
- recover failed sessions

Every agent action must carry scope, permission, receipt, and rollback
semantics. Silent broad control is not acceptable.

### 4. Apps Are Capability Adapters

Linux and Android apps are execution capabilities behind a common shell model.

LibreOffice Writer is the first proven adapter. It must not remain the center of
the UI.

Initial adapter classes:

- Linux GUI app
- Linux terminal command
- Linux file manager
- Android compatibility app
- Android share/import handler
- Agent automation
- System diagnostic action

### 5. Trust Is A Primary Surface

AI-native OS design requires visible trust. The shell must show:

- what was launched
- what files were touched
- what command ran
- what permissions were used
- what process is still alive
- what can be undone or stopped
- which action came from the user, Android share, or agent

Receipts are not debug afterthoughts. They are the accounting layer of the OS.

### 6. Runtime Substrates Are Swappable

The product model must survive backend changes:

- Android-hosted fullscreen shell now
- WebView/noVNC display backend now
- Wayland/Phoc backend later
- native DRM backend only after hard recovery evidence

The shell must not encode noVNC or Writer assumptions into core product state.

## Information Architecture

### Home

Purpose: resume useful work quickly.

Content:

- intent bar
- active sessions
- recent imports/files
- pinned capabilities
- compact system health
- pending trust items

Primary actions:

- Ask / act
- Resume session
- Open file
- Launch app
- Review trust item

### Ask

Purpose: agent-mediated work.

Content:

- intent entry
- suggested actions
- scoped context selector
- action preview
- receipt trail

The Ask surface must not become a generic chatbot disconnected from sessions.
It should understand the current workspace, files, apps, and trust state.

### Apps

Purpose: capability discovery and explicit launch.

Groups:

- Linux apps
- Android compatibility apps
- system tools
- automation templates

The default app list should be curated. Raw Android package inventory belongs in
System or a secondary compatibility view.

### Sessions

Purpose: lifecycle control for running and paused work.

Each session shows:

- title
- app/capability
- state
- file/import source
- backend
- health
- last receipt
- open/resume/stop actions

### Files

Purpose: make imported and generated work concrete.

Content:

- Android shares
- recent documents
- workspace directories
- generated outputs
- export targets

Share ingress should route by MIME and user intent, not directly to Writer.

### Automation

Purpose: saved or generated workflows.

Examples:

- convert document
- summarize folder
- run project tests
- clean workspace
- extract images
- build OTA

Automation must use the same receipt and trust system as app launches.

### Trust

Purpose: permission and accountability.

Content:

- pending approvals
- active scopes
- agent actions
- file modifications
- process/session ownership
- notification/import policy
- rollback availability

### System

Purpose: diagnostics and engineering visibility.

Content:

- bridge health
- profile health
- package counts
- apt checks
- OTA/build status
- raw receipts
- backend details

This is where current Command Center diagnostics belong.

## Core Data Models

### RootLinuxApp

```text
id: stable identifier, e.g. linux.writer
name: user-facing label
kind: linux-gui | linux-cli | android-compat | automation | system
icon: shell asset or Linux desktop icon mapping
profile: core | gui-baseline | custom
command: launch command or action mode
file_types: accepted MIME types/extensions
intents: high-level tasks it can satisfy
display_backend: android-webview-novnc | android-fullscreen | wayland-phoc
health_check: process, port, receipt, or app-specific probe
stop_policy: graceful | kill-session | unsupported
permissions: files, network, clipboard, android-share, agent-visible
```

### Session

```text
id: stable per-session id
app_id: RootLinuxApp id
title: user-facing task/session title
state: starting | running | attention | stopped | failed
source: user | android-share | agent | automation | system
workspace: path or logical workspace id
document_uri: Android URI or Linux path when applicable
display_backend: backend selected for this session
display_endpoint: URL/surface/token hidden from normal UI
pid_set: process evidence when available
receipt_paths: launch/status/stop receipts
created_at_ms: timestamp
updated_at_ms: timestamp
```

### Intent

```text
id: stable intent id
utterance: user or system request
source: user | share | schedule | agent
selected_context: files, sessions, apps, permissions
proposed_actions: ordered action graph
approval_state: pending | approved | denied | auto-allowed
receipts: action receipts after execution
```

### Receipt

```text
id: stable receipt id
action: launch-app | open-file | stop-session | run-command | agent-action
actor: user | agent | system | android-share
scope: files/apps/sessions touched
status: ok | failed | partial | blocked
summary: user-facing summary
details_path: raw receipt path
rollback: available | unavailable | not-needed
timestamp_ms: timestamp
```

## Current Implementation Migration

| Current element | Future role | Migration rule |
| --- | --- | --- |
| `CommandCenterActivity` | Shell prototype host | Rename conceptually; replace UI sections with OS surfaces |
| `RootLinuxBridgeProvider` | Runtime adapter | Keep as internal trigger/receipt provider |
| `RootLinuxBridgeContract` modes | Action backend | Map to `launch-app`, `stop-session`, `status`, `receipt` |
| `ShareIngressActivity` | Import router | Route MIME/imports to intent + app chooser |
| `profile-display-libreoffice` | Writer app adapter | Keep as first `RootLinuxApp`, then generalize |
| `DisplaySurfaceActivity` | Display backend surface | Hide backend name; session opens it as needed |
| noVNC port `6085` | Backend endpoint | Store in session backend metadata, not main UI |
| receipts under `/data/trillionnium` | Receipt layer | Promote summary to Trust/System UI |

## Compatibility With Current v2.3 Baseline

The current stable baseline remains useful:

- Bridge v2.3 from `/system_ext`
- DisplaySurface v0.5 from `/system_ext`
- 76M/512 core package embedded
- 700 package GUI baseline data-staged
- share-to-Writer path proven
- clean start/stop receipts
- no 6085 or GUI process residue after stop

The redesign should build on this baseline. It should not reintroduce the risky
pattern of embedding the 700 package GUI archive into `system_ext`.

## Implementation Phases

### Phase 0: Product Contract

Deliverables:

- this architecture document
- product vocabulary lock
- migration map from current names to user-facing names
- first app/session/receipt schema

No device changes.

### Phase 1: Generic Shell Prototype

Goal: replace Writer-specific UI with generic OS surfaces while keeping the same
backend routes.

Deliverables:

- Home / Ask / Apps / Sessions / Files / Automation / Trust / System sections
- curated `RootLinuxApp` registry in code
- `linux.writer` adapter backed by current proven path
- placeholder adapters for Terminal, Files, Calc, Browser
- generic `launch-app(appId)`
- generic `stop-session(sessionId)`
- generic session state model backed by receipt + live process/port checks

Validation:

- hot-install only first
- no OTA
- no reboot unless explicitly needed
- Writer still passes current v2.3 smoke
- at least one non-Office app appears in Apps/Sessions as a real or bounded
  placeholder adapter

### Phase 2: Non-Office App Gate

Goal: prove the shell is not Office-specific.

Candidate apps:

- Terminal or xterm
- Files or a lightweight file manager
- Calc
- Text editor
- Browser, if packaged and stable

Validation:

- launch through `launch-app`
- session row appears
- status is live-backed
- stop cleans process set
- receipt is visible in Trust/System

### Phase 3: Share/File Router

Goal: Android imports become OS intents.

Deliverables:

- MIME router
- import inbox
- "open with" chooser
- recent file/session linking
- Writer remains a target for text/plain, not the only path

### Phase 4: Agent Surface

Goal: introduce AI-native behavior without unsafe broad control.

Deliverables:

- Ask surface
- scoped context picker
- proposed action preview
- action approval
- receipt summary
- first bounded automations

### Phase 5: Small OTA

Only after hot-install smokes pass:

- build a small OTA for shell/app/session model code
- keep 700 GUI archive data-staged
- rerun pure `/system_ext` validations
- verify no updated-system app overlays remain

## Non-Goals For The Next Gate

- No full OTA before a hot-install prototype passes.
- No 700-package GUI archive inside `system_ext`.
- No native DRM/Phoc rewrite before the shell model is generic.
- No broad autonomous agent control without Trust/Receipt UI.
- No Android launcher re-skin as the final product.
- No Office-only feature work as the main track.

## Acceptance Criteria For v1 Prototype

The first implementation after this document is acceptable when:

- The first screen says and feels like Trillionnium OS, not Command Center.
- Writer is represented as `linux.writer`, not as hard-coded product center.
- Apps and Sessions are backed by generic model objects.
- A non-Office app path is visible and at least one non-Office launch smoke has
  a bounded plan or passing result.
- Share ingress becomes an import/intent event instead of direct Writer-only
  behavior.
- Trust/Receipt summaries are first-class UI elements.
- All changes are hot-install validated before OTA.

## Next Engineering Step

Implement the Phase 1 generic shell prototype in the Android-hosted shell:

1. Introduce small in-code `RootLinuxApp` and `Session` model classes.
2. Map current Writer launch/stop/status to `linux.writer`.
3. Replace visible `Start Writer` centered UI with Apps/Sessions surfaces.
4. Add placeholder registry entries for Terminal, Files, Calc, and Browser.
5. Keep old bridge modes behind System diagnostics.
6. Build and hot-install the shell APK only.
7. Run the existing Writer smoke plus a non-Office app discovery/session smoke.

This is the first step from "Linux GUI bridge works" to "Trillionnium OS exists
as a coherent AI-native operating surface."
