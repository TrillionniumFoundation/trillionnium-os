# Trillionnium Shell UI Architecture v1

Date: 2026-05-28

## Position

The current Command Center Bridge UI and Browser/noVNC LibreOffice route prove the
runtime path, not the product interface. They should be treated as a backend and
debug control plane. Trillionnium needs its own shell: a first-screen system UI
where Linux applications, Android compatibility applications, files,
notifications, bridge health, and approvals are presented as one Trillionnium
workspace rather than as Android launcher cards or Android settings panels.

This changes the product target:

- Android is a hardware/runtime substrate and compatibility plane.
- Root Linux is a first-class application/runtime plane.
- Trillionnium Shell is the user-facing operating surface.
- Phoc/DRM is a backend option, not the UI architecture itself.

## Current Evidence

Installed device `ZY32JLVHGN` now has a durable root-Linux display bridge:

- provider mode `display-libreoffice`
- init service `trillionnium_root_linux_display_libreoffice`
- `/system_ext/bin/trillionnium-root-linux-display-bridge`
- Command Center Bridge v7/v1.6 LibreOffice card
- Xvfb/openbox/x11vnc/websockify/LibreOffice alive after init trigger
- Android Browser/noVNC screenshot proving LibreOffice renders on the phone

This is enough to promote Linux GUI app display as a supported backend surface.
It is not enough to keep Android Browser or the old Command Center layout as the
main UI.

Prior Phoc/DRM probing also found a real boundary:

- Phoc can start headless enough to launch `soffice.bin` in a Wayland session.
- Physical panel ownership is blocked in the current Android-hosted chroot.
- `seatd-launch` cannot open `/dev/tty0`.
- libseat/VT/DRM ownership is unavailable while Android owns display.

Therefore native Phoc/DRM should be pursued as a separate backend feasibility
track after the shell model is defined.

## Design Principles

1. Shell first, apps second.
   The first screen is not a list of Android apps. It is a work surface with
   running tasks, recent documents, active Linux sessions, trusted actions, and
   system health.

2. Linux apps are native Trillionnium surfaces.
   LibreOffice should appear as a Writer workspace, not as "open Browser to
   noVNC". The transport can remain noVNC internally while the shell owns
   launch, focus, stop, status, and file handoff.

3. Android compatibility is contained.
   Android apps can be launched and indexed, but they should appear under a
   compatibility section with clear status and permissions. Android settings
   screens remain escape hatches, not the primary UX.

4. Trust is visible.
   Every privileged bridge action has an obvious status, receipt, and policy
   state. Raw notification payloads and action surfaces remain gated unless an
   explicit policy changes.

5. Backend swappable.
   The shell must run on an Android fullscreen system-app backend first, then
   allow a future Wayland/Phoc/DRM backend without rewriting the interaction
   model.

## System Layers

### Layer 1: Shell Surface

Responsible for what the user sees and touches.

MVP surfaces:

- Home workspace
- Running sessions
- App shelf
- Files/recent documents
- Trust and approvals
- System health
- Notifications summary

The shell should be fullscreen and visually distinct from Android. It should not
use Android card-list diagnostics as its main layout.

### Layer 2: Shell Runtime Adapter

Responsible for turning user intent into backend actions.

Initial adapters:

- `RootLinuxBridgeProvider` for receipt/status/mode calls
- display bridge launcher for Linux GUI sessions
- Android package inventory from `BridgeStore`
- share ingress events from `ShareIngressActivity`
- notification listener policy/status, counts only for now

New adapter shape should expose app/session concepts:

- `launch_profile`
- `session_id`
- `display_backend`
- `state`
- `url_or_surface`
- `receipt_path`
- `stop_supported`
- `last_health_check`

### Layer 3: Display Backend

Responsible for pixels and input.

Backends:

- `android-fullscreen`: first implementation, a fullscreen privileged system UI
  using Android SurfaceFlinger only as a compositor substrate.
- `android-webview-novnc`: acceptable implementation detail for Linux GUI app
  sessions, hidden behind Shell session controls.
- `wayland-phoc`: future backend once VT/seat/DRM ownership is solved.
- `drm-native`: high-risk future backend that requires boot-time display
  ownership, rollback design, and panel recovery evidence.

### Layer 4: Root Linux Application Plane

Responsible for actual Linux applications.

Initial profiles:

- `writer`: LibreOffice Writer
- `calc`: LibreOffice Calc
- `terminal`: root-Linux terminal
- `files`: file manager
- `browser`: Linux browser if packaged later

Each profile must define package prerequisites, launch command, health probe,
stop behavior, data directory policy, and visible shell label.

## What To Retire

The existing `CommandCenterActivity` should not remain the product UI. It should
be renamed conceptually to a debug/admin console or replaced by Shell screens.

Keep:

- provider contract
- store
- receipt readback
- bridge trigger path
- display bridge scripts
- notification policy boundary

Retire from main UX:

- vertically stacked diagnostic cards
- Android-style buttons for bridge internals
- exposing property names as user-facing UI
- launching Browser as the visible product step
- treating receipts as the primary screen content

## MVP Shell Layout

### Visual Language

The shell should read as an operating workspace, not a settings app.

- Use a full-screen workspace canvas with a persistent navigation rail or bottom
  switcher depending on width.
- Use compact app tiles for launch targets, not large Android preference cards.
- Use session strips for running work: app icon/name, backend, health, open/stop.
- Keep debug receipts behind details panels.
- Prefer direct verbs: Open, Resume, Stop, Files, Trust, System.
- Avoid exposing Android package names, init property names, noVNC transport
  names, or receipt paths on the main screen.
- Keep status visible but quiet: online, running, blocked, attention required.

Portrait phone target:

- top: workspace title and system health line
- middle: active sessions and recent documents
- bottom: app/profile launcher and navigation

Landscape/desktop target:

- left: navigation rail
- center: workspace/session content
- right: details/trust inspector

### Home

Primary content:

- current workspace title
- running Linux sessions
- recent documents
- pinned app profiles
- compact bridge health

Primary actions:

- open Writer
- open Calc
- open Terminal
- open Files
- stop inactive sessions

### Sessions

Shows active Linux/Android sessions:

- app name
- backend (`Xvfb/noVNC`, `Wayland`, `Android`)
- running/stopped/error
- last receipt
- stop/open controls

### Apps

Shows apps by plane:

- Linux
- Android compatibility
- system tools

Linux profiles should be curated. Android inventory can be searchable but should
not dominate the first screen.

### Trust

Shows only policy state and pending approvals:

- notification listener is user-controlled and disabled by default
- action surfaces disabled unless explicitly enabled
- broker privacy boundary
- receipt health

### System

Shows diagnostics and receipts. This is where the old Command Center behavior
belongs.

## Implementation Plan

### Phase 0: Lock the UI Contract

Create a stable shell contract before code churn:

- shell surfaces and names
- app/session state model
- launch profile schema
- backend adapter names
- policy labels
- visual non-Android constraints

Output:

- `Trillionnium Shell UI Architecture v1`
- session/profile schema draft
- migration map from old Command Center modes to shell actions

### Existing Mode Migration

| Existing mode | Product UI destination | Notes |
| --- | --- | --- |
| `prepare` | System > Runtime setup | Debug/admin action, not first-screen content |
| `command-center-help` | System > Diagnostics | Keep as command reference |
| `bridge-readiness` | Home health line + System details | Main screen shows summary only |
| `bridge-gates` | Trust > Gates | Expose blockers as user-facing state |
| `bridge-evidence` | System > Evidence | Receipt/debug only |
| `daemon` | System > Runtime service | Lifecycle control, not a user app |
| `display-libreoffice` | Apps > Writer profile and Sessions | Main user flow is Open/Resume/Stop Writer |

### Phase 1: Android-Hosted Shell Prototype

Build a fullscreen privileged shell Activity that becomes the user-facing entry.

Constraints:

- no Android launcher-style vertical diagnostic feed
- no property names on main screens
- no Browser/noVNC branding in normal flow
- Linux app profiles shown as native Trillionnium app entries
- receipts available from details/debug only

First dogfood path:

1. Tap Writer in Trillionnium Shell.
2. Shell triggers `display-libreoffice`.
3. Shell waits for session health.
4. Shell opens the session surface.
5. Shell can return to Home and stop/reopen the session.

### Phase 2: Bake Runtime Dependencies

Move live rootfs GUI dependencies into the baseline rootfs/archive:

- LibreOffice writer/calc
- `libreoffice-gtk3`
- MIME cache generation
- Xvfb
- openbox
- x11vnc
- noVNC
- websockify
- x11-utils/xauth

Also make Browser/network-loopback policy durable or replace Browser with an
owned WebView/noVNC container inside Shell.

### Phase 3: Session Lifecycle

Replace one hardcoded `display-libreoffice` mode with profile-based lifecycle:

- `display-start <profile>`
- `display-status <session_id>`
- `display-stop <session_id>`
- `display-list`

The init/provider path can remain property-backed initially, but the public
contract should be session-oriented.

### Phase 4: Backend Feasibility Track

Only after the shell is useful, pursue native display ownership:

- read-only DRM/VT/seat/input inventory
- SurfaceFlinger ownership map
- rollback path before stopping Android UI
- secondary/virtual backend tests first
- Phoc/DRM proof only after recovery path is written down

This track should not block Phase 1.

## Acceptance Gates

The shell redesign is not accepted until:

- first screen is Trillionnium Shell, not Android Launcher/Browser
- Writer opens from Shell as a Trillionnium app profile
- session can be reopened without retriggering broken duplicate servers
- session can be stopped from Shell
- status survives return-to-home/resume
- receipt/debug data is still accessible
- no raw notification payloads are exposed
- action surfaces remain gated
- readiness remains PASS
- screenshot proves the new UI does not look like the old Command Center cards

## Immediate Next Code Gate

Build `TrillionniumShellActivity` or a renamed replacement for
`CommandCenterActivity` with these minimum screens:

- Home
- Sessions
- Apps
- Trust
- System

The existing provider/store stays intact. The first integration target is the
already-proven LibreOffice display bridge.

The initial OTA should be a UI-only change plus lifecycle controls. It should
not attempt native Phoc/DRM in the same gate.
