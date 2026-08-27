# Trillionnium OS AI Agent Native Progress Audit after P0.14

Date: 2026-07-23

This is a point-in-time architecture and implementation audit. It does not
replace `docs/CURRENT_STATE.md` or the accepted Direct Agent Native ADR.

## Audit definition

The product is evaluated as an Android-based AI Agent Native OS with these
non-negotiable properties:

- provider inference is currently off-device; a phone-local LLM is neither a
  requirement nor a release gate;
- Codex, OpenClaw and future approved Agents are built-in, independently
  measured OS principals;
- the OS hosts Agent turns and owns context, egress, resource, policy, journal,
  effect and result custody;
- Agents operate the phone through typed OS-owned tools, not adb, root, generic
  shell, arbitrary Binder or an Android backend identity;
- Root Linux is an Android-managed headless Agent runtime rootfs;
- Windows compatibility counts only when it has a supervised product runtime,
  Agent access path, typed tools and device evidence.

The corpus review covered the canonical README, current state, accepted ADR,
the earlier same-day architecture audit, all current evidence/history indexes,
and a machine scan of the retained documentation/design corpus. The current
repo has 387 text/JSON documentation artifacts, including 362 historical
`mobile-smoke` files. The older Android design tree has 3,401 artifacts and
about 315 MB of data, including 3,141 Command Center iterations.

## Executive verdict

| Boundary | Verdict | Reason |
| --- | --- | --- |
| Product definition | PASS | Built-in measured Agents, off-device inference and OS-mediated phone tools are the canonical design. |
| Direct Agent Host architecture | PASS WITH DEBT | Codex/OpenClaw, descriptors, direct result and tool contracts are real; built-in and generic carriers still use separate transitional dispatch paths. |
| General phone operation | HOLD | Only low-risk launch, metadata observation, scroll and Back/Home are available; `open_uri`, click, text and gesture remain denied. |
| Action lease and effect custody | SOURCE-STRONG, PRODUCT-OFF | P0.3-P0.14 substantially close source contracts, but no live service, trusted inputs, broker-main route, product coordinator, token mutation or ACK authority exists. |
| Root Linux | SOURCE/PRODUCT-CONTRACT PASS, RELEASE HOLD | Rootfs, init, Agent packages and SELinux exist; daemon payload/TCB and clean-build/device gates fail. |
| Windows | NOT IMPLEMENTED | 230.2 MiB of research assets are retained but have no product module, service, Agent path or typed tools. |
| Maintainability | NEEDS REFACTOR | Legacy desktop/Authority code remains in the default workspace and core files are oversized. |
| Device/OTA/release | HOLD | No clean current full build, release artifact, installation or physical Direct conformance exists. |

The most accurate maturity label is **internal Alpha / source-integrated
security prototype**. The architecture direction is qualified; the product is
not yet qualified as a generally operable Agent Native phone OS.

## What is correctly implemented

The canonical product path is coherent:

```text
TrillionniumAiShell
  -> trillionniumd Agent Host
  -> measured Codex or OpenClaw turn in Root Linux
  -> MCP stdio System API / Accessibility tools
  -> Android backends
  -> strict direct result and durable recovery state
```

The vendor product graph includes Codex, OpenClaw, their fixed descriptors,
Root Linux, the daemon and both direct Android backends. Product packaging also
contains an explicit local-model retirement/denylist gate. The two Agents use
separate UID/GID, SELinux, replay and executable identities. Tool calls are
typed and bounded before backend I/O, and the model receives neither an Android
service identity nor generic shell/root authority.

P0.3-P0.14 added a serious source-level action-lease foundation: root task
registration, publication/ACK framing, measured publisher launch, immutable
root authentication, an authenticated proof carrier, clone3/pidfd custody,
exact publisher completion, dual-listener correlation, a private commitment-
only route, concrete socket custody and terminal startup/teardown sessions.
Those boundaries are valuable and should be preserved.

## Why general phone control is still HOLD

The currently allowed product tool subset does not complete a normal
`observe -> click/type -> verify` workflow. `launch_package`, metadata-only
snapshot, scroll and Back/Home are low-risk; `open_uri`, click, set-text,
gesture, sensitive global actions, screenshot and full-text observation remain
denied. The framework `open_uri` implementation still returns
`capability_lease_unavailable`.

P0.3-P0.14 improved source security but did not change that functional fact.
The current root-route family alone now contains 12 contracts, 14 SDK root
classes and 12 broker root/custody source files. There is still no public or
private live broker route in `main`, no runtime factory/service construction,
no packaged replay-sync publisher, no product trust inputs, no token mutation,
no ACK authority and no physical-device proof. Further horizontal contract
growth would increase review and maintenance cost without making the phone
more operable.

Built-in Agents also still enter through an OS-supervised transitional dispatch
port rather than the generic kernel-authenticated Agent UDS carrier. The two
paths intentionally preserve separate trust domains, but their lifecycle and
authentication cores should converge behind a provider-neutral internal API so
that built-in execution is not permanently a special case.

## Root Linux audit

Root Linux is genuinely implemented at source and Android product-graph level:

- init materializes and verifies the rootfs and starts the egress guard first;
- Codex/OpenClaw packages, descriptors and direct tools are product inputs;
- Agent state is separated from read-only runtime/tool mounts;
- the product runner admits only the daemon entrypoint and no generic root-shell
  fallback;
- Agent identities and Android backends have explicit SELinux policy.

It is not release complete:

- the checked-in rootfs archive hashes to
  `7a3e8f14dedd6e58acdb87b2d9dfee333af625149a99540db2201d86ddb9de9f`;
- its embedded daemon is the stale `5723e663...` payload while the product pin
  requires `d315bc06...`, so the verified Soong extraction gate correctly
  fails closed;
- the current production-TCB test fails because the archive exposes only
  `libc.so.6` and `libm.so.6` in the observed dependency closure;
- the newer `83f2f4ee...ae3f9` AArch64 candidate came from dirty source and is
  not a refreshable production artifact;
- the long-lived daemon still runs as root/coredomain/mlstrustedsubject with
  CHOWN, KILL, SETGID, SETPCAP, SETUID and SYS_CHROOT. This remains the largest
  privileged TCB and should be split so the Agent Host is non-root and only a
  minimal broker retains narrowly reviewed privilege;
- there is no clean current full build, target-files/OTA, installation or
  physical Agent conformance.

## Windows audit

Windows compatibility is not implemented as a product capability. The vendor
tree retains 61 files and 230.2 MiB of Wine/QEMU-related archives, licenses and
historical scripts. The all-variant absence contract passes: these assets have
no install/runtime Soong module, init service, product package or inherit path.

They also have no AgentDescriptor, measured supervisor, typed launch/inspect
tool, signed app allowlist, or defined file/clipboard/display/audio/network/
recovery/update semantics. The correct product claim is **research custody
only**. If Windows is not a near-term requirement, move these bytes out of the
active vendor tree and retain only an immutable manifest plus external archive.
If it remains required, restart it as a small supervised service exposed
through the same lease/journal/evidence model; do not expose Wine shell scripts
directly to an Agent.

## Redundancy and cleanup findings

The default Rust workspace still includes large superseded product surfaces:

- Command Center: about 69,109 lines;
- Shell: about 33,890 lines;
- Bridge protocol: about 7,165 lines;
- D-Bus/legacy service crate: about 4,576 lines;
- legacy Authority receipt implementation: about 3,116 lines.

Command Center, Shell and Bridge alone total about 110,000 lines and are not
the current Android Direct product UI/runtime. They should not remain default
workspace members. Mobian packaging contributes another 287 tracked files.

`trillionniumd` still imports `trillionnium_dbus::AgentService` in its normal
binary. That crate now mixes useful Agent lifecycle/state with a retired D-Bus
and Authority history. Extract the production-neutral control service into a
new crate, then move actual D-Bus and legacy plan/effect code out of the product
dependency graph.

The main maintainability hotspots are `android_agent_api.rs` (~13,967 lines),
`context_memory.rs` (~12,418), and `supervised_codex.rs` (~10,314). OpenClaw
also imports substantial Codex-named supervision code. Split a provider-neutral
process/lifecycle/egress core from Codex/OpenClaw adapters, then split Android
host code by invocation, context, direct result, egress, recovery and UI
transport.

Mechanical storage/framing logic is repeated across System API replay,
Accessibility replay, capability-lease ledgers, token registry, operation
journal and broker stores. Merge only canonical JSON, bounded framing,
atomic-write/fsync/rename, safe-path metadata checks and generator tooling.
Keep trust-domain ledgers, identity namespaces, risk policy and replay authority
separate.

Repository hygiene remains a release blocker. Current dirty/untracked counts
are 74 control-plane, 97 SDK, 6 AiAuthority, 9 AiShell, 21 vendor and 8 SELinux.
The immutable cross-repo freeze created before P0.2 is valuable recovery
evidence but does not include P0.3-P0.14, so it is no longer the current
reproducible baseline. A new freeze is required before any build/payload work.

## Recommended development order

### P0: turn the existing source into one real phone effect

1. Freeze new lease/root-route schemas unless an integration defect proves a
   missing field. Do not add another readiness protocol merely to restate P0.14.
2. Use the existing contracts to complete one end-to-end `open_uri` vertical
   slice: trusted producer, root publication, private route, consumer, exact
   backend result, ACK, replay/restart and durable evidence.
3. Replace the stale rootfs daemon with two clean byte-identical AArch64 builds,
   satisfy the TCB verifier and refresh product pins through the existing
   builder/high-water ceremony.
4. Reduce the long-lived root daemon: move launch/cgroup/credential operations
   into the minimal privilege broker and run the Agent Host unprivileged.
5. Build the full product and run physical Codex/OpenClaw conformance, including
   response loss, restart, replay, ENOSPC, power loss, rollback and privacy.

### P1: make the OS natively useful and maintainable

6. Expand semantic System APIs before Accessibility: foreground/window state,
   intent resolution, allowlisted settings, notifications, documents/media and
   shares. Keep Accessibility as the third-party UI fallback.
7. Extract provider-neutral Agent supervision and production Agent control
   state; remove D-Bus/Authority/Hepta dependencies from the default product.
8. Set minimal workspace `default-members`; move Command Center, Shell, Bridge,
   Mobian and legacy conformance into a separate compatibility workspace.
9. Generate Java/Rust/JS/Python vocabulary and golden vectors from reviewed
   contracts while preserving independent trust-domain verifiers.

### P2: reduce historical and research noise

10. Archive the 3,141 Command Center design iterations, 362 mobile-smoke files
    and superseded Mobian material behind immutable manifests.
11. Choose Windows explicitly: a small supervised product service, or external
    research archive. Do not leave 230 MiB of inactive runtime assets in the
    active vendor source indefinitely.

## Final qualification

Trillionnium has a valid Agent Native OS architecture and substantial security
engineering. It does not depend on a local phone LLM, and Codex/OpenClaw are
correctly modeled as built-in OS Agents. The current implementation is not yet
qualified as a generally operable Agent Native phone because sensitive effects,
Root Linux release artifacts, privileged-TCB reduction and device evidence are
unfinished. Root Linux is source-integrated but release-HOLD; Windows is not
implemented; the largest immediate risk is continuing source-only protocol
expansion instead of finishing one real, measured phone-action vertical slice.
