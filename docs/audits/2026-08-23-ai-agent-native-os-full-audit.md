# Trillionnium OS AI-agent-native architecture audit

**Date:** 2026-08-23 (Asia/Shanghai)  
**Scope:** canonical control repository, Android `lineage-fogos` target metadata and
the attached dogfood device `ZY32JLVHGN`.  This was a read-only audit. Existing
modified and untracked files were preserved; no product package, key, device
setting, partition or boot state was changed.

## Executive verdict

The product direction is internally coherent and matches the stated AI-agent-native
design: Codex is the single built-in agent, inference is off-device, Codex chooses
and invokes tools, and Android owns transport credentials, SELinux/cgroup/capability
policy, risk gates, deadlines, audit and recovery. That direction is documented in
`README.md`, the 2026-08-06 direct-shell/ADB ADR and the v2 machine-readable
boundary contract.

The implementation is **not yet a qualified AI-agent-native OS runtime**. It is a
source/host-conformance prototype with a successful local userdebug dogfood OTA.
Through the currently authorized shell observer, no Root-Linux daemon, built-in
Codex host, or Codex turn/effect receipt was observable.  A later bounded read-only
probe did see the expected Android-side abstract sockets
`@trillionnium-agent-gateway-v1`, `@trillionnium_system_api`, and
`@trillionnium_system_api_replay_control`, plus the `org.trillionnium.aishell`
process.  Socket presence and an APK process do not prove authenticated peer
ownership, Root-Linux activation, a live Codex client, or a durable effect.  SELinux
also prevents the shell observer from reading several labelled runtime properties
and files, so this remains an observation boundary, not a claim of absolute
absence. Direct ADB has a typed admission/wire contract but its production
transport and OS key custody are deliberately fail-closed. The Windows result is correctly
“research-only, absent from every product variant,” not an incomplete product
feature.

The useful distinction is:

| Surface | What is real now | Qualification |
| --- | --- | --- |
| Codex identity / off-device inference | Source registry, UID/GID, SELinux identity and boundary contracts | Source pass; no device turn |
| Agent Host / turn lifecycle | Wrapper, init choreography and Android-side sockets/APK | Device hold: no Root-Linux host, authenticated peer/effect |
| Android System API | Compiled source path and typed request/receipt logic | Static/source pass; physical ACK/replay hold |
| Accessibility | APK, listener, peer/SELinux and replay source contracts | Not operationally closed; no bound service/epoch sync |
| `shell.exec.v1` | Root-Linux broker/worker, bounded output and recovery source path | Device broker/effect/restart hold |
| `android.adb.*` | Typed request/admission/codec tests | Transport/listener/key custody hold |
| Root Linux | Minimal Bookworm/headless artifacts and init policy on host | No device mount/daemon/high-water/turn |
| OTA | A/B dogfood write, slot switch, postinstall and merge verified | `userdebug`/`test-keys`, orange/unlocked; not release |
| WindowsCompat | Absence contract and research tombstones | Intentionally not implemented |

This is consistent with the repository's own release boundary: a real Codex turn,
a durable System API plus shell/ADB effect, cancellation/restart/reboot/power-loss
replay, and one clean source/BOM/target-files/signed-OTA identity are still required.

## Evidence reviewed

- `README.md:3-20,27-48,63-80` — canonical Codex-only graph, OS custody and
  explicit P0/non-release status.
- `docs/CURRENT_STATE.md:32-48,63-103,123-158,181-208` — inert ADB boundary,
  source/host test results, qualification table and release holds.
- `docs/architecture/2026-08-06-codex-native-direct-shell-adb.md` — accepted
  direction, implementation hold, and explicit Windows deferral.
- `docs/contracts/agent-exec-adb-windows-product-boundary-v2.json` — Codex owns
  tool invocation; OS owns effects; ADB not implemented; Windows absent.
- `crates/trillionnium-agent-direct-tools/src/adb_transport_boundary.rs:1-13,33-38`
  — source-only boundary and `ProductionAdbTransport::new()` fail-closed HOLD.
- Android target metadata under the old
  `out/target/product/fogos/` path — a **stale** (2026-08-07/11) metadata record
  describing a fresh headless v6
  archive plus P01 overlay, with explicit
  `agent_accessibility_epoch_activation=absent_product_hold`,
  `agent_accessibility_replay_sync_binary=absent_product_hold`,
  `agent_adb_transport=unavailable_fail_closed`, and `p01_release_allowed=false`.
- Android init choreography
  `vendor/trillionnium/prebuilt/common/etc/init/init.trillionnium-system_ext.rc`
  — prepare/quarantine, measured mount, high-water → shell broker → daemon
  sequencing and fail-closed stop paths.
- `docs/evidence/2026-08-23-internal-dogfood-ab-ota.md` — local A/B OTA only;
  it does not promote production authority.
- `docs/evidence/2026-08-23-accessibility-live-adapter-snapshot.md` — reversible
  probe restored `null/0`; no bound service, v2 snapshot, replay receipt or ACK.
- `docs/audits/2026-08-06-ai-agent-native-os-full-audit.md` — historical asset and
  module inventory used to classify stale material, not to infer current readiness.

Semantic memory search was unavailable in this run (embedding/provider timeout),
so prior decisions were cross-checked directly against the workspace memory files,
the canonical documents above and current source/target metadata.

## Device-side reality after the dogfood OTA

The bounded read-only probe after the A/B update recorded:

- `_a`, `sys.boot_completed=1`, incremental `1786679844`;
- `ro.build.type=userdebug`, `ro.build.fingerprint` still userdebug/test-keys,
  Verified Boot `orange`, device state `unlocked`;
- `SELinux=Enforcing`;
- no `trillionniumd`, `agentd`, `codex` or `root-linux` process was visible to
  the shell observer;
- a bounded `/proc/net/unix` read did show the Android-side abstract endpoints
  `@trillionnium-agent-gateway-v1`, `@trillionnium_system_api`, and
  `@trillionnium_system_api_replay_control`; their owning peer, authenticated
  UID/domain, request/receipt exchange and durable replay state were not proven;
- no Root-Linux/Trillionnium mount was visible in the shell-readable
  `/proc/mounts` view;
- the shell observer could not read the labelled
  `ro.trillionnium.agent_ready`, `sys.trillionnium.rootlinux.prepare`,
  `sys.trillionnium.agent_egress_guard` or `sys.trillionnium.operation_replay`
  properties (empty output is not treated as a definitive value);
- APK presence (AiShell, AiAuthority, Accessibility, updater and lease issuer)
  was observed, but installed APKs and Android-side sockets are not evidence of
  a live Root-Linux Codex turn.

The audit keeps four layers separate: source graph, generated metadata,
target-files/ZIP contents and live device state. The old
`out/target/product/fogos` directory is not a fresh product payload:
`manifest.txt` is timestamped 2026-08-07 and `.installable_files` 2026-08-11,
and its `system_ext` tree lacks the runtime binaries. The active named OUT,
`out/target/trillionnium-userdebug-v28-standard-relative-20260814.9YHOOi/`,
does contain the declared Root Linux, agentd, Codex, System API, Accessibility,
ADB and shell binaries, but its runtime files are from 2026-08-14 while the
source `Android.bp`/`common.mk` graph changed on 2026-08-21. That mixed-generation
state still fails freshness qualification. The dogfood OTA used a separately
staged and verified package; its successful slot switch does not repair this
source→BOM→target-files binding gap.

The fresh dogfood artifact is instead under
`out/target/trillionnium-userdebug-v28-standard-relative-20260814.9YHOOi/internal-dogfood-ota/`:
1,356,454,975 bytes, SHA-256
`a993dddefb4d8a909f1d804ac61aaa9a50423347837f2fb4ca131d4d8ed64af5`. It contains
the A/B payload and metadata, not an extracted target tree. Its source commit,
target-files receipt and manifest are not currently bound by one freshness ID;
that binding is a release-critical gap.

There is also a build-consistency warning: `ro.build.type=userdebug` coexists with
`ro.debuggable=0`. This needs an explicit product/BOM decision and a clean rebuild;
it must not be “fixed” by setting a property on the phone.

## Root Linux and Android findings

### What is implemented

The host graph contains a minimal Bookworm ARM64/headless artifact, manifest hashes,
SELinux labels, capability/cgroup/seccomp scaffolding, a Root-Linux runner and a
one-shot init choreography. The source System API path can call the Codex planning
adapter with cancellation, and the shell broker has source-level effect-first
receipt/recovery behavior.

### What is missing

The stale target manifest advertises a fresh v6 archive **and** a P01 overlay with
standalone and overlay transaction roles. The active named OUT also contains the
declared runtime payloads, but no single freshness identity currently binds those
bytes to the current source graph and target-files. This is a valid conformance
staging surface, not proof of one active runtime. The manifest itself records
absent Accessibility replay-sync, unavailable ADB transport, device-evidence
holds and release disallowance.

Before any cleanup or release claim, generate a freshness-bound BOM recording the
build ID, manifest digest, target-files digest and existence/hash of every listed
file. Release/preflight tooling should reject stale metadata or missing listed
payloads instead of treating a manifest as an installed runtime.

The init design is security-conscious: `prepare=1` stops/quarantines old paths,
then `prepare=0` mounts measured payloads and waits for high-water, shell broker and
egress guard before starting the daemon. The bootstrap source does contain the
intended root-owned producer (`publish_rootlinux_prepare_complete`), which sets
and reads back `sys.trillionnium.rootlinux.prepare=0` only after the staged
payload, manifest, labels and migration checks pass. What is still missing is a
restricted, freshness-bound observer receipt proving that this producer actually
ran in the current target and that the resulting Agent API socket/effect path is
live. The shell observer cannot read the labelled state needed to establish that
fact. Manually forcing properties or using host ADB would bypass the producer and
hide the lifecycle defect.

The rootfs admission v4 contract still has explicit identity-independence and
materialization holds. The source bootstrap also contains source-only/legacy
contract markers. Rebuild one exact source → archive → ELF → manifest → target-files
chain before deciding which overlay binaries are retired.

### Direct ADB and Accessibility

`android.adb.*` currently stops at typed parsing, OS admission and in-memory/UDS
codec tests. There is no product listener, socket connector, `adb` launcher,
fastboot path or private-key container in the transport boundary; the engineering
`trillionnium-agent-adb` binary is an adapter, not OS-held-key product transport.

Accessibility has a stronger source surface (user consent, peer checks, SELinux and
TRACSC01 replay ledger), but the target manifest says the replay-sync binary and
epoch activation are absent. The live probe temporarily selected a service, saw
pending binding, then restored the original `null/0`; no production effect or ACK
was generated.

### Durability and migration risks

The source contracts are careful about duplicate effects, but bounded-state
behavior still needs a product policy. The current shell ledger permanently
rejects after its configured 30-entry limit, while the direct-operation journal
can fill its 128-entry bound and cancellation tombstones are not compacted.
Older readers are not automatically compatible with every v3 enum change, and
the provider-terminal/UI receipt plus outer-ACK coordinator has a teardown window
across crash/reboot. These are P0 operational issues for a long-running agent,
not reasons to add more evidence-only types: define compaction, migration and
restart-coordinator semantics and test them on-device.

## Windows status

WindowsCompat is intentionally absent from all product variants. The v2 contract
and the Android absence test both pass; there is no Soong runtime/install module,
init service, product package, stable typed API or device evidence. Historical
Wine/QEMU research bytes must remain outside target-files. The tombstone for the
retired ~237 MB archive should be retained until its recoverability/hash is audited.
Do not restart Windows work until the Android Codex turn/effect/replay loop is closed.

## Hygiene, redundancy and cleanup classification

No deletion is authorized by this audit. The safe classification is:

1. **Archive now (after a hash manifest):** `docs/mobile-smoke/` (362 files of
   Mobian/Phosh/Waydroid/old fastboot research), superseded dual-Agent ADRs and
   obsolete v42/v66/v68 hotpatch receipts. Keep a short index/tombstone.
2. **Keep out of product inputs:** old Mobian/rootfs GUI records, Wine/QEMU
   research payloads, old Command Center/Shell package records and any prebuilt
   identity-bearing ELFs. Rebuild from a fresh allowlist rather than patching an
   old archive.
3. **Refactor, do not delete:** split the large domains in
   `apps/trillionniumd/src/android_agent_api.rs`,
   `crates/trillionnium-tool-runtime/src/supervised_codex.rs`,
   `crates/trillionnium-agent-direct-tools/src/operation_journal.rs`,
   `apps/trillionniumd/src/direct_operation_custody.rs` and
   `apps/trillionniumd/src/context_memory.rs` into protocol, state-machine,
   custody/high-water and receipt/replay modules.
4. **Resolve duplicate runtime artifacts by generated BOM:** decide whether
   `trillionniumd`, `trillionniumd-p01-core`, `trillionniumd-wrapper`, duplicate
   Codex/System API/replay paths and debug ADB helpers are active, compatibility,
   or test-only. Do not remove any until an install/dependency map proves it.
5. **Preserve migration/tombstone/negative-test paths:** old OpenClaw unmounts,
   retired rootfs admission v1-v3 schemas and absence tests are safety barriers
   until one real OTA → reboot → residual scan is recorded.
6. **Fix the stale test, not the crate:**
   `tools/tests/test_retired_legacy_surface_absence.py` rejects the substring
   `trillionnium-shell`, which falsely matches the legitimate
   `trillionnium-shell-exec` member. Use the same token-boundary rule already used
   by `tools/production_agent_feature_gate.py`; deleting `shell-exec` would damage
   the current source graph.
7. **Rename later, with migration:** `tools/mobian_toolchain_snapshot.py` is still
   imported by active builders. Rename to a provider-neutral API only after moving
   imports/tests. Do not delete it now. Likewise keep the typed-exec foundation,
   replay-sync static package and provider bootstrap until their consumers are
   explicitly merged or archived.
8. **Ignored build output:** `target/` (~6.3 GB), the foundation target (~364 MB)
   and Python caches are not product BOM. Once no build is running, clean them via
   a recoverable, explicitly scoped operation; never confuse this with source
   cleanup.
9. **Separate host residue from product evidence:** local audit SQLite WAL/SHM and
   stopped Waydroid bridge data, plus the still-running generic Waydroid container
   manager, are not Trillionnium Agent authority. Register and isolate them (or
   stop/archive after checking unrelated user workflows) so future probes cannot
   mistake them for the OS runtime.
10. **Constrain Android source discovery:** the sibling `trillionnium-os/` tree
    contains archive/browser/command-center/design/fixtures/probes/tools material
    and a historical `target` symlink. Keep these behind an explicit allowlist;
    do not delete them in place before dependency and residual-OTA checks.

## Recommended implementation order

1. Record one current release identity (`v28` dogfood target; `v27` host/static
   predecessor; v66/v68 retired history) and generate a single active BOM.
2. Fix the stale legacy-surface test and any build-type/debuggable mismatch in
   source/BOM; rerun source contracts.
3. Build one real authenticated activation path: measured rootfs mount → egress
   guard → high-water → shell broker → daemon → Agent API socket; expose its
   restricted observer receipt (including the freshness-bound target identity),
   then prove one Codex turn and one Android System API effect with durable
   ACK/replay.
4. Implement the OS-owned local ADB transport and key custody as a separate,
   explicitly labelled engineering/dogfood profile first; keep host ADB diagnostic
   tooling out of the product authority catalog.
5. Add the Accessibility replay-sync product binary/epoch adapter and physically
   test cancellation, timeout, daemon restart, reboot, power loss and exact replay.
6. Rebuild the fresh rootfs and all common/P01 binaries from the same source/BOM,
   remove only artifacts proven compatibility-only, then run the release gate and
   signed OTA workflow.
7. Keep Windows research-only until the Android loop is qualified; retain only its
   small absence contract and recoverable research tombstone.

## Bottom line

The architecture is on the right track, and the refusal to run a phone-local LLM
is correct. The project is not yet “an agent inside the OS that can directly drive
the phone” in the operational sense: it is a well-specified, security-conscious
source/static prototype whose runtime authority is still intentionally disabled.
The next milestone is not more APKs or more typed contracts; it is one measured,
device-observable Codex turn with a real System API/shell effect, durable replay,
and a generated single BOM. Only after that should compatibility material be
retired and release/OTA claims be expanded.
