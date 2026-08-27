# Trillionnium OS Current State

Last updated: 2026-08-27

Status: **owner-open Codex direction is canonical; the current userdebug image
has a working Android build/install substrate but the live Codex-to-shell/ADB
turn is still being implemented. This page contains historical source and
release observations; the owner-open plan below supersedes older semantic
Authority/approval wording. The image is not a public release.**

This is the concise canonical status page. The full evidence-backed audit is
[`audits/2026-08-06-ai-agent-native-os-full-audit.md`](audits/2026-08-06-ai-agent-native-os-full-audit.md).
The current architecture decision is
[`architecture/2026-08-06-codex-native-direct-shell-adb.md`](architecture/2026-08-06-codex-native-direct-shell-adb.md),
with the machine-readable boundary in
[`contracts/codex-sovereign-direct-tools-v1.json`](contracts/codex-sovereign-direct-tools-v1.json).
The older v2 file is retained as a transition record.
Earlier dual-Agent and typed-only shell/ADB documents are historical and do
not describe the current product direction.

## 2026-08-27-r3 owner-open supersession

The active implementation direction is
[`TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md),
revision 2026-08-27-r3. Codex is the only semantic control plane and may
directly issue arbitrary shell and ADB commands. The Android substrate supplies
only launch, IPC, process/transport, storage, watchdog and recovery mechanics;
it does not insert an Authority, risk classifier, approval UI or typed
allowlist. Older entries below that describe those layers as mandatory gates
are historical observations of the pre-r3 implementation and are not current
sequencing instructions.

The plan's §8.1 is the current closeout handoff: the planning/contract package
is fixed, while the integrated owner-open graph, real ARM64/transparent ADB and
same-turn device effect remain implementation work. Its `IMPLEMENTATION NEXT`,
`NOT CLAIMED` and `DEFERRED` labels are status markers only; none is a
developer-bootstrap or direct shell/ADB denial gate.

The latest owner-authorised dogfood device observation is ZY32JLVHGN, slot _a,
incremental 1787707748, SELinux Enforcing, Accessibility bound, the legacy
Agent/System API/replay sockets listening and USB reverse networking available.
Those sockets belong to the previous image graph and must disappear from the
next owner-open product. This proves build/transfer/install/startup substrate
only. It does not yet prove
that a live Codex turn executed a physical shell/ADB effect. Release signing,
AVB/rollback and public-release claims remain separate release work.

The dirty source tree also contains typed ADB tiers, confirmation fields,
ProductionAdbTransport HOLDs and a restrictive supervised Codex launch. Those
are pre-r2 migration/sealed-profile material. They are not evidence that
owner-open direct ADB or shell is implemented and must not be linked into the
default path. In particular, AOSP's ordinary `packages/modules/adb` client
target is host-only, while the existing AArch64 `trillionnium-agent-adb` ELF is
the typed BackendUnavailable adapter rather than platform-tools `adb`; W3 still
needs a real ARM64 userspace client or byte-transparent relay.

The selected AOSP graph is additionally non-converged at the platform SDK
closure: unconditional `org.trillionnium.platform(.internal)` edges remain in
framework/services and common apps, and framework source/resource consumers
still import Trillionnium identity/settings/keys classes. Removing an Authority
APK alone will not remove that compile-time closure. The owner-open profile must
split/profile-gate or replace every edge and consumer, then verify Soong
`module-info`, framework/service/app classpaths and target-files as specified in
§5.2 of the plan. This is an integration work item, not a reason to block the
developer bootstrap lane.

All dated checkpoint sections below are historical snapshots unless a section
explicitly says `r3 owner-open` (or is labelled as the earlier `r2 owner-open`
supersession). They document why old source and release artifacts exist; they do
not override the active plan or create a startup, shell or ADB gate.

## 2026-08-22 source checkpoint (no device write)

The canonical source tree now contains a source-only fixed Settings vertical
slice: the OS authors the operation identity, persists `PREPARED` before the
backend callback, publishes independently validated receipt/ACK artifacts, and
reopens to byte-exact replay without a second Android effect. Ambiguous
backend outcomes become a durable `HOLD` and are never retried automatically.
The test-only System API UDS seam proves this route through a bounded local
backend with one effect across drop/reopen.

The source also contains an inert typed `android.adb.*` contract separated from
`rootlinux.exec.*`, with OS-selected device binding, finite key-generation
rotation and graduated permission tiers. Model/provider input has no private-key
field or transport selector. This is a contract and test surface only: no ADB
transport, hardware rollback anchor, or production key custody is enabled. The
new source-only `adb_wire::transport_boundary` layer now makes that HOLD
explicit: an OS-owned trait receives only an admitted typed request, a bounded
in-memory broker rejects conflicting/retried identities, and a UDS codec test
uses `UnixStream::pair()` without creating a listener. `ProductionAdbTransport`
has no constructor path and returns the fixed production HOLD marker.

The source tree also carries a read-only Android release/flash preflight at
`packaging/android-release-gate/verify_android_release.py`. It refuses
userdebug/eng or test/dev-key target files, empty OTA key material, missing or
digest-mismatched signed metadata, and missing exact hardware anti-rollback
evidence. It never signs, invokes ADB/fastboot, opens private-key paths, or
writes an input. The preflight is a release gate, not flash authorization.

AiShell's source contract additionally checks the UI-only capability-lease
delivery acknowledger: an issuer-produced indeterminate result must contain
exactly five fields and a verified tuple digest before the broker ACK call;
status recovery is issuer-package-only. Capability-lease trust enrollment,
KeyMint/rollback proof, and the measured Accessibility adapter remain HOLD.

The connected device still runs an older incremental than the current target
files, and the available target files are userdebug/test-key material with an
empty OTA key list. Direct-host/shell services and sockets are not running on
the device. Therefore this checkpoint does not authorize a flash, reboot,
production lease enrollment, Accessibility closure, formal signing, rollback
claim or OTA claim.

## 2026-08-23 safe-order checkpoint (source/host only; no device write)

The current continuation follows the requested order. First, the allocator now
exposes a borrowed, non-serializable `VerifiedAllocatorCommitForAndroidAck`
seam. It reconstructs the exact persisted `AdapterPrepared` receipt, binds the
provider attempt, adapter ordinal, journal sequence, canonical request and
backend-request digests, and rechecks the record before accepting an outer
ACK/replay correlation. Tamper and restart/replay coverage is recorded in
`docs/evidence/2026-08-23-production-allocator-android-ack-replay-source-audit.md`.
The product allocator/listener/high-water flags remain closed and `main` still
does not instantiate a product listener.

Second, the KeyMint/rollback and Accessibility phase remains an explicit HOLD.
The detached evidence-shape contract at
`crates/trillionnium-os-types/src/capability_lease_android_evidence.rs` checks
the future `user`/`release-keys` target, non-empty OTA keys, issuer/consumer
lineage, KeyMint/Verified-Boot/rollback observations and exact Accessibility
protocol/SELinux/replay/receipt-ACK fields, but it cannot mint authority. The
current v28 target is still `userdebug`/`test-keys`, uses AOSP test AVB keys,
has rollback index 28 only as static metadata, and has no production KeyMint
attestation or Accessibility closure evidence. See
`docs/evidence/2026-08-23-keymint-rollback-accessibility-source-audit.md`.

Third, the ADB boundary remains source-only. The boundary now rejects a
completed result without an explicit exit code and refuses key-generation
rotation away from OS-owned custody. The read-only release verifier also
rejects symlinked evidence parents, AVB argument sets without rollback
indices, and rollback evidence with extra partitions. Rust boundary tests pass
12/12 and release-gate tests pass 13/13; the production constructor and
hardware transport are still unavailable. No real ADB command was sent to the
connected device during this checkpoint; the host daemon was stopped after a
read-only device-presence check.

The final host regression is green for the touched source surfaces:
`trillionnium-os-types` 197/197, allocator 23/23, and
`trillionnium-agent-direct-tools` 283/283. `rustfmt --check`, Python
`py_compile`, and `git diff --check` pass. These are source/host facts only;
they do not satisfy the missing OS-held key, hardware rollback, signed
`user`/`release-keys` BOM, OTA, or device replay evidence. Consequently the
rebuild/sign/OTA step and every flash/reboot/power-loss validation remain
blocked by the same release gate. Windows stays deferred.

## 2026-08-23 blocker-clearance continuation (source/host and read-only device probe)

The allocator phase now has a separate move-only bridge seam in
`apps/trillionniumd/src/android_ack_replay_bridge.rs`. It accepts only the
already authenticated product listener and the borrowed
`VerifiedAllocatorCommitForAndroidAck`; it does not accept paths, digests,
serialized booleans or provider IDs. The Android handoff bit and every product
authority flag remain false, so the bridge returns a stable HOLD and `main`
only declares the module. Its two unit tests pass.

The canonical Android tree now registers a fixed-path, source-only
KeyMint/rollback/Accessibility guard and host contract test. Source shape
checks pass, while the real-tree result is intentionally `HOLD` for software
default KeyMint, missing device-manifest owner and live hardware attestation,
missing OS-owned monotonic rollback producer/counter, and unverified live
Accessibility binding. See
`docs/evidence/2026-08-23-android-security-surface-preflight.md`.

The new read-only BOM preflight at
`packaging/android-release-gate/verify_android_bom_preflight.py` validates the
canonical source-BOM receipt and target-files metadata without invoking a
process or writing an input. Against the current v28 target it returns 17
HOLDs: userdebug/test-keys, AOSP test AVB key path, empty OTA keys, missing
rollback indices on image footer arguments, and absent signed metadata and
rollback evidence. Its combined release-gate suite is 20/20.

After the bridge and guards landed, the full daemon regression completed
`364 passed, 0 failed, 1 ignored`; `trillionnium-os-types` remains 197/197 and
`trillionnium-agent-direct-tools` 283/283. These are host/source results and
do not promote any product authority flag.

A bounded read-only probe of the attached target recorded
`unlocked`/`orange`, `userdebug`/`test-keys`, `UNOFFICIAL`, and no bound or
enabled Accessibility service. A separate reversible TEE keystore probe then
generated a uniquely named temporary key with `keystore_cli_v2 --seclevel=tee`,
returned hardware authorization characteristics, deleted the key, and
confirmed that the alias was gone. This proves a usable TEE-backed
Keymaster/keystore generation path exists on the attached build; it does not
prove a production-trusted attestation chain, locked/green Verified Boot,
hardware rollback high-water, or a KeyMint 4 (400/400) interface. The target
also exposes a running QTI legacy HIDL Keymaster 4.1 process/declaration, but
shell SELinux blocks direct HAL introspection and the project verifier
explicitly does not equate legacy HIDL 4.1 with KeyMint 4 attestation. See
`docs/evidence/2026-08-23-device-tee-keystore-probe.md` and
`docs/evidence/2026-08-23-device-readonly-keymint-accessibility-probe.md`.
This is diagnostic evidence only; it does not authorize shell effects,
signing, OTA, reboot, or flashing. All source and Android-tree dirty changes
remain uncommitted and preserved.

A separate bounded material audit found no configured production release-key or
AVB private-key set in the canonical estate; only the public Trillionnium
certificate and AOSP development/test material are present. Reusing or
renaming development keys would not satisfy the release verifier. See
`docs/evidence/2026-08-23-production-material-audit.md`.

## Product definition

Trillionnium is intended to be an AI Agent native Android OS. The only built-in
Agent is Codex:

- provider: `openai-codex`
- Agent: `agent-codex-direct-v1`
- owner-open execution identity: owner-configured (root is the dogfood
  default; no fixed UID/GID is part of the contract)
- observed pre-r2 identity: UID/GID 5901,
  `u:r:trillionnium_codex_agent:s0` (historical implementation only)

Model inference is off-device. The phone contains the measured Agent runtime,
tool protocol and OS integration, but no local LLM weights or local inference
scheduler.

Codex must call Android System API, Accessibility, shell and ADB as
first-class tools during its own turn. In the owner-open profile, Codex owns
the semantic policy, target choice, consent conversation and recovery decision.
The substrate only supplies process/IPC, transport, storage, watchdog and
out-of-band recovery mechanics. It must not turn direct commands into a typed
allowlist or a hidden approval/Authority hop. This is an owner-dogfood trust
model, not a public multi-user safety claim.

## Qualification summary (historical pre-r2 snapshot)

The table below records the pre-r2 static/source qualification that was true
before the owner-open direct-tool decision. It is not a current owner-open
capability claim or a start gate; the r3 status at the top of this page and the
canonical plan are authoritative.

| Area | Current state | Release status |
| --- | --- | --- |
| No phone-local LLM | Explicit product rule | PASS |
| Codex-only identity and source contracts | Singleton registry and generated SDK contracts | SOURCE PASS |
| Android product graph | Codex-only install/start/manifest graph | SOURCE PASS |
| Fresh helper ELF/daemon/rootfs | The post-retirement v27 A/B shell/raw/launcher/rootfs-v9/final-daemon graph reproduced byte-identically, passed 28/29/29 Soong receipt-stage custody/publication and was consumed by the matching clean target-files/image graph | HOST/STATIC IMAGE PASS; DEVICE HOLD |
| AiShell and the former AiAuthority path | Pre-r2 request/consent/recovery source checks and prompt tuple | HISTORICAL PRE-R2 SOURCE SNAPSHOT; NOT OWNER-OPEN |
| SELinux | The v25 Type-C label failure was corrected minimally. The fresh v27 bp4a graph completed precompiled/full policy construction, and target-files static inspection passed the intended UID/domain/socket/service and retired-payload checks | CLEAN STATIC PASS; DEVICE HOLD |
| Root Linux substrate | Minimal Bookworm ARM64 A/B archive, daemon and manifest are reproducible; no current-device runtime proof | HOST PASS; DEVICE HOLD |
| Production Codex turn | No verified end-to-end turn on the current device | HOLD |
| Direct shell tool | A restrictive standard-only broker/worker scaffold exists; owner-open command-string/argv and live Codex turn are not yet wired | IMPLEMENTATION IN PROGRESS |
| Direct ADB tool | `android.adb.*` source contract exists, but the real ARM64 client/shim and Codex tool path are not yet wired | IMPLEMENTATION IN PROGRESS |
| Windows compatibility | Research assets only; absent from product | NOT IMPLEMENTED |
| Reproducible build/OTA/AVB | v27 proves an exact-clean BOM replay, independent A/B construction, receipt-stage admission, clean target-files/image packages and static verification of 9 AVB images. The rollback index is statically observed as 28 and the image uses known AOSP test keys; formal signing lineage, device rollback behavior, OTA and public release are not proven | HOST/STATIC PASS; RELEASE HOLD |
| Physical reboot/power-loss/replay proof | Not collected | HOLD |

The accurate product statement is:

> **Pre-r2 static/source snapshot only:** the former standard `shell.exec.v1`
> broker/worker and typed ADB boundary were source-tested, but they are not the
> owner-open direct shell/ADB implementation. The current owner-open path is
> still pending a live Codex turn and physical effect; no source receipt,
> static image or old broker result promotes it to that capability.

## Historical pre-r2 — 2026-08-11 `shell.exec.v1` source checkpoint

The first slice is deliberately narrow. AiShell accepts the shell result
classification; every Codex provider invocation obtains and retires a fresh
broker registration bound to the existing DirectOperationBinding; the public
MCP tool accepts exact UTF-8 argv and workspace-only cwd; and the Android
broker/worker source implements durable `NOT_DISPATCHED`, `DISPATCHED`,
terminal and indeterminate outcomes, binary-safe bounded output,
`CLOCK_BOOTTIME` deadlines, disconnect cancellation and immutable receipts.

The product worker is a one-shot UID/GID 5903 process with no supplementary
groups or capabilities. It enters the retained Root-Linux tree with `chroot`,
uses the measured fixed cgroup-v2 memory profile, marks every non-stdio
descriptor close-on-exec with `close_range` before `execveat`, and installs a
default-allow seccomp filter with an explicit dangerous-syscall denylist. The
high-FD custody case is source/host tested. This is not an independent
mount/PID namespace and must not be described as one. The first-slice measured
executable policy is only these seven paths:

- `/bin/echo`
- `/bin/false`
- `/bin/sleep`
- `/bin/true`
- `/bin/uname`
- `/usr/bin/id`
- `/usr/bin/printf`

Path readers, directory/file constructors, interpreters, launchers and
recursive tools are excluded. In particular, `pwd` is excluded so the hidden
per-binding workspace name is not disclosed, and `whoami` is excluded because
the minimal rootfs has no NSS entry for UID 5903.

Source tests cover exact argv without a shell, output budgets, deadline/cancel
boundaries, durable replay and crash states, cross-boot clock handling,
broker/adapter/worker death, cgroup cleanup, retained-path custody, receipt
tamper cases and Android receipt-stage admission. These are source and host
diagnostic results only. The tracked Android HOLD remains
`effect_authority=false`. The three AArch64 shell ELFs, raw/launcher/
final-daemon lanes, v9 rootfs and Android receipt stage were independently
reproduced in the v22 host graph. Device preflight then found that the selected
Android product still installed the legacy privileged-ADB binder service even
though `ro.debuggable=0`. The product package, domain, transition,
service-manager name, data type and adbd/system-server permissions are now
removed. The remaining adbd and framework clients now reject a production
`ro.debuggable=0` build before any lookup of the absent Binder service, so the
expected `adb root` rejection is immediate and does not generate a lookup AVC.
Because these changes alter Android pins, every earlier artifact is historical
and must be rematerialized from a new BOM. No target-files from v22 or v23 may
be built or flashed.

The artifact-builder source also requires an explicit measured
`qemu-aarch64-static` input and performs bounded pre-publication AArch64
start/exit probes for the adapter, broker and worker. Those probes are host
load diagnostics, not target-kernel or device evidence, and QEMU remains a
build-host tool rather than a product payload. The host build-filesystem source
boundary now uses Landlock plus eight independent, exact inherited role FDs
(`cargo`, `rustc`, target linker, host-linker wrapper, Zig, Zig root, immutable
Cargo input and private target). A real Rust 1.95/Zig 0.14.1 fixture proves a
malicious `build.rs` cannot read a BOM-external sentinel, `/etc/passwd` or
`/proc/self/status`, while the positive fixture reaches both the host Zig
wrapper and AArch64 target linker. The 26 builder tests pass without skipping
that toolchain test. This is still source/host-boundary evidence only. The
pre-removal v22 BOM and complete A/B graph prove reproducibility of the path,
but they cannot admit the later Android and control commits. No current
artifact admission claim followed at that checkpoint until the complete graph
was rematerialized; the later v26 and v27 terminals are recorded below.

On the authoritative bp4a product selection, the targeted host suites passed:
the Agent-provider security contract 1/1, AiShell direct-result tests 18/18,
workflow-recovery tests 12/12, shell SELinux contract tests 5/5 and Android
product-wiring tests 8/8. The previous shared output's full
`m selinux_policy` build completed 462/462 actions; it predates the two new
Android pins and is not their build evidence. At that checkpoint a clean
`OUT_DIR`, current policy build, target-files and device execution remained
HOLD. v27 later closes those host/static build items; device execution remains
HOLD.

The result proof has two deliberately separate hash domains. The durable
operation journal retains the SHA-256 of the exact backend response bytes for
replay integrity. After typed validation, the OS independently injects a
domain-separated canonical semantic-result SHA-256 for Codex evidence,
listener reconciliation and outer receipts. Backend responses may author
neither carrier. JSON object key order and insignificant whitespace may change
the raw digest but not the semantic digest; arrays, scalar values and all other
response fields remain significant.

Effect-first receipt liveness is closed at source-test level: after one fully
committed System or shell effect, a later duplicate/generic MCP call, malformed
final output, timeout or provider crash no longer discards an already validated
terminal prefix. Recovery accepts only a complete, sanitized, replay-verified
prefix after child containment, egress teardown and shell retirement are all
proven; error classes are a positive closed set. It never synthesizes evidence
from an incomplete listener commit, broker ledger entry, model final output or
definitely-not-dispatched call. The in-process carrier is not an authenticity
format for externally deserialized data. These tests close the source P0 only;
Stage 2 remains open until the same path produces a physical phone effect and
durable device receipt from a BOM-bound image.

Each P0 shell registration authorizes exactly one effect. Its durable shell
ledger intentionally retains at most 30 effect records and has no compaction;
the 31st permanent history record is rejected. Admission reserves worst-case
copy-on-publish ledger plus receipt bytes on one verified filesystem, but this
finite-history policy is a product-availability HOLD until receipt-backed
retention/compaction is designed.

Separately, the direct-operation journal retains `CancelledBeforeTool`
tombstones in the current v3 durable enum so a cancelled invocation/binding
cannot be silently reused. Those tombstones share the fixed 128-record custody
capacity and are not pruned. This is fail-closed but eventually exhausts
availability under repeated cancelled/refused/no-action turns. Adding the enum
variant is also rollback-incompatible with older readers. Formal OTA remains
HOLD pending an explicit v4 migration/compaction design, old-version
fail-closed behavior and reopen/power-loss/rollback evidence.

The product P0 daemon build currently compiles the System API conformance lane
alongside the shell path. That does not establish a physical System effect.
The live System path still lacks a restart-safe coordinator across provider
terminalization, UI receipt persistence and outer ACK retirement, including a
window whose teardown authority exists only in memory. System effect and
crash/reboot recovery therefore remain a separate HOLD after the physical
shell chain.

The Qualcomm policy freeze now wraps the legacy `dumpstate -> vold` binder
permission in `until_board_api(202604)`. For the authoritative bp4a board API
202504 this preserves the upstream permission exactly; for board API 202604
and later it removes that allow to complement the platform neverallow. This is
a board-API compatibility correction, not a neverallow relaxation. Both API
expansions passed direct `checkpolicy`/`sepolicy-analyze` comparison, and the
shared-out bp4a full-policy build passes as recorded above. A clean-output
full-policy build remains part of the target-files gate.

## 2026-08-12 v24 receipt-stage failure and v25 recovery boundary

The first post-retirement clean graph was materialized under the former v24
evidence root (the dated scratch path was removed; its failure records remain
in the shared release-evidence/custody stores). Its clean source BOM
has SHA-256
`d0f74d3b16c3966eb329d9ef90fdceed98d0c085bdd3f8b7326ce62549bfdcc4`,
receipt ID
`sha256:d2305fea49d5d17d29ada4ae1a3d630ffa913bcea0aa9ef5adb6387a5ecd5d5a`
and resolved-manifest SHA-256
`44def782884178030fb5f7bdcc2286678d5dd30ed81aa03556db308198ce78fa`.
Independent shell, common/P0.1 raw, launcher, rootfs-v9 and final-daemon lanes
completed byte-identically, and a fresh external Android stage produced the
expected 27 roles plus its receipt. This remains host diagnostic evidence.

The first Soong invocation incorrectly requested the custom module name as a
top-level Ninja phony and was rejected as an unknown target. Requesting the
actual generated output edge then exercised the intended boundary: the
pre-sbox retained-FD custody rule passed and produced exactly 29 files, while
the sbox publication rule rejected every generated `./out/...` argument as a
non-normalized path and cleaned all tentative `gen/` outputs. Thus v24 has no
published admission, SELinux build, target-files or device authority.

The minimal correction is Android `vendor/trillionnium` commit
`fb4dc75fae46cee867060ef9cca18044c2b98686`. It accepts and removes exactly
one leading `./` emitted by RuleBuilder sbox before applying the existing
canonical-path checks; traversal, repeated dot components and other
non-normalized spellings remain rejected. The focused regression passed 1/1,
the receipt-stage verifier 56/56, materializer 14/14 and Android product wiring
8/8. Because this source commit differs from the v24 BOM, neither the v24
receipt stage nor any v24 artifact may feed a later image. Recovery begins
with a unique clean v25 BOM, full A/B rematerialization and a fresh OUT_DIR;
v24 must not be patched in place or flashed.

## 2026-08-12 v25 admission pass and SELinux fail-closed boundary

The replacement v25 evidence root (the active copy is
`host-estate/trillionnium-release-20260812-v25.9wKhgj`; the historical suffix
in the original receipt is retained for provenance) has an exact-clean BOM
with SHA-256
`5757ff095e86e5cc97c9363cd3ce94d24f13fd1057d738d9e364998353d1ed12`,
receipt ID
`sha256:76090751f5a54f4bb03f4fbdc17a37775e139847d13980abe2b25d4bf1d89a5e`
and resolved-manifest SHA-256
`50fe2a8d3742dda82e93ce70ef86bc47cf0ab8ad530609fc51771ea27e5de62a`.
The shell, common/P0.1 raw, both launcher, rootfs-v9 and final-daemon lanes
were built independently and reproduced byte-identically. A fresh Android
stage then passed the corrected Soong boundary with exactly 28 external, 29
retained-FD custody and 29 sbox-published regular files. The external receipt
has SHA-256
`85ad36a1352d7a2f88cf4c0e336dd8dc32fc8cb558aa8c7b0afae84857b251a2`
and the canonical custody ID is
`sha256:1e49c62598bef054402fe5aa39b1e955f276689e44555362f5f1a2caccd9dfbd`.
This closes the host/Soong admission question that v24 exposed, but still
grants neither device nor release authority.

The subsequent clean `m selinux_policy` passed its neverallow and compatibility
checks, then failed final `precompiled_sepolicy` assembly because platform
board API 202604 assigns `/sys/class/typec` to `sysfs_typec` while legacy
Qualcomm vendor policy assigned the same path to `vendor_sysfs_usb_c`. The
platform change deliberately grants `hal_usb` access to the new public type,
which is inherited by `vendor_hal_usb_qti`; the existing `ueventd`
`sysfs_type` rule also covers it. Therefore the minimal correction removes
only the obsolete `/class/typec` and `/class/typec/usbc0` vendor genfscon
entries while retaining the separate device-specific USB-PD label and all
still-used vendor types. It is committed as legacy Qualcomm vendor SELinux
`7d3d2de94c4d63fe873cd6529264e900cee42466` and pinned by Android manifest
commit `d33c0119177585bda4869fcfb68229b14e6ab592`.

That source change intentionally invalidates v25 for any later build stage.
The v25 OUT and receipts are immutable failure/diagnostic evidence only; they
must not be resumed, mixed into target-files or flashed. Recovery starts at
v26 with a fresh exact-clean BOM, complete independent A/B rematerialization,
fresh receipt stage and unique OUT_DIR before focused precompiled policy, full
SELinux and target-files gates are attempted again.

## 2026-08-12 v26 clean static-image terminal

The v26 evidence root (active custody copy
`host-estate/trillionnium-release-20260812-v26.cNdAmy`; the historical suffix
in the original receipt is retained for provenance) has a canonical source
BOM with SHA-256
`6b4517a771e993d57b2cf8954ace9db29e6e349a9feeefbabc7e63cb56a9b4c1`,
receipt ID
`sha256:2c5b1be58ada40ba59c25f7febd0d8ef59955da99d2301f2df1f578d4b73a40f`
and decision `PASS_LOCAL_EXACT_CLEAN_GRAPH`; the independently materialized
replay is byte-identical. The resolved-manifest SHA-256 is
`72efdacc541406c59a14786db4495d0d10a2c11c1e5f74e7c78907a496370e12`.
All 23 captured Git projects and both proprietary-file inventories remained
exactly frozen through the terminal audit.

The complete independent A/B host graph reproduced the shell, common/P0.1
raw, launcher, rootfs-v9 and final-daemon lanes byte-identically. Its fresh
Android stage again admitted exactly 28 external, 29 retained-FD-custody and
29 sbox-published regular files. The unique clean Android OUT then completed
the target-files package and image package. Their terminal observed hashes are:

- target-files, 3,348,883,550 bytes:
  `62bf422df9c59fee00a4add99699a2534bfaf44caadabebf2845939f7d72a946`;
- image package, 1,757,566,395 bytes:
  `ccfb130662a472ade862d6a3c300b772391a89a25c51f72e48730597e0569f34`.

Two audit-harness defects failed closed without changing either package. The
first target-files audit inherited six shell line breaks after an equality
operator, so valid SHA comparisons exited with `test` status 2. The corrected
evidence-only rerun passed the exact package, receipt/custody, rootfs, UID,
SELinux/socket and retired-payload checks. The first AVB audit then supplied a
PEM file where `avbtool --expected_chain_partition` requires the raw AVB
public-key blob and extracted descriptor targets under prefixed rather than
partition basenames. The original script SHA-256
`d43a56f3cff9281a4970be943ee5d6fccb90fceddea2eac5926cedfdb63aeded`,
both original failure directories and their stop decisions remain preserved.
The five-line evidence-only correction has SHA-256
`728804324f34dd75abcc96d91c4eb37540acc440f509cf01b4e2ecb1f228ae06`;
its isolated rerun had empty stderr and verified `vbmeta`, `vbmeta_system`,
`boot`, `dtbo`, `vendor_boot`, `product`, `system`, `system_ext` and `vendor`.
It also confirmed absent AVB-disable flags, rollback index 28, vbmeta-system
rollback location 2 and the expected known-AOSP-test-key/userdebug class.

The terminal decision is `PASS_STATIC_ONLY_KEEP_RELEASE_HOLD`. This is a
static host/image result, not device or release authority. No v26 device write
was authorized or performed, and the connected phone was not validated as
running v26. AiShell and AiAuthority still declare
`trillionnium.codex-direct-tools-prompt.v1/1`, while the daemon declares
`trillionnium.codex-p0-system-api-shell-exec-prompt.v3/3`; therefore the
vertical execution chain remains HOLD. Device runtime effects, production
signing and lineage, rollback behavior, OTA and public release also remain
HOLD, with `device_write_authorized=false` and
`public_release_allowed=false`.

## 2026-08-14 v27 prompt-aligned static-image terminal

The v27 release root remains the retained static-evidence directory
`trillionnium-release-20260812-v27.nVcJWP`; the superseded v27 preflight copy
was moved to retired custody. The terminal
authority archive is
`android-v27-standard-static-build-evidence/terminal-static-seal-fresh-out-retry4/pass-20260814T081241+0800`
beneath it. The canonical source BOM has SHA-256
`3b056bb555d5e2569cf7fe7a47a3dc6b5596bf353df260b330bad8a2dab59325`,
size 1,249,792 bytes, receipt ID
`sha256:d2f593a39f32a31dba055404f26778110106979621384e09a9df0c2977f9a1e2`
and source-set SHA-256
`c267e5a83ee0ae8ae6c60e7c222c87c53d9653d4f009e2c14027082e4711df3d`.
The resolved-manifest SHA-256 is
`cca59363099da6a67bed5d08aba923c9ee9e8f38906299469fd4ae68596df7c1`.
The terminal live BOM was byte-identical to that canonical BOM.

The sole qualifying Android OUT is
`out/target/trillionnium-userdebug-v27-standard-relative-retry4-20260813.zNmKmJ`.
It binds `TARGET_RELEASE=bp4a`, an effective build umask of 0002, exactly 28
external, 29 retained-FD-custody and 29 generated receipt files, 27 rehashed
artifact payloads, UIDs 5901/5902/5903 and Codex 0.144.1. AiShell, AiAuthority
and the daemon all bind
`trillionnium.codex-p0-system-api-shell-exec-prompt.v3/3`. Kernel UAPI and
`libdrmutils` compatibility, precompiled policy, full bp4a SELinux, the
post-target receipt re-audit and target-files static audit all passed in the
sealed authority chain.

The exact packages sealed by the terminal are:

- target-files, 3,311,309,510 bytes:
  `61f7e6816168bb1859ac13294bc385e52a5862bdd43c3cf12e0ddeddd7f37859`;
- image package, 1,738,920,051 bytes:
  `daa2a4b2ccd9a2817f9a442aec7220a78d32834c71aa9fa503a99cd341f81f8b`.

Target-files Ninja completed successfully with empty stderr. Its original
systemd wrapper nevertheless exited 1 at a GNU `stat %F` check against the
English literal `regular file`. The preserved post-hoc diagnosis attributes
that result to localized `stat` output, but grades the causality as inferred
rather than directly captured from the launch environment. The post-Ninja
finalizer records `AUTHORITY_BASIS=POST_NINJA_LOCALIZED_STAT_SALVAGE` and
explicitly forbids a Ninja rerun. Image Ninja later regenerated target-files
in place with the same inode, SHA-256 and byte size but a later mtime. The
chain accepts byte/content continuity and freezes the post-image
artifact-state fields recorded by the seal; it does not claim full metadata
continuity between the target-files and image phases.

The image authority and corrected static audit passed with empty build/audit
stderr. Ten core and 18 non-core image mappings were byte-equal across the
archives, and 9 AVB images verified statically. The observed rollback index is
28, `vbmeta_system` rollback-index location is 2, and the signing-key class is
`KNOWN_AOSP_TEST_KEYS`. These are host-static observations, not device verified
boot, rollback-enforcement or production-signing proof. Failed audit-harness
attempts and their corrective evidence remain retained; the terminal headline
files do not promote those historical records into current authority.

The terminal result is
`PASS_V27_RETRY4_TERMINAL_STATIC_SEAL_AUTHORITATIVE` with decision
`PASS_STATIC_ONLY_KEEP_RELEASE_HOLD`. Its `SHA256SUMS` has SHA-256
`23307ab94f05d6d4360c54f55d28055c0c06da6618db5dde3b4a63ce19458d6f`
and verifies in full. Device execution, physical validation, any device write
or flashing, formal signing, rollback monotonicity and device enforcement,
OTA, public release and release authority remain HOLD;
`device_write_authorized=false` and `public_release_allowed=false`.

## Historical pre-r2 source authority and custody

The two authority roots remain the control tree at
`/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-release-sources/p0-agent-native-integration-20260731/trillionnium-os`
and the Android manifest tree at
`/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/android/lineage-fogos`. The
Android manifest repository is clean at
`df82bdd88692994eaa78f17a244091a8c7d9a3b7`; its tracked
`trillionnium-fogos.xml` has SHA-256
`3efc10ae9f299ab8b85f2ed21eec37f6da4c24bb7add86851b2b973407a17b59`.
The Android side of the integration is frozen at these clean local commits:

- AiShell: `dea3e4c8d80b464a336a889a9b453163f24324bb`;
- AiAuthority: `e582fab6021c9fa4627f2e088be6ae48b20399ff`;
- `vendor/trillionnium`: `fb4dc75fae46cee867060ef9cca18044c2b98686`;
- Trillionnium SELinux: `d53fcc5e12a9b4b0b8867899c1e60458ee327881`;
- framework production client gate:
  `366a3b4c354b60a5c3b205989abf013ae93ce12f`;
- adbd production client gate:
  `318bdb11c42125779a6fc4338da7c2885d277624`;
- Qualcomm SELinux: `e2aaca90b577db9c02293b9a20393d480e8321e2`;
- Qualcomm legacy vendor SELinux:
  `7d3d2de94c4d63fe873cd6529264e900cee42466`;
- sm6375-common device configuration:
  `854361f52ad01154244de806da692b23aa465d63`.

The v27 external BOM authoritatively binds the pre-documentation control HEAD
`4c7f8a4633c904d48f62fbc69ab3d67ad2cccbd5`, Android manifest HEAD
`df82bdd88692994eaa78f17a244091a8c7d9a3b7`, every resolved Android project
commit and the external toolchain inputs used by the static terminal. This
required status update is a separate docs-only successor commit made after
the terminal seal; it is intentionally outside the v27 build BOM and cannot
be retroactively consumed by or attributed to the sealed artifacts. Any later
source change likewise requires a new exact-clean BOM and fresh OUT before it
can receive build authority. The Android vendor checkout alone is not a
complete Android source authority.

The superseded pre-removal v22 evidence root
(`trillionnium-release-20260811-final.NraSmJ`) was removed from the active
estate; its source BOM has
SHA-256
`579d813d2858c221ff75845ec49cf5a3600d750bfee8c6122002be40b4456a16`,
decision `PASS_LOCAL_EXACT_CLEAN_GRAPH`, receipt ID
`sha256:d00f4d29d7e86087f241fb5d2dc0a032e298c95de9a824a6c0527f3b95740ee0`
and resolved-manifest SHA-256
`af3e6db785b71af074d2977207a7b4e5ecf1ca9f7fc0fcc2907698a3a4493bf9`.
Its two independent shell artifact sets are byte-identical, with internal
artifact-set SHA-256
`8594e955f067fe636389c40cf1c0c3f6a622b7b528618fded68edede818840dc`.
Its final daemon is byte-identical across lanes at SHA-256
`8850b1e8b5e4d775f379330a3db46ea8d961a50e38cf94cb3e1559e65a3bd7c4`,
the v9 rootfs is byte-identical at SHA-256
`bd7f7f079a3486173ca8dd558ca2282ba9f0829839387093d07aad763062f4a3`,
and the receipt-stage receipt has SHA-256
`355da38f9d7951001bbe744003177bc735e383238e8ac883708bab46441b7796`.
These artifacts bind the removed Android pins and are reproducibility evidence
only: they must not be consumed by current target-files or the device lane.

The subsequent v23 evidence root
(`trillionnium-release-20260811-v23.HkkrdL`) was also removed from the active
estate; its clean-graph BOM
has SHA-256
`39e97d492a425a8ab1f7e99f46c1155b9070e3ce27cf2e81da0f5262a6d3bb52`,
receipt ID
`sha256:0da210180c6ea5d139b07ea120ee2b012a57ba91d9936e835e67e2c6937cd015`
and resolved-manifest SHA-256
`89d8de22c54fd5f26941d4973bc148a8b487a0e112082236e97f0a06b6daf87c`.
Its shell A/B sets passed with internal artifact-set SHA-256
`30eb4de7571224a5c114d95ce6d0013c6b2563f06e7d792985a2bb5d7c1dcf49`.
The raw A/B builders were interrupted in private scratch before publication
when the production-client lookup gap was found; the root carries an explicit
`SUPERSEDED_DO_NOT_CONSUME.md` marker. Nothing in v23 is current artifact
authority.

The superseded frozen v20 evidence root
(`trillionnium-release-20260809.9neZf4`) was removed from the active estate;
its canonical source BOM
has SHA-256
`c56db81b98703ba9c860cae355b13ece1507a0cacc0b0a3a88d504b7edaa9c18`
and decision `PASS_LOCAL_EXACT_CLEAN_GRAPH`. It is host evidence for earlier
bytes only and explicitly authorizes neither the current build nor a device
write, OTA or release. The current source changes require a new unique BOM and
new artifacts; v20 bytes must not be mixed with them.

Before the 2026-08-10 continuation, the complete dirty integration baseline
for the control, Android vendor, device configuration, Trillionnium SELinux
and AiShell worktrees was preserved without altering those worktrees under the
retired custody copy `trillionnium-authority-precontinuation-20260810T143924Z`.
Its `SHA256SUMS` file has SHA-256
`cd81428bf0f9012f739bc28dab24e18e5a1e7f087b3e48e801b408bbe1641f8f`.
This is recoverability evidence, not a build or release BOM; the clean control
freeze and new external BOM are still required before Android artifacts may be
accepted.

The detached July 15 dirty checkout was moved intact and recoverably out of
the active OpenClaw workspace to the owner-only retired custody copy
`trillionnium-legacy-workspace-quarantine-20260811T200722+0800`.
The original active-workspace path is absent; no process or open descriptor
references the quarantined tree. Its retained `RETIRED_NON_AUTHORITATIVE.md`
marker has SHA-256
`34493df388d71820d4ef58e314d47863d0ff6ab06d281bd655a5bbf558b7b293`
and forbids bulk-copy or reverse merge into either current tree. This is
historical recoverability material, not source authority.

The singleton source contracts are:

- Agent descriptor registry SHA-256:
  `5ecd89d3c9fedbbeb0ac1de32fba2b5e5e5d248048ddc9a9e0359a0a01903119`
- canonical operation binding SHA-256:
  `e24a5029cbc545971dc8ca935754faa44df4406bcdc600c7e5fef3b7c8b48231`
- typed operation catalog SHA-256:
  `c4efd224e75bc21ab95753eac4f183732c447e315ac89d4369bc5185a4997453`
- superseded typed-candidate permission model SHA-256:
  `9399b1375d267e2672d3de28519d9f001e5c50ff83d056dd20fe08383613613d`
- direct Agent host ABI SHA-256:
  `d538ef22f6ff1fcc5cf2ff15a158a8227631991bf83c3676ab19a66fce162c11`
- shell/ADB/Windows product boundary SHA-256:
  `c55684e9c52d04586477e9420c0e488a8a4d6fc4eeca42e287ad5be6e585a5ff`
- direct-effect contract SHA-256:
  `5c4fe8ac528d2da54d7eecb28b7c50107f1bd9971196bdabd6b55e5f483d2266`

The permission model describes only the pre-r2 System API, Accessibility and
typed-candidate surfaces. It is non-authorizing historical material and is
superseded for product direction by the r3 owner-open contract. The old labels
`standard_source_wired_artifact_device_authority_hold`,
`effect_authority=false` and `planned_not_implemented_hold` describe that
snapshot, not the current direct-tool contract. No static artifact or source
test is evidence of a live Codex turn; the r3 implementation status at the top
of this page remains authoritative.

## Root Linux and device state (historical pre-r2 details below)

The pre-r2 Root Linux substrate used read-only/nosuid/nodev mount boundaries,
SELinux-enforced private state and capability-hardening source contracts. v27
independently reproduced the minimal Bookworm ARM64 rootfs package, final P0.1
daemon and disabled measured AgentManifest across A/B lanes, admitted them
through the matching Android receipt stage and included them in the verified
static image graph. This remains host/static evidence with
`release_allowed=false`, not installed-device proof. No v27 device write or
validation was authorized or performed. The prompt tuple is aligned
statically, but the image has not been written to a phone, the vertical chain
has not run on that image, and no physical effect receipt binds the clean v27
BOM and verified static image to a device. The product therefore remains
operationally open. The last retained device inspection, which is not current
v27 proof, reported that:

- the device had no active Codex/agentd process or Agent API v2 socket;
- the egress guard, custody high-water, ready gate and Root Linux daemon were
  stopped;
- the inspected userdebug device booted a test-key/orange image with old
  OpenClaw descriptors/runtime paths and an old debug ADB helper.

For the future v27-or-later device scan, “no OpenClaw residue” means no
installed OpenClaw executable/payload/package, runnable service or UID subject,
SELinux domain/transition, socket, active mount, process, or retained state
content. Two non-authorizing migration records remain intentionally visible:
UID/GID 5902 is a permanent retired-identity tombstone, and init contains
idempotent unmount/quarantine references for upgrading old devices. A literal
zero-match string grep would therefore be the wrong test; neither record may
be executable or grant identity/effect authority.

The old large GUI-oriented rootfs is historical and must never be used as the
base of a current image. For owner-open dogfood, the current userdebug base
plus a writable overlay is the practical path; there is no executable
allowlist on the direct shell/ADB path. A fresh minimal immutable image and
allowlisted/sealed lane are later packaging or public-release options, not a
dogfood start gate.

## Host isolation

The May 2026 desktop `trillionniumd` installation was disabled and moved to
the recoverable retired custody copy
`trillionnium-host-quarantine-20260809T080055Z`. The retired
user units, D-Bus activation entries and Shell/Command Center binaries no
longer occupy or advertise `org.trillionnium.Agent1`; this prevents legacy
host smoke from masquerading as current product evidence. The 2026-08-11
re-audit found all three legacy units absent/inactive with no PID, no D-Bus
owner or activatable entry, and no legacy binary, launcher, socket, mount,
process, open descriptor, scheduled job or product-host container. All ten
quarantined files still match their recorded SHA-256 values, and the detached
old workspace was moved intact out of the active workspace into the owner-only
recoverable quarantine recorded above.

Two non-activating host residues are disclosed rather than counted as product
authority: `~/.local/state/trillionnium-os/audit.sqlite{,-wal,-shm}` and
Waydroid data for `ai.trillionnium.bridge`. The Waydroid Android session is
`STOPPED`, but the generic host `waydroid-container.service` manager remains
`active/running`; this page does not misclassify that manager as stopped. The
Waydroid host launcher is absent, the retained APK has no boot receiver, and
the re-audit found no Agent1 activator, process or socket. Neither residue is
current product authority; both remain migration-cleanup concerns.

## Windows compatibility

Windows compatibility is `research_only_not_implemented`:

- no runtime/install Soong module;
- no product package or init service;
- no Agent descriptor or stable API;
- no device execution evidence.

Wine/QEMU custody bytes must remain outside target-files. Their presence in a
source research directory is not implementation progress or a product claim.

## Retired Agent migration

The former second Agent is retired and has no active descriptor, runtime,
launcher, package, SELinux domain, cgroup or effect authority. Its executable
and packaging artifacts were removed from active source/product trees after a
recoverable external archive was created.

One OTA migration boundary intentionally remains:

- fixed legacy bind paths are unmounted explicitly;
- old state/inbox paths are quarantined with no-follow checks and fixed
  allowlists;
- UID/GID 5902 remains a non-reusable tombstone.

Those migration identifiers must not be reused or deleted until a real
dual-Agent-to-Codex-only OTA, reboot, power-loss and residual-file scan passes.
They do not make the retired Agent reachable. This is migration cleanup only;
it never blocks owner-open shell/ADB, a new Codex image or a userdebug turn.

## Priority development plan

The detailed plan now lives in
[`TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`](TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md).
It is the only active plan and is authoritative for sequencing, Codex-only /
Root Linux scope, direct shell/ADB semantics, cleanup and release evidence.
This
file remains the status ledger; it must not grow a second competing roadmap.

For the current owner-open milestone, a working AI Agent native OS means that
one Codex turn can use host/Root Linux shell and raw ADB, receives the real
observations, and can recover after a restart or disconnect. Source tests are
feedback, not a substitute for that live turn. Clean signed BOM, rollback,
multi-user and formal power-loss evidence belong to the later public-release
profile and must not block owner dogfood.
