# Trillionnium OS

Trillionnium is an AI Agent Native Android OS. Codex is the single built-in
Agent: the OS launches, keeps alive and connects it to native phone tools.
Measurement is diagnostic/release provenance, not owner-open admission. Model
inference is off-device; running an LLM on the phone is not a product target,
requirement or release gate.

The accepted product direction is:

```text
AiShell -> OS Agent Host -> Codex turn
                           -> direct shell.command / shell.exec
                           -> direct adb.exec
                           -> optional System API / Accessibility
                           -> raw observation -> same Codex turn

Codex owns: intent, context, policy, tool/target choice, retry and meaning.
Substrate owns only: process/IPC, transport, storage, watchdog and recovery.
```

OpenClaw is retired and is not a product Agent. Old OpenClaw identities and
paths may remain temporarily only as non-reusable OTA cleanup tombstones; they
must not be accepted for a new request, installed, started or granted effect
authority.

Root Linux is the Android-managed, headless Codex runtime environment. It is
not an alternate mobile Linux desktop OS and does not contain a local-model
desktop. WindowsCompat is research-only, absent from every product variant and
not an implemented capability.

Historical host-side Provider/Codex/kernel/P01 outputs were removed from the
active `rootfs/data` estate. They are recoverable only under the external
`trillionnium-retired-artifacts/2026-08-26/host-estate/data-legacy-20260826/`
custody directory; the only active Trillionnium data state there is the
Android-managed `data/trillionnium/root-linux` substrate. Custody is excluded
from source, BOM and product discovery.

## Current status

This repository is a P0 source prototype and owner-dogfood substrate, not a
public release.

- The r3 semantic contract remains canonical: one Codex semantic control plane,
  off-device inference and direct owner-open shell/ADB.
- The r4 execution plan is the only active implementation sequencing and
  closeout plan.
- The first r4 foundation adds isolated owner-open Host and codec packages,
  strict frame decoding, machine status/traceability and negative default-graph
  checks.
- The foundation Host currently has stdio/filesystem-UDS transport, one
  synchronous turn lineage and an honest unavailable-provider default. It does
  not claim live Codex, shell, ADB, durable replay or Android integration.
- Root Linux mount, SELinux and capability-hardening foundations exist, but the
  current Android audit overlay still selects the pre-r3 Authority/lease/P01/
  shell-broker graph and must not be treated as the owner-open product closure.
- Checked-in Android helper ELF files still contain retired identity bytes, and
  the rootfs predates current daemon hardening. These are provenance and
  release-diagnostic issues; they do not block owner-authorized bootstrap while
  the direct path is rebuilt.
- There is no clean, uniquely traceable target-files/OTA/AVB plus physical
  reboot/power-loss conformance package.

Do not infer a public-release claim from source presence, a userdebug hotpatch,
a host-only test or a historical evidence file. Owner-open dogfood is allowed
to proceed on the authorized test device while the direct path is completed.

## Start here

- [Owner-open r4 execution plan — active sequencing and closeout plan](docs/TRILLIONNIUM_OWNER_OPEN_R4_EXECUTION_PLAN.md)
- [r4 machine implementation status](docs/status/owner-open-r4-status.json)
- [r4 requirement-to-code/test traceability](docs/status/owner-open-r4-traceability.tsv)
- [Owner-open Direct Agent Host v1 implementable protocol](docs/protocols/owner-open-direct-agent-host-v1.md)
- [Owner-open threat model](docs/security/owner-open-threat-model.md)
- [r3 semantic architecture plan](docs/TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md)
- [Current implementation and release status](docs/CURRENT_STATE.md)
- [2026-08-06 full Agent-native audit](docs/audits/2026-08-06-ai-agent-native-os-full-audit.md)
- [Canonical Codex-only direct shell/ADB ADR](docs/architecture/2026-08-06-codex-native-direct-shell-adb.md)
- [Owner-open direct-tools contract](docs/contracts/codex-sovereign-direct-tools-v1.json)
- [Owner-open forbidden default-graph contract](docs/contracts/owner-open-forbidden-default-graph-v1.json)
- [Publication scope and audit snapshot](PUBLISH_SNAPSHOT.md)
- [Android manifest and latest dirty integration overlay](android-integration/README.md)
- [Transition v2 product boundary](docs/contracts/agent-exec-adb-windows-product-boundary-v2.json)
- [Direct System API and Accessibility contracts (pre-r2 implementation notes)](crates/trillionnium-agent-direct-tools/README.md)

The previous dual-Agent, typed-only shell/ADB ADR is superseded and retained
only for history. May 2026 retired distro UI, application bridge and local-model
material, plus the former plan-to-Authority executor, are historical; they must
not be used as current implementation or release claims. The r3 semantic plan
defines the one Codex + Root Linux execution path; r4 defines the engineering
order, evidence levels and completion gates.

## Owner-open foundation checks

The foundation verifier checks the isolated Cargo default graph, generated
codec constants, machine status, required documents and the known Android
legacy graph hold:

```sh
python3 tools/generate-owner-open-types.py --check
python3 tools/verify-owner-open-foundation.py
python3 -m unittest discover -s tools/tests -p 'test_*.py'
cargo test --locked --package trillionnium-owner-open-types
cargo test --locked --package trillionnium-owner-open-host
```

`--strict-android` is intentionally not the default until the W0 Android
profile split lands. After that cutover it becomes mandatory and any forbidden
Authority/lease/P01/shell-broker marker is a build failure.

## Release claim boundary

Owner-open dogfood is complete when:

1. one Codex turn can invoke host shell, Root Linux shell and raw ADB;
2. the real command/result stream returns to that same turn;
3. restart, disconnect and recovery produce honest observations;
4. Codex can build, install and iterate the userland on the test device;
5. the Android owner-open build/link/install/start graph contains no forbidden
   legacy semantic node; and
6. L4 normal-path plus L5 fault evidence binds exact source, image and device.

Signed production images, AVB/rollback, multi-user isolation and formal public
release evidence are release-only properties. They are not prerequisites for
owner-open operation.

Source or documentation changes that alter owner-open sequencing, status or
traceability must update the r4 plan/status/traceability package in the same
change. Product or release claim changes must additionally update
`docs/CURRENT_STATE.md` and the current machine-readable semantic contract.
