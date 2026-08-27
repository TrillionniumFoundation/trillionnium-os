# Trillionnium host tools

> The privilege-broker and release scripts documented here are sealed/history
> or release-provenance lanes. They are not owner-open startup dependencies.
> The owner-open Agent uses Codex full-access shell plus the ordinary ARM64
> `adb` client and must receive raw process/ADB results; a broker
> `mutation_unavailable`/HOLD is never a substitute.

## Android privilege-broker artifact

- `build_android_privilege_broker.sh` is the only reviewed direct Cargo entry
  for an Android arm64 privilege-broker ELF.
- It requires an explicit `ANDROID_NDK_ROOT` at exact NDK r27d revision
  `27.3.13750724`, uses the API-35 AArch64 linker, and builds with Cargo
  `--frozen` for `aarch64-linux-android`.
- It rejects a non-PIE/non-AArch64 ELF, the wrong Android interpreter,
  executable stack, missing RELRO/BIND_NOW, RPATH/RUNPATH/TEXTREL, or any
  dependency closure other than `libc.so` plus `libdl.so`, then prints the
  exact output path and SHA-256.
- `TRILLIONNIUM_ANDROID_TARGET_DIR` may select an isolated build directory.
  The script does not copy into the Android product, update a vendor pin, sign,
  upload, or operate a device; those remain separate reviewed gates.

## Android release-signed full A/B OTA

- `android_release_ota.py` is the current config-driven
  target-files-to-release-OTA host pipeline. It has no source revision, run tag,
  secret directory or output hash hard-coded into it. The fogos product map is
  `android_release_signing_fogos.v1.json`.
- The preflight requires the exact device and build type, an unsigned
  test/dev-key input, AVB plus A/B metadata, complete mappings for every AVB
  key-bearing partition and every non-`PRESIGNED` APEX, and stable SHA-256/file
  identities for the input and Android host tools. APEX inventory drift fails
  closed instead of silently retaining an AOSP test payload key.
- `--dry-run` performs no signing and does not read private material.
  `--dry-run --validate-key-material` additionally verifies private directory
  modes and every named handle. Secret locations may be supplied with
  `--key-dir`/`--apex-key-dir` or the
  `TRILLIONNIUM_RELEASE_KEY_DIR`/`TRILLIONNIUM_RELEASE_APEX_KEY_DIR`
  environment variables.
- During execution, private bytes exist only in a temporary `0700` directory;
  the `ANDROID_PW_FILE` and staged private files are `0600`. Logs are sanitized,
  partial ZIPs remain explicitly suffixed `.partial`, and the receipt contains
  only public handles, public certificate digests, tool/input/output hashes and
  result metadata. Successful output still does not authorize device writes,
  uploads or public release.
- The historical ten-APEX replacement closure is not accepted as production
  signing: fogos currently contains 36 non-`PRESIGNED` APEX packages. All 36
  payload-key handles must be provisioned before execution. Replacing a key
  already present on a deployed device also requires a separately reviewed
  APEX key-rotation/lineage or fresh-install plan; this host tool neither
  invents that lineage nor treats a newly generated key as update-compatible.

Build the unsigned source artifact from the Android root first:

```sh
source build/envsetup.sh
lunch trillionnium_fogos-bp4a-userdebug
m target-files-package
```

Resolve the produced target-files archive from the selected build output and
require one exact candidate; do not guess a build-number-dependent filename:

```sh
product_out=$(get_build_var PRODUCT_OUT)
mapfile -t target_files_candidates < <(
  find "$product_out/obj/PACKAGING/target_files_intermediates" \
    -maxdepth 1 -type f -name '*-target_files*.zip' -print | sort
)
test "${#target_files_candidates[@]}" -eq 1
target_files=${target_files_candidates[0]}
```

Non-secret preflight example:

```sh
python3 /path/to/trillionnium-os/tools/android_release_ota.py \
  --android-root /path/to/android \
  --target-files /path/to/trillionnium_fogos-target_files.zip \
  --dry-run
```

The source-BOM binding is an explicit, fail-closed opt-in.  When a target-files
archive has been produced with
`META/trillionnium-source-bom-binding.json`, require that member and
cross-check it against the exact canonical BOM used for the build before any
signing/tool work:

```sh
python3 /path/to/trillionnium-os/tools/android_release_ota.py \
  --android-root /path/to/android \
  --target-files /path/to/trillionnium_fogos-target_files.zip \
  --source-bom-binding-bom /path/to/source-bom.v2.json \
  --require-source-bom-binding \
  --dry-run
```

The two flags must be supplied together.  Omitting them preserves the
backwards-compatible host preflight behavior; supplying only the BOM path or
only the requirement flag is rejected.  This provenance check does not replace
the separate signed-metadata, rollback, device-custody, or release gate.

The full signing command adds an unused output directory, an artifact prefix
and the two private-material boundaries. It intentionally has no ADB, fastboot,
recovery, reboot, sideload or upload operation.

## Android P0.1 read-only device conformance

- `android_p01_device_conformance.py` is the post-OTA, device-side evidence
  collector for the current fogos P0.1 userdebug boundary. It is deliberately
  narrower than an installer or test driver: its ADB vocabulary is limited to
  fixed property reads, `getenforce`, `id -u`, bounded `cat`, `sha256sum`, and
  `stat` operations. It has no flash, push, install, `adb root`, set-property,
  service-control, activity-launch, ACK, reboot, or power-loss implementation.
- There are no embedded daemon, launcher, System API, replay-helper,
  high-water, or manifest digests. `--contract` is mandatory and must name one
  absolute, non-symlink, measured
  `org.trillionnium.android-p01-device-conformance-contract.v1` JSON object
  derived from the finally frozen target-files/BOM. The contract binds the
  exact manifest digest and facts, the system_ext image digest, the complete
  fixed-path artifact hash map, its upstream target-files/BOM digest, and the
  reviewed release boundary.
  `--expected-contract-sha256` is also mandatory, so merely replacing the
  contract file at the selected path cannot silently change the expectation.
  Missing, stale, cross-spliced, malformed, or mutation-authorizing contracts
  fail closed before ADB is opened. No final contract is checked in while the
  daemon/manifest freeze is still pending.
- The layered JSON checks fingerprint/build type/slot/verified boot, the unique
  manifest facts, P0.1 launcher/core/tool/helper/daemon and Root-Linux artifact
  hashes, init and SELinux state, boot-bound egress evidence, high-water state,
  read-only bind identity/flags, and daemon/high-water PID, UID/GID, final
  domain, and cgroup evidence. If adbd was not already root, private `/data` and
  cross-process checks are reported as `HOLD`; the collector never changes adbd.
- The reviewed contract boundary remains explicit: the exact userdebug
  daemon-custody ACK source closure may be complete, while external authority,
  hardware rollback resistance, and physical-device effect evidence remain
  distinct `HOLD` facts. No reviewed Codex-only egress receipt producer/schema
  is currently bound, so the collector reports
  `HOLD_INCOMPLETE_READ_ONLY_EVIDENCE` even when every available candidate
  observation is internally consistent; it does not invent a replacement
  receipt or promote the P0.1 effect chain. Ordinary encrypted `/data`
  high-water state is separately recorded as a production hardware
  rollback-resistance `HOLD`.
- `--plan-settings-effect`, `--plan-ack-compact-retire`,
  `--plan-service-restart`, `--plan-reboot`, and `--plan-power-loss` are
  independent dry-run planning flags. They add closed plan records without
  issuing any additional ADB command. The Codex effect trigger remains
  `absent_closed_hold` until a reviewed stable interface exists; no retired
  Provider trigger is accepted or reported.
- By default evidence is written only to stdout. `--output` may create one new
  host file with mode `0600`; it rejects symlinked parent components, rejects a
  symlink/final collision, fsyncs file and directory, and never overwrites.
  `--system-ext-image` optionally measures a non-symlink host image against the
  exact digest already bound by the pinned expectation contract.

Read-only collection example (use the real, non-symlink ADB executable path):

```sh
python3 tools/android_p01_device_conformance.py \
  --adb /absolute/path/to/adb \
  --serial EXACT_DEVICE_SERIAL \
  --contract /absolute/path/to/frozen-p01-device-contract.json \
  --expected-contract-sha256 FROZEN_CONTRACT_SHA256 \
  --system-ext-image /absolute/path/to/system_ext.img \
  --output /absolute/new/evidence/android-p01-device.json
```

An exit status of `0` requires the read-only baseline decision to start with
`PASS_`; `HOLD` and fail-closed evidence return `2`. No exit status from this
collector authorizes flashing, mutation, release, or publication.

## Current rootfs packaging

### Cross-repository source and userdebug artifact truth

- `materialize_cross_repo_source_bom.py` binds the complete resolved
  `repo manifest -r` bytes to the exact Git/non-ignored dirty state of the
  fixed P0 critical source set. The default
  `p0-cross-repo-source-set.v2.json` adds the two exact non-Git Motorola blob
  roots; the frozen v1 schema and v1 receipt route remain accepted only for
  legacy callers and do not acquire v2 tree semantics.
- Required manifest membership, exact revision equality, clean worktrees and
  an empty ignored-path inventory are independent gates. The receipt records
  tracked-diff, index, status and untracked-content digests; it never edits a
  checkout or manifest.
- The fixed set also names the fogos product/device repositories and Android
  build/release configuration repositories. In v2, the extracted
  `vendor/motorola/{fogos,sm6375-common}` directories are first-class `trees`,
  not fake Git projects and not resolved-manifest members. The contract fixes
  both roots, their entry/byte limits, and the mode policy.
- Tree traversal opens every path component relative to directory descriptors
  with `O_NOFOLLOW`, measures regular files without buffering whole blobs, and
  re-runs the complete measurement before accepting it. Its canonical
  inventory addresses every relative UTF-8 path, entry type and mode; file
  byte count/SHA-256; confined symlink target; and in-tree hardlink target.
  Absolute or escaping links, links to outside hardlink aliases, unsafe paths
  or modes, devices, FIFOs, sockets, excessive trees, and any unstable
  pathname/file/directory state fail closed. Each tree receipt contains the
  exact inventory SHA-256, entry count, addressed byte count, type counts, and
  full deterministic inventory.
- The v2 source contract requires `artifacts` to be exactly empty. Built ELF
  files are outputs, not source inputs, and must not be folded back into the
  source graph or used to create a circular clean-source claim. Real common and
  P0.1 ELF identities are bound later by their independent artifact-set
  receipts and the downstream materialization BOM. `--artifact-root` remains
  a required CLI argument for frozen v1 compatibility; a v2 invocation passes
  an existing empty isolated directory, and the resulting receipt must retain
  `artifacts: []`.
- A v2 receipt is `PASS_LOCAL_EXACT_CLEAN_GRAPH` only when every Git project is
  exact, clean and has no ignored inputs, both non-Git trees pass their two
  stable measurements, and the artifact set is empty. Every other
  successfully measured state is a deterministic `HOLD_LOCAL_SOURCE_GRAPH`.
  Output must be outside all measured checkouts so publication cannot
  invalidate the state it just measured.

Example host-only invocation:

```sh
install -d -m 0700 /separate/empty/source-bom-artifacts
python3 tools/materialize_cross_repo_source_bom.py \
  --android-root /path/to/android \
  --control-root /path/to/control-plane \
  --artifact-root /separate/empty/source-bom-artifacts \
  --contract tools/p0-cross-repo-source-set.v2.json \
  --resolved-manifest /separate/evidence/resolved-manifest.xml \
  --output /separate/evidence/current-local-source-bom.json
```

When the external checkout makes the Python `repo manifest -r` walk exceed its
bounded I/O budget, a static, fully pinned manifest can be resolved without
invoking Git.  `resolve_repo_manifest_low_io.py` rejects dynamic manifest
composition, reads every worktree `.git/HEAD` (including repo's symbolic refs),
and publishes the declaration bytes only after all 1,172 (or fewer) checked-out
HEADs match their exact SHA revisions.  It also emits a provenance receipt with
`release_allowed=false`; this is source evidence, not a release or device
authority.  Both outputs must live outside the checkout:

```sh
python3 tools/resolve_repo_manifest_low_io.py \
  --android-root /path/to/android \
  --resolved-manifest /separate/evidence/resolved-manifest.xml \
  --receipt /separate/evidence/resolved-manifest-receipt.json

python3 tools/materialize_cross_repo_source_bom.py \
  --android-root /path/to/android \
  --control-root /path/to/control-plane \
  --artifact-root /separate/empty/source-bom-artifacts \
  --contract tools/p0-cross-repo-source-set.v2.json \
  --resolved-manifest /separate/evidence/resolved-manifest.xml \
  --resolved-manifest-receipt /separate/evidence/resolved-manifest-receipt.json \
  --require-resolved-manifest-provenance \
  --output /separate/evidence/current-local-source-bom.json
```

The materializer verifies the receipt schema, digest, checkout/path binding,
receipt identity, and non-authorizing posture.  A supplied regular XML file
without the receipt remains a fixture/dogfood lane and is rejected when the
strict provenance flag is enabled.

### Codex raw ELF materialization

`build_codex_only_raw_elf_set.py` builds the fixed `common` or
`p01_userdebug_pre_daemon` Cargo lane with explicit cargo, rustc, host linker,
target linker, archiver and readelf inputs, a clean allowlisted environment, offline/locked
Cargo, and live source-BOM measurements before and after compilation. Its raw
v3 receipts bind exact selected tool identities and closed ELF hardening
evidence. Cargo, rustc, both linkers, ar and readelf are opened and measured once,
then retained through every identity/sysroot query, Cargo build and artifact
inspection. Direct invocations execute `/proc/self/fd` while preserving the
original argv0; Cargo inherits the retained rustc/host-linker/target-linker/ar
descriptors and its closed environment names those descriptor paths for every
host and target selector, including the encoded target-linker Rust flag, rather
than reopening the original executable paths.
All retained bytes/metadata and original paths are revalidated before exclusive
publication, and every descriptor is closed on success or failure. The fixed
Mobian manifest and entire snapshot tree are remeasured before and after each
build, and the effective GCC12/assembler/linker/CRT/sysroot components are
receipt-bound. The host process interpreter plus fallback glibc/libm/libz path
is not byte-closed, so complete release toolchain closure remains false and
product/release admission remains HOLD. On AArch64,
only the daemon may retain
`ld-linux-aarch64.so.1` as both interpreter and DT_NEEDED, and only when
readelf proves the loader is the unique `GLIBC_2.17` provider for the unique
undefined `__stack_chk_guard@GLIBC_2.17` symbol emitted by stack-protected
bundled SQLite. Every non-daemon role, extra loader-bound symbol, dependency,
version or provider drift fails closed. Independent lane A/B receipts are
combined only by `verify_codex_only_raw_elf_ab.py`, which emits raw A/B v3
host-only evidence and never product/device authority.

### Codex launcher materialization

- `build_common_codex_integrity_launcher.py` and
  `build_p01_userdebug_agent_launchers.py` both require an explicit
  `--source-bom`. The selected file must be the canonical v2
  `PASS_LOCAL_EXACT_CLEAN_GRAPH` receipt above, have no blockers, retain its
  non-authorizing local posture, and bind the current control-plane Git HEAD.
  Each builder also requires the exact Android root, empty artifact root, and
  supplied resolved manifest used for the BOM. It invokes the canonical BOM
  materializer before and after compilation and requires byte-for-byte equality
  with the supplied receipt. The builder hashes the checked-in source-set
  contract's raw bytes at build time and requires the BOM descriptor to match;
  it accepts the canonical supplied BOM's valid resolved-manifest digest and
  proves that digest again by live remeasurement. Neither digest is compiled
  into the builder as a revision-specific constant. A change in any of the 23
  Git projects or two
  measured non-Git vendor trees therefore fails closed even when the control
  HEAD does not move.
- Each `--output-dir` must already exist, be empty, be owned by the invoking
  user, and have no group/other permission bits. Keep it outside every measured
  checkout. Publication is exclusive and never overwrites an artifact.
- The v2 stable-principal registry binds the Codex provider/agent, replay
  namespace, UID/GID, SELinux domain, runtime adapter, and fixed endpoint
  domains. It deliberately contains no executable digest. Each launcher
  SHA-256 is instead measured after its closed runtime/tool inputs are fixed
  and is recorded separately in `stable_principal_launcher_measurement`.
  Never write that measured launcher digest back into the stable-principal
  registry or treat a preliminary permission disposition as launcher
  admission.
- Both receipts remain host-only `HOLD` evidence with `release_allowed=false`.
  Their closed `legacy_descriptor_contamination_hold_gate` records only a
  literal absence check for the three derived v1 AgentDescriptor registry
  digests: its legacy launcher identity, contract digest, and canonical
  registry digest. Stable-principal contract/canonical digests and the current
  measured launcher belong only to `stable_principal_launcher_measurement`;
  their presence is not legacy contamination. Both counterfactual same-source
  rebuild and stable-principal admission-split evidence remain explicitly
  required and unverified, with no evidence receipt. For P0.1 this gate is carried by
  `p01-userdebug-pre-daemon-artifact-set.v8.json`; the daemon build accepts
  only that v8 schema. It embeds only the SHA-256 of the closed daemon build
  binding plus the separate unresolved identity-HOLD record, never the source
  BOM or complete pre-daemon receipt. The binding fixes the userdebug feature
  set, release Cargo profile, normalized deterministic Rust flags, AArch64 GNU
  target, Bookworm/glibc ABI ceiling, stable-principal inputs, and measured
  runtime artifacts without creating a daemon-to-BOM cycle.
  Product admission still requires daemon/broker custody of the measured
  launcher, an AVB/slot-bound installed measurement, and the later
  effect/durability evidence chain. The P0.1 receipt is only an input to the
  separately measured final daemon build.
- Both builders require explicit absolute `--cc` and `--readelf` paths. Every
  path component is opened without following symlinks; the executable leaf
  must be single-link, executable and non-writable. Version queries, target
  queries, both launcher compilations and both ELF inspections execute the
  same retained open file descriptions through `/proc/self/fd`, under a
  seven-variable allowlisted environment. The common v5 and P0.1 v8 receipts
  bind bytes, SHA-256, mode, owner, link count and execution custody for both
  tools. This closes the compiler-driver and inspector TOCTOU boundary, but
  not the recursive GCC `cc1`/assembler/linker/CRT/sysroot closure; product and
  release admission therefore remain HOLD.

Common Codex launcher example (the input paths name already frozen AArch64
artifacts, not files from an earlier output directory being overwritten):

```sh
install -d -m 0700 /separate/build/common-launcher-a
python3 tools/build_common_codex_integrity_launcher.py \
  --output-dir /separate/build/common-launcher-a \
  --source-bom /separate/evidence/current-local-source-bom.json \
  --android-root /path/to/android \
  --artifact-root /separate/empty/source-bom-artifacts \
  --resolved-manifest /separate/evidence/resolved-manifest.xml \
  --codex-runtime /separate/inputs/codex-0.144.1 \
  --system-api-tool /separate/inputs/common/trillionnium-agent-system-api \
  --accessibility-tool /separate/inputs/common/trillionnium-agent-accessibility \
  --replay-sync-helper /separate/inputs/common/trillionnium-system-api-replay-sync \
  --daemon /separate/inputs/common/trillionniumd \
  --cc /separate/toolchain-lane-a/toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12 \
  --readelf /separate/toolchain-lane-a/toolchain/sysroot/usr/bin/aarch64-linux-gnu-readelf \
  --toolchain-manifest /separate/toolchain-lane-a/toolchain-manifest.json \
  --target-sysroot /separate/toolchain-lane-a/toolchain/sysroot \
  --target-compiler-bin /separate/toolchain-lane-a/toolchain/sysroot/usr/bin \
  --target-gcc-libdir /separate/toolchain-lane-a/toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12 \
  --target-binutils-dir /separate/toolchain-lane-a/toolchain/sysroot/usr/aarch64-linux-gnu/bin \
  --target-host-runtime-libdir /separate/toolchain-lane-a/toolchain/sysroot/usr/lib/x86_64-linux-gnu
```

P0.1 userdebug pre-daemon launcher example:

```sh
install -d -m 0700 /separate/build/p01-launcher-a
python3 tools/build_p01_userdebug_agent_launchers.py \
  --output-dir /separate/build/p01-launcher-a \
  --source-bom /separate/evidence/current-local-source-bom.json \
  --android-root /path/to/android \
  --artifact-root /separate/empty/source-bom-artifacts \
  --resolved-manifest /separate/evidence/resolved-manifest.xml \
  --codex-runtime /separate/inputs/codex-0.144.1 \
  --system-api-tool /separate/inputs/p01/trillionnium-agent-system-api-device-conformance \
  --replay-sync-helper /separate/inputs/p01/trillionnium-system-api-device-conformance-replay-sync \
  --high-water-authority /separate/inputs/p01/trillionnium-direct-operation-custody-high-water \
  --cc /separate/toolchain-lane-a/toolchain/sysroot/usr/bin/aarch64-linux-gnu-gcc-12 \
  --readelf /separate/toolchain-lane-a/toolchain/sysroot/usr/bin/aarch64-linux-gnu-readelf \
  --toolchain-manifest /separate/toolchain-lane-a/toolchain-manifest.json \
  --target-sysroot /separate/toolchain-lane-a/toolchain/sysroot \
  --target-compiler-bin /separate/toolchain-lane-a/toolchain/sysroot/usr/bin \
  --target-gcc-libdir /separate/toolchain-lane-a/toolchain/sysroot/usr/lib/gcc-cross/aarch64-linux-gnu/12 \
  --target-binutils-dir /separate/toolchain-lane-a/toolchain/sysroot/usr/aarch64-linux-gnu/bin \
  --target-host-runtime-libdir /separate/toolchain-lane-a/toolchain/sysroot/usr/lib/x86_64-linux-gnu
```

For A/B evidence, rerun from the same final source revision with a freshly
materialized canonical BOM, independently built upstream inputs, and a second
new empty output directory. Feed both outputs and the matching raw v3 A/B
receipt to `verify_codex_launcher_artifact_set_ab.py`. Its common-lane v4 or
P0.1-lane v5 aggregate
remeasures both directories, cross-binds compiler/readelf to the raw selected
tool identities, and requires byte-identical launcher artifacts. It remains
host-only because recursive toolchain, identity counterfactual, rootfs, Android
and device evidence are outside that receipt.

`materialize_p01_final_daemon_artifact.py` emits the final v5 host-only P0.1
receipt. Its selected lane always requires `--toolchain-manifest`. A complete
peer lane additionally requires `--peer-toolchain-manifest` together with its
pre-daemon directory, raw receipt, and daemon. Both manifests are fully
verified before and after lane validation; their semantic bindings must be
equal; their manifest parents, toolchain roots, sysroots, manifests, pre/raw
input directories, receipts, and exact GCC/ar/readelf leaves must not alias;
and each lane's pre/raw
compiler, archiver, and readelf paths must name exact leaves under that lane's
snapshot root. Missing or cross-spliced peer custody remains fail-closed and
never creates product authority.

- `build_minimal_bookworm_rootfs.py` is the positive-allowlist, snapshot-pinned
  builder for a fresh Debian Bookworm arm64 headless base. It requires an exact
  resolved package/version inventory, passes that complete version-pinned set
  to `mmdebstrap`, verifies the supplied Debian archive keyring and both exact
  snapshot `InRelease` files, rejects any unpinned host build-tool binary,
  emits an SPDX 2.3 SBOM, strips volatile content, and writes a deterministic
  tar whose directories/files are `0555`/`0444` (executables remain `0555`).
- The former retired multi-Provider `compose_final_agent_rootfs.py` and its tests
  were removed from active tool and test discovery on 2026-08-06. Their exact
  pre-removal bytes are retained only in the external retired-artifact archive;
  they are not a supported RootFS input or release path.
- `build_immutable_rootfs_erofs.py` retains the historical `host-base` v1 lane.
  That lane accepts one normalized Root-Linux tar.zst and pinned host tools and
  emits a deterministic read-only EROFS image plus a non-authorizing
  descriptor. It has no provider, Agent composer, Android install, signing, or
  device-write authority. Computing a host fs-verity digest is not Android
  enablement; Android must enable and re-measure fs-verity on an independently
  admitted exact image before a read-only mount.
- Its separate `codex-product-preflight` path now accepts only the v4 admission
  manifest and v9 Codex-only package receipt. It revalidates the common v5
  artifact set, common launcher A/B v4 receipt, compiler/ELF-inspector custody,
  unresolved identity-independence gate, runtime placeholders and compiled
  SELinux database, then emits a canonical v4 HOLD receipt. Its
  `common_build_evidence` carries the source BOM, frozen Mobian snapshot and
  effective target compiler closure only as cross-agreeing upstream receipt
  claims. The common v5 receipt is bound by exact bytes and SHA-256 and has no
  `receipt_id`; the launcher v4 receipt is self-hashed, and its `receipt_id` is
  an unsigned content identifier rather than a signature or attestation.
  Preflight receives no physical snapshot,
  remeasures no snapshot or physical source BOM/live graph, and requeries no
  effective compiler component; its closed `limitations` list records those
  boundaries. It deliberately
  emits no image: a reviewed label-applying EROFS materializer, pinned xattr
  verifier, Android fs-verity enable/re-measurement and product/device evidence
  remain missing. Historical admission v1/v2/v3 files stay frozen evidence.
- `tests/test_minimal_bookworm_immutable_rootfs.py` covers the exact package
  allowlist, frozen snapshot, non-authorizing contract, deterministic SPDX,
  read-only modes, hardlinks, symlink confinement and special-file rejection.
- `evidence-factory/materialize_common_codex_agent_manifest.py` derives the
  disabled common AgentManifest from the retained physical common launcher
  after revalidating the common v5 artifact set and launcher A/B v4 receipt.
  It accepts no caller-selected identity: the historical
  `identity_key_sha256` field is the launcher executable SHA-256, not a public
  key. Independent A/B invocations must produce byte-identical, inode-distinct
  canonical mode-0444 outputs before rootfs contract materialization.
- `package_current_rootfs.py` is the contract-driven, deterministic and
  host-only Root-Linux packager. Its v9 contract and CLI require the common v5
  artifact-set receipt, common launcher A/B v4 receipt and one explicit,
  exact-size/SHA-256-bound, read-only `zstd` executable. It performs no `PATH`
  discovery and executes only a remeasured held file descriptor. Unresolved
  identity/toolchain/product/device gates remain explicit HOLDs. Its
  `common_build_evidence` labels source BOM, snapshot and target compiler
  closure values as claims from a content-hash-bound common v5 receipt and a
  self-hashed launcher v4 receipt that cross-agree. The common input has no
  `receipt_id`; the launcher's `receipt_id` is an unsigned content identifier,
  not a signature or attestation. The packager has no physical snapshot input, does not
  remeasure that snapshot, requery effective compiler components, or remeasure
  a physical source BOM/live graph; its closed `limitations` list makes those
  boundaries explicit. Its v9
  `output_rootfs` receipt preserves the raw decompressed-tar digest and adds an
  exact `android_staging_filter` closure. That closure models the pinned Android
  C filter's directory `0555` to staging `0755` header/checksum transform
  without invoking a helper or changing the published rootfs bytes. A shared
  differential corpus requires the compiled C helper, packager model and Codex
  EROFS preflight model to agree on accepted and rejected physical tar variants.
- `tests/test_package_current_rootfs.py` provides tiny fixture archives for
  reproducibility, tamper, path/link, duplicate/special member, secret, ELF
  architecture and glibc fail-closed coverage, including a byte-exact fixture
  shared with the compiled Android staging-filter tests.
- The retired composer, its tests, and the former EROFS final-product boundary
  are recoverable from
  `/home/qian-qi/trillionnium-retired-artifacts/2026-08-06/`; that directory is
  outside every source/build tree and must never be consumed by a product build.
- `evidence-factory/rootfs-packager.contract.template.json` and
  `evidence-factory/README.md` define its Evidence Factory handoff.
- `evidence-factory/legacy-rootfs-e9e937451c20-migration.json` is an exact,
  base-bound migration for one historical rootfs; it is not a generic cleanup
  policy.

The current packager requires distinct `--base-rootfs` and
`--output-rootfs` paths, requires a base archive with no filesystem write bits,
requires explicit `--zstd` bytes already frozen without write bits, rejects
symlinked inputs/output-parent components, and refuses to overwrite any output
or receipt. Device, ADB, reboot, OTA and signing operations are outside this
tool's scope.

Duplicate members remain denied. The only exception is an explicitly contracted
legacy duplicate-directory migration that matches the path and complete ordered
mode sequence exactly, emits one non-writable directory, and is recorded in the
receipt. Such a rule can never cover a file, link, special member, unexpected
duplicate, changed sequence, or unused exception.

Known legacy files may be removed only through `legacy_prune_members`, whose
exact path/type/mode/bytes/SHA-256 tuple is checked before discard and recorded
in the receipt. It is not recursive: missing descendants, digest drift,
duplicates, links, special files, unused rules, and replacement-path pruning
all fail closed.
An invalid historical name containing a literal backslash can only be removed
by the separate exact raw-name prune contract; canonical path handling remains
strict for every output member.
Reusable contracts keep all migration arrays empty. Historical migrations are
supplied separately with `--legacy-migration`; the packager requires an exact
base byte-size/SHA-256 match and rejects mixed inline plus external rules.
Root-absolute symlinks remain denied by default. One exact base-bound migration
may convert a complete, count- and inventory-hash-bound set to equivalent
relative targets; every converted path and target is audited in the receipt,
and any overlap with injected replacement content fails closed.

Files whose names contain historical version tags, including
`package_internal_alpha_rootfs_v9.py`, are retained for receipt archaeology and
must not be used as current Evidence Factory entrypoints.

## shell.exec.v1 product artifacts

- `build_shell_exec_artifact_set.py` is the offline control-owned builder for
  the Root-Linux MCP adapter and Android broker/worker. It requires an explicit
  closed-v2 source BOM, Android tree, empty artifact root, resolved manifest,
  fixed Rust 1.95 toolchain tree, Cargo home tree, direct
  Cargo/Rustc/target-linker ELFs,
  an explicit static host-linker wrapper plus Zig 0.14.1 driver/toolchain tree,
  and one explicit static x86-64 `qemu-aarch64-static` ELF. It recreates the
  complete 23-project/two-tree BOM before and after compilation and requires
  byte equality with the supplied BOM. It
  uses the single `android-product` feature with `--locked --frozen --offline
  --release --target aarch64-unknown-linux-musl --no-default-features`, and
  atomically publishes exactly three fully static AArch64 ELFs plus
  `trillionnium-shell-exec-artifact-set-v1.json`.
- Cargo runs with a literal environment, empty `PATH`, retained executable file
  descriptors, a Landlock filesystem allowlist, an
  addressable/network-socket-denying seccomp filter, and a private target tree.
  Rust's local AF_UNIX exec-error channel remains usable;
  `connect`/`bind`/`listen`, nonlocal socket pairs, `setsid`, and `io_uring`
  remain denied.
  Host build scripts link through the retained static `zig-cc` argv wrapper.
  The wrapper fixes `x86_64-linux-gnu` plus baseline CPU, inserts Zig's `cc`
  subcommand and `execve`s the retained Zig descriptor through
  `/proc/self/fd/<n>`; it performs no host ABI discovery or `PATH` lookup.
  Cargo receives exactly eight explicit input-authority roles: Cargo, Rustc,
  target linker, wrapper, Zig, Zig root, immutable Cargo input and private
  target. Each is independently reopened read-only so a build descendant does
  not share the builder's original open-file-description. Identity, status
  flags and descriptor flags are checked before and after the complete Cargo
  session. The Cargo ELF duplicate is also the exact exec descriptor; the
  Landlock ruleset FD is closed by the pre-exec restriction step. The source
  BOM, manifest, Android/artifact roots and publication parent are never
  inherited. Receipt hashing records stable role labels rather than runtime FD
  numbers, and rejects every unknown `/proc/self/fd/<n>` reference.
  `ZIG_LIB_DIR` uses the retained Zig-root directory role, both
  Zig cache roots are private target scratch, and no ambient `cc`, compiler
  search path, or Zig cache participates. Cargo's writable lock/use-tracking
  metadata is likewise confined to a target-scratch Cargo home; only explicit
  `registry`/optional `git` payload links resolve through the retained,
  immutable Cargo-home fd. The complete Rust, Zig, and Cargo-home trees are
  byte-inventoried before and after the build; Zig and Cargo inputs must also
  be owner-read-only. Cargo output hardlinks are accepted only after a bounded
  descriptor walk proves every link to the inode is inside private target
  scratch. The target tree is descriptor-walked and removed before
  any public pathname; a distinct four-file directory is published with
  `renameat2(RENAME_NOREPLACE)`. The builder rejects host-conformance features,
  malformed/non-executable ELF layouts, dynamic interpreters, `DT_NEEDED`,
  uint64 address-end wrap (including an end exactly at 2^64), AArch64 loads
  outside the lower 48-bit product user range, writable-executable loads or
  stack, retired provider markers, a dirty or cross-spliced checkout, ambient
  Cargo configuration, closure mutation, and any existing output path. Its
  retained, byte-measured QEMU input must really
  load and start each captured
  AArch64 ELF before target-scratch cleanup and publication: adapter with no
  arguments must emit its usage failure at exit 2, broker with a fixed invalid
  argument must exit 2, and worker with no inherited fixed FDs 3-6 must fail
  closed at exit 1. Each probe has a 15-second timeout and 256-KiB combined
  output bound. The QEMU digest is explicit in the receipt's bounded Cargo
  identity string; its version, digest, probe contract, and captured-output
  digests are also included in that identity's closure hash. These are host
  load/start admission checks, not target-kernel or device-effect evidence. Its
  `product_candidate` receipt is build provenance for the Android receipt stage;
  it is not device-effect or release evidence.

> **Owner-open notice (2026-08-26-r2):** The `package_current_rootfs.py`
> behavior described in the next paragraphs is the historical pre-r2 sealed
> profile. It must not be used to block or define the owner-open Root Linux
> overlay. The owner-open variant packages a normal shell and `adb` without a
> command allowlist; the old measured empty bind target and
> `shell-exec-standard-allowlist.v1.json` are legacy/release outputs only.

- `package_current_rootfs.py` separately creates a measured empty 0555
  `/usr/local/bin/trillionnium-agent-shell` bind target. The executable payload
  comes only from the Android `/system_ext` artifact at boot, so the Root Linux
  archive cannot become a second shell effect authority. It also generates the
  compact, recursively key-sorted, no-LF, mode-0444
  `/etc/trillionnium/shell-exec-standard-allowlist.v1.json`. That closed
  `standard` profile binds 7 fixed non-launcher utility paths (`echo`, `false`,
  `sleep`, `true`, `uname`, `id`, and `printf`) to SHA-256
  values taken from the newly assembled rootfs inventory. The first slice has
  no file/directory constructor, caller-path reader/enumerator, hidden
  workspace-path reporter, or NSS-dependent identity alias; those require a
  separate command domain or stronger disclosure/custody semantics before
  admission.
  The policy file and empty
  bind target are themselves bound by the v9 receipt's self-hashed
  `output_rootfs.members`; the closed v9 `runtime_layout` shape is unchanged.
  Its wire order begins with `entries`, followed by `profile` and `schema`;
  consumers must verify this canonical encoding rather than reserializing a
  declaration-ordered struct.

The shell artifact builder expects private, non-group/world-writable closure
roots, and requires its Zig/Cargo trees to be owner-read-only. In particular,
use a curated immutable Cargo home, Rust 1.95 toolchain copy,
and exact Zig 0.14.1 distribution containing the prebuilt static wrapper; do
not use mutable default caches, a `rustup` shim/symlink, `/usr/bin/cc`, a QEMU
symlink, or a wrapper found through `PATH`. The output parent must be an
existing controlled directory outside every measured input root. A host-only
invocation has this complete explicit shape:

```sh
python3 tools/build_shell_exec_artifact_set.py \
  --workspace /absolute/control-checkout/trillionnium-os \
  --source-bom /absolute/evidence/source-bom.v2.json \
  --android-root /absolute/android \
  --artifact-root /absolute/empty-artifact-input \
  --resolved-manifest /absolute/evidence/resolved-manifest.xml \
  --rust-toolchain-root /absolute/immutable-rust-toolchain \
  --cargo /absolute/immutable-rust-toolchain/bin/cargo \
  --rustc /absolute/immutable-rust-toolchain/bin/rustc \
  --linker /absolute/immutable-rust-toolchain/lib/rustlib/x86_64-unknown-linux-gnu/bin/rust-lld \
  --zig-toolchain-root /absolute/immutable-zig-x86_64-linux-0.14.1 \
  --zig /absolute/immutable-zig-x86_64-linux-0.14.1/zig \
  --host-linker-wrapper /absolute/immutable-zig-x86_64-linux-0.14.1/host-tools/zig-cc-wrapper \
  --qemu-aarch64-static /absolute/immutable-host-tools/qemu-aarch64-static \
  --host-dynamic-loader /absolute/host-runtime/ld-linux-x86-64.so.2 \
  --host-libc /absolute/host-runtime/libc.so.6 \
  --host-libgcc-s /absolute/host-runtime/libgcc_s.so.1 \
  --host-libm /absolute/host-runtime/libm.so.6 \
  --host-libdl /absolute/host-runtime/libdl.so.2 \
  --host-libpthread /absolute/host-runtime/libpthread.so.0 \
  --host-librt /absolute/host-runtime/librt.so.1 \
  --host-libz /absolute/host-runtime/libz.so.1 \
  --host-dev-null /dev/null \
  --cargo-home /absolute/immutable-cargo-home \
  --output /absolute/controlled-output/shell-exec-artifacts
```

This closes the selected source, Cargo dependency/cache, Rust toolchain, Zig
host-linker tree, static argv wrapper, retained QEMU ELF, and literal
process-environment inputs.
The wrapper and Zig driver are individually retained and byte-measured; their
tree root is retained by dirfd and remeasured after
compilation. It does not claim a recursively byte-closed host kernel,
hardware, AVB, device execution, or release boundary; those remain separate
admission evidence.

## Production Agent feature graph

- `production_agent_feature_gate.py` verifies the explicit empty default
  feature tables for the daemon, UDS, D-Bus and tool-runtime crates.
- It resolves the locked offline normal/build feature graph for
  `trillionniumd --no-default-features` and rejects every legacy plan,
  Authority-effect or development fault feature.
- It also verifies that the reviewed Root-Linux builder uses exactly one
  `--no-default-features` production build, explicitly selects only
  `trillionnium-agent-direct-tools/production-durable-hotpath`, and never
  requests all features. The compiled hotpath still fails before any backend
  effect when root-authored kernel launch custody or secure journal
  provisioning is absent.
- `test_production_agent_feature_gate.py` covers transitive legacy activation,
  implicit/mutated defaults and builder-command drift. A PASS is source/build
  graph evidence only; it is not a release or device receipt.
