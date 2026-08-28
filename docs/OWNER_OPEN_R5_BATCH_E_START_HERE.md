# Owner-open R5 Batch E: start here

R3 remains the normative product-semantic contract. R5 remains the active
implementation and evidence sequence. Batch E now owns target qualification,
Root Linux payload packaging and Android product convergence.

## Read in this order

1. `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`
2. `TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`
3. `architecture/2026-08-28-owner-open-rootlinux-payload-packaging.md`
4. `plan/owner-open-r5-batch-e-release-selection.md`
5. `plan/owner-open-r5-batch-e-physical-adb.md`
6. `plan/owner-open-r5-batch-e-rootlinux-payload-profile.md`
7. `contracts/owner-open-r5-selected-python-paths-v1.json`
8. `contracts/owner-open-r5-rootfs-payload-selection-v1.json`
9. `contracts/owner-open-r5-android-profile-selection-v1.json`
10. `status/owner-open-r5-batch-e-status.json`
11. `status/owner-open-r5-rootfs-payload-status.json`
12. `status/owner-open-r5-android-profile-v3-status.json`

## Selected source path

```text
Codex / AiShell / owner client
  -> connection-bound local MCP and broker mechanics
  -> selected v5 bounded transport
  -> selected job-aware v7 execution core
  -> direct shell / ordinary adb / durable shell.job

Android product
  -> Android-native bootstrap and emergency stop
  -> read-only Root Linux payload image and manifest
  -> private writable overlay/state under /data/trillionnium/owner-open
  -> Root Linux supervisor
       -> Host / core / Codex / Python tools / broker / ADB relay
```

The Host/Core/Codex/Python runtime is not selected as an Android
`/system_ext/bin` executable closure. It lives inside the Root Linux payload and
is qualified against its own loader, libc and shared-library environment.

## Selected qualification entries

```text
tools/owner-open/supervise_codex_mcp_qualification_release.py
tools/owner-open/adb_smart_socket_relay_release.py
tools/owner-open/qualify_owner_open_adb_release.py
tools/owner-open/stage_owner_open_rootfs_payload_release.py
tools/owner-open/build_owner_open_rootfs_image_release_v2.py
```

Machine selection contracts prevent the earlier draft implementations from
being referenced by release plans, status promotion or selected workflows.

## Current claim ceiling

```text
source implementation and source-shape qualification only
SOURCE_IMPLEMENTED / L0
```

The following remain false:

```text
final exact-checkout runner closure passed
final Rust lock/metadata/feature graph reviewed
installed target Codex qualified
physical ordinary adb target qualified
real Root Linux payload staged
real squashfs image built and independently inspected
Soong/init/SELinux bound
clean Android target-files built
physical device observed
fault/reboot/power-loss qualified
public release
```

## Exact source gates

```sh
python3 tools/verify-owner-open-selected-paths.py --json
python3 tools/verify-owner-open-rootfs-payload-selection.py --json
python3 tools/verify-owner-open-android-profile-selection.py --json
python3 tools/generate-owner-open-android-profile-v3.py --check
python3 tools/verify-owner-open-android-profile-v3.py --json

python3 -m unittest \
  tools.tests.test_verify_owner_open_selected_paths \
  tools.tests.test_verify_owner_open_rootfs_payload_selection \
  tools.tests.test_verify_owner_open_android_profile_selection \
  tools.tests.test_stage_owner_open_rootfs_payload_release \
  tools.tests.test_build_owner_open_rootfs_image_release_v2 \
  tools.tests.test_release_qualification_paths_v2 \
  tools.tests.test_supervise_codex_mcp_qualification_release \
  tools.tests.test_verify_owner_open_android_profile_v3 \
  -v

cargo generate-lockfile
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
cargo metadata --locked --format-version 1
```

The current unselected Android profile is expected to fail:

```sh
python3 tools/verify-owner-open-android-profile-v3.py --strict --json
```

A strict pass before real payload/bootstrap/Soong/init/SELinux/target-files
binding would be a false promotion.

## Next critical path

1. execute all selected Python and Rust gates on one exact final commit;
2. repair every real runner finding and bind logs, lockfile, metadata and feature
   trees;
3. stage the real Host/Core/Codex/Python/provider/shared-library payload;
4. build and independently inspect a real reproducible squashfs image;
5. implement Android-native bootstrap and emergency stop;
6. bind Soong modules, init, SELinux and the chosen Android client ingress;
7. run supervised installed-Codex and physical ordinary-adb qualification;
8. build clean target-files and collect L3-L5 evidence.
