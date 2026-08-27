# Operation replay-sync static helper checkpoint

This directory is a deliberately non-authorizing source checkpoint for two
measured helpers:

- `trillionnium-system-api-operation-replay-sync`
- `trillionnium-accessibility-operation-replay-sync`

It does not replace `build-root-linux-arm64.sh`. That older Root Linux lane is
an AArch64 GNU/dynamic build, while the measured launcher requires a static
`aarch64-unknown-linux-musl` `ET_EXEC`. Nothing here is selected by Soong,
`PRODUCT_PACKAGES`, init, `trillionniumd` main, or the launcher authority.

## Frozen posture

The checked-in recipe fixes the two roles, the two builder profiles
(`amd64-cross` and `arm64-native`), `SOURCE_DATE_EPOCH`, the Cargo package and
feature, selected source entrypoints, and the raw ELF/reconciliation contract.
It keeps all of the following false:

- formal 2x2 lane started/completed;
- independent builder custody and signed product verification;
- product installation, fs-verity, and AVB provenance;
- launcher/main/effect/release authority.

Running the script without a subcommand is an argparse error; it never starts
a build. `verify-recipe` and `inspect-elf` are read-only. `build-candidate`
is a fixed HOLD even with the literal
`--acknowledge-non-authorizing-source-only` flag. It exits before opening build
inputs, starting a process, or creating an output. Candidate execution remains
disabled until an outer-owned cgroup-v2 leaf can prove zero survivors and a
fixed-custody publication journal plus external permanent-HOLD path exist.

## Held publication transition model

`publication_custody_model.py` is an unwired, pure transition sketch. It has
no filesystem, process, lock, rename, journal-write, or HOLD-write surface.
Given fresh authenticated observations, it closes every malformed journal
state, explicitly false/malformed/missing barrier fact, ambiguous both/neither
placement, and integer/boolean type confusion to `HOLD`. It also records the
important `RENAME_NOREPLACE` rule that an error may still have committed: only exact
final-only placement may enter committed verification, while exact stage-only
placement after an error may resolve aborted.

The model does not produce or authenticate its observations. Freshness and
authentication remain caller obligations. This checkpoint still has no
provisioned root-owned journal/HOLD roots,
outer-authority HOLD acknowledgement, persistent target lock, retained
mount/inode identity, terminal name/tree barrier, restart reconciliation, or
no-replace record archival. It is not a publisher and must not be wired into
the builder or reconciler. All durable-publication, source-checkpoint, and
authority facts remain false.

## Candidate input receipts

A future isolated lane supplies canonical JSON receipts. They are evidence
inputs, not approvals.

The image receipt schema is
`trillionnium.operation-replay-sync-static-image-receipt.v1` with exactly:

```json
{
  "authority": {"effect_authority": false, "installable": false, "product_authority": false, "release_authority": false},
  "host_arch": "x86_64",
  "claimed_image_id": "sha256:<64 lowercase hex>",
  "invocation_id": "<non-empty lane invocation>",
  "network_mode": "none",
  "profile": "amd64-cross",
  "rootfs_read_only": true,
  "schema": "trillionnium.operation-replay-sync-static-image-receipt.v1"
}
```

The `arm64-native` form uses host arch `aarch64`. The toolchain receipt schema
is `trillionnium.operation-replay-sync-static-toolchain-receipt.v1`. It binds
the profile and target, a target-spec SHA-256, exact `cargo`, `rustc`, linker,
and archiver paths/digests, plus a CRT closure:

```json
{
  "authority": {"effect_authority": false, "installable": false, "product_authority": false, "release_authority": false},
  "crt": {
    "files": [{"path": "crt1.o", "sha256": "<hex>", "size": 1}],
    "manifest_sha256": "<domain-separated manifest digest>",
    "root": "/absolute/read-only/crt-root"
  },
  "profile": "amd64-cross",
  "schema": "trillionnium.operation-replay-sync-static-toolchain-receipt.v1",
  "target": "aarch64-unknown-linux-musl",
  "claimed_target_spec_sha256": "<hex>",
  "tools": {
    "archiver": {"path": "/absolute/path", "sha256": "<hex>"},
    "cargo": {"path": "/absolute/path", "sha256": "<hex>"},
    "linker": {"path": "/absolute/path", "sha256": "<hex>"},
    "rustc": {"path": "/absolute/path", "sha256": "<hex>"}
  }
}
```

The CRT list must include `crt1.o`, `crti.o`, `crtbegin.o`, `crtend.o`,
`crtn.o`, `libc.a`, and `libunwind.a`. The builder remeasures every named
tool and CRT file. CRT entries must be sorted and unique, use canonical bounded
ASCII relative paths, and stay within 128 files, 256 MiB per file, and 512 MiB
total. Tools and CRT files are opened component by component without following
symlinks. Tool files, the CRT root, CRT directories beneath that root, and CRT
regular files must be read-only.
The target-spec and image identifiers are explicitly `claimed_*`: this
checkpoint does not prove the running compiler/image came from those
identifiers. The future candidate implementation rejects `.cargo/config` and
`.cargo/config.toml` from the source root and every ancestor before Cargo, and
inventories a read-only, symlink-free full source snapshot and a physically
separate read-only Cargo vendor snapshot around the locked/offline invocation.
These checks are useful future drift evidence, but compiler read-set, hostile
same-UID custody, network-namespace observation, and product authority remain
false.

The unreachable future implementation retains its private work directory by
descriptor and does not recursively delete it. POSIX has no unlink-by-FD
operation, so pathname cleanup would reintroduce a same-UID rebind race. A
future isolated/ephemeral lane must own cleanup after the builder exits; its
candidate receipt would record `automatic_work_cleanup_performed=false`.

## ELF and reconciliation contract

The verifier parses ELF bytes itself; `file` and `readelf` are not authority.
It requires AArch64, little-endian ELF64, `ET_EXEC`, no `PT_INTERP`, no
`PT_DYNAMIC`/`SHT_DYNAMIC`, one executable entry segment, exactly one
non-executable `PT_GNU_STACK`, bounded/aligned program and section tables, and
no combined writable+executable page caused by overlapping `PT_LOAD`s at
4 KiB, 16 KiB, or 64 KiB page sizes. Every load is also offset/address
congruent for all three page sizes and advertises at least 64 KiB alignment.

Reconciliation retains both bundle-root descriptors, both receipt descriptors,
and all four artifact descriptors through one final absolute-path/name/inode/
mode/bytes barrier. It requires the exact profile pair, equal
source/Cargo.lock/vendor/claimed-target-spec/CRT facts, byte-identical output
for the same role, byte-distinct output between roles, and rejects a
cross-profile role exchange. Without `--output`, reconciliation emits only a
`PREVIEW_SOURCE_ONLY_UNWIRED_BYTE_RECONCILIATION` JSON document on stdout.
Persistent `--output` publication is a fixed HOLD before receipt inputs are
opened. A content-complete bundle or preview document is not a publication
terminal and confers no promotion authority; the fixed journal and external
permanent-HOLD path remain prerequisites. Toolchain and image receipts remain
profile-specific and do not confer authority.

## Commands

Read-only checks:

```bash
PYTHONDONTWRITEBYTECODE=1 \
  python3 packaging/operation-replay-sync-static/build_operation_replay_sync_static.py \
  verify-recipe

PYTHONDONTWRITEBYTECODE=1 \
  python3 packaging/operation-replay-sync-static/verify_operation_replay_sync_static.py \
  artifact /path/to/helper

PYTHONDONTWRITEBYTECODE=1 \
  python3 -m unittest discover \
  -s packaging/operation-replay-sync-static/tests \
  -p 'test_*.py' -v
```

Deliberately rejected candidate build shape:

```bash
python3 packaging/operation-replay-sync-static/build_operation_replay_sync_static.py \
  build-candidate \
  --profile amd64-cross \
  --source-root /read-only/source-snapshot \
  --vendor-dir /read-only/cargo-vendor \
  --toolchain-receipt /lane/toolchain-receipt.json \
  --image-receipt /lane/image-receipt.json \
  --output /lane/system-helper-candidate \
  --acknowledge-non-authorizing-source-only
```

This exits with status 78 before inspecting the supplied paths. Persistent
reconciliation with `--output` is rejected at the same early boundary; only
stdout preview reconciliation is reachable.

The formal 2x2 build, root-owned importer, fs-verity enable/remeasure, signed
Android descriptor, product graph, SELinux/cgroup ceremony, launcher authority,
fixed-custody publication journal, real effect, OTA, and locked-green device
evidence all remain separate HOLDs.
