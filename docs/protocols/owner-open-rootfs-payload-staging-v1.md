# Owner-open Root Linux payload staging v1

Status: **R5 source implementation; rootfs image and Android inclusion pending**

Selected implementation:

```text
tools/owner-open/stage_owner_open_rootfs_payload_release.py
```

## 1. Boundary

The stager converts an owner-authored exact-digest plan into:

```text
private output directory
  root/                                  deterministic staging tree
  owner-open-rootfs.manifest.json        external canonical manifest
```

The same manifest is embedded at:

```text
/etc/trillionnium/owner-open/rootfs.manifest.json
```

It does not invoke `mksquashfs`, create an Android module, modify a device or
claim that an image exists.

## 2. Explicit execution

`--execute` is mandatory. The output must be a new absolute directory under an
owner-controlled parent that is not group/world writable.

All plan entries are fully inspected before the output directory is created.
An invalid digest, source, path, mode, UID/GID or ELF header therefore leaves no
partial payload tree.

## 3. Plan schema

```text
org.trillionnium.owner-open.rootfs-payload-plan.v1
```

Example:

```json
{
  "schema": "org.trillionnium.owner-open.rootfs-payload-plan.v1",
  "payload_id": "owner-open-rootfs-2026-08-28",
  "architecture": "aarch64",
  "libc": "glibc",
  "entries": [
    {
      "role": "owner_open_host",
      "source": "/absolute/build/trillionnium-owner-open-r5-host",
      "destination": "/usr/libexec/trillionnium/trillionnium-owner-open-r5-host",
      "mode": "0555",
      "uid": 0,
      "gid": 0,
      "expected_sha256": "...",
      "require_aarch64_elf": true
    }
  ]
}
```

Every role and destination is unique. The current v1 staging format supports
only root-owned payload entries; image construction later applies the recorded
UID/GID rather than relying on the build user's staging ownership.

## 4. Source admission

Each source must be:

```text
absolute
regular
non-symlink
one hard link
nonempty
at most 512 MiB
not group/world writable
exactly equal to expected_sha256
stable across descriptor-bound inspection and streaming copy
```

The full payload source bytes are limited to 4 GiB and 4,096 entries.

The tool performs two bounded reads: one inspection/hash pass and one streaming
copy/hash pass. A source identity or digest change between those passes aborts
and deletes the output.

## 5. Destination admission

Destinations are canonical absolute paths under a limited Root Linux set:

```text
/bin
/lib
/lib64
/usr/bin
/usr/lib
/usr/lib64
/usr/libexec/trillionnium
/etc/trillionnium
```

The tool rejects traversal, Android partition paths, mutable `/data` paths and
credential-like destinations such as provider auth files, ADB private keys,
SSH keys, secret/token/credential paths.

Credentials and mutable job/event state are provisioned separately after boot.

## 6. ELF check

Entries with `require_aarch64_elf=true` must have:

```text
ELF magic
ELF64 class
little-endian data encoding
EM_AARCH64 machine ID 183
nontruncated ELF header
```

This is a first mechanical gate. The later image builder/qualifier must also
bind the ELF interpreter, libc and shared-library closure.

## 7. Staging filesystem

Only directories below the new `root/` are created or chmodded. The output
parent mode must remain unchanged. Staged files are regular single-link files
with the exact plan mode and bytes.

The staging ownership reflects the build process. Desired image UID/GID is
stored in the manifest and is applied/verified during image construction.

## 8. Manifest

The canonical manifest records:

```text
payload and plan identity
architecture and libc
entry count and total bytes
role and destination
source path and source filesystem identity
mode and desired UID/GID
SHA-256 and byte count
AArch64 ELF header observation
```

Claims remain:

```text
staging_tree_complete = true
rootfs_image_built = false
android_module_bound = false
image_included = false
physical_device_observed = false
public_release = false
```

Claim ceiling:

```text
ROOTFS_PAYLOAD_STAGED_NOT_IMAGE
```

## 9. Failure semantics

Any error removes the newly created output tree. The stager never substitutes a
source, changes a destination, downloads a dependency, retries a changed file or
promotes a partial tree.

## 10. Next gate

The deterministic image builder must:

1. revalidate the entire staging tree against the manifest;
2. use a measured, option-qualified `mksquashfs` executable;
3. apply deterministic ordering, timestamps, ownership, xattr and compression
   settings;
4. build at least twice from independent copies;
5. require byte-identical image hashes;
6. emit image/manufacturer/tool provenance; and
7. keep `image_included=false` until Soong and target-files evidence exists.
