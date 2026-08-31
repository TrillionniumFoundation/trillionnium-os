# Owner-open Root Linux image build v1

Status: **R5 source implementation; real mksquashfs, Soong and Android image evidence pending**

Selected builder:

```text
tools/owner-open/build_owner_open_rootfs_image_release_v2.py
```

Input contract:

```text
docs/protocols/owner-open-rootfs-payload-staging-v1.md
```

## 1. Boundary

The image builder accepts only a private staging output whose external and
embedded manifests are identical and whose entire file tree still matches the
manifest.

It produces:

```text
owner-open-rootfs.squashfs
owner-open-rootfs.image-manifest.json
```

It does not create or select an Android Soong module and does not claim that the
image is present in target-files or on a device.

## 2. Explicit execution

`--execute` is mandatory. Required inputs include:

```text
absolute staging directory
absolute mksquashfs executable
expected mksquashfs SHA-256
new private output directory
at least two reproducibility runs
finite help/build timeouts
```

The output is removed on any validation, tool, timeout or reproducibility
failure.

## 3. Staging revalidation

Before the image tool starts, the builder verifies:

- staging manifest schema and source claims;
- external and embedded manifest byte identity;
- all declared files exist with exact SHA-256, byte count and mode;
- no undeclared files;
- no symlinks, hard links, devices, sockets or FIFOs;
- every directory is mode `0755`; and
- the path set exactly matches the staging manifest plus its embedded copy.

This closes the interval between staging and image construction.

## 4. Image tool admission

The exact `mksquashfs` executable must be:

```text
absolute
regular
non-symlink
one hard link
executable
not group/world writable
within the configured byte bound
equal to expected_mksquashfs_sha256
```

A bounded `-help` probe must advertise:

```text
-noappend
-all-root
-no-xattrs
-no-exports
-no-progress
-comp
-b
-mkfs-time
-all-time
-sort
```

No unobserved option is silently substituted.

## 5. Deterministic build invocation

Each run uses an independent normalized copy of the staging root. File bytes and
modes are rechecked during the copy, and every file/directory timestamp is set
to the epoch.

Canonical options:

```text
-noappend
-all-root
-no-xattrs
-no-exports
-no-progress
-comp zstd
-b 131072
-mkfs-time 0
-all-time 0
-sort <generated deterministic sort file>
```

The sort file assigns stable priorities to the lexically sorted file set.
Build environment is restricted to a finite PATH plus `LC_ALL=C` and `TZ=UTC`.
No shell is used.

## 6. Process lifecycle

Help and build commands execute in separate process groups. On timeout the
builder sends TERM, waits a finite grace, sends KILL if required and reaps the
leader. A timed-out or unreaped tool never yields an image claim.

Stdout and stderr are bounded and represented in the image manifest by byte
counts and digests rather than trusted prose.

## 7. Reproducibility

The builder performs two to four independent runs. All resulting image byte
counts and SHA-256 values must be identical. The selected output therefore has
byte-identical image hashes across the independent runs. Any difference removes
the whole new output directory.

The selected image is made read-only after comparison. Run roots, sort files and
secondary images are removed.

The v1 image-manifest schema now requires the complete entries inventory.
Older v1 manifests that contain only aggregate counts are rejected by both the
materialization verifier and the Android bootstrap; this prevents a stale
manifest from being paired with a newly built image.

## 8. Image manifest

The external image manifest binds:

The image manifest also carries runtime_state_directory with the exact value /var/lib/trillionnium/owner-open. The builder refuses a staging tree that does not contain this real 0755 directory, because Android bootstrap binds /data/trillionnium/owner-open/state over it.

```text
payload/plan/staging manifest identity
architecture and libc
entry count
complete per-entry role, payload path, mode, UID/GID, byte count and SHA-256
records (the Android-native bootstrap validates these records against the
mounted image before starting Root Linux)
mksquashfs path, inode and SHA-256
help observation digests
canonical option vector
per-run command/output/image observations
reproducibility run count
selected image SHA-256 and byte count
```

Claims:

```text
staging_revalidated = true
deterministic_options_observed = true
independent_builds_byte_identical = true
rootfs_image_built = true
android_module_bound = false
target_files_built = false
image_included = false
physical_device_observed = false
public_release = false
```

Claim ceiling:

```text
ROOTFS_IMAGE_BUILT_NOT_ANDROID_INCLUDED
```

## 9. Remaining qualification

A host-process fixture or fake image tool does not prove a valid squashfs. The
next evidence gate must use the measured target build tool and additionally
validate the resulting filesystem with an independent reader such as
`unsquashfs`, bind ELF interpreter/shared-library closure and compare a clean
rebuild on an independent build host.

Android promotion still requires Soong modules, strict Android profile v3,
clean target-files and physical boot/effect evidence.
