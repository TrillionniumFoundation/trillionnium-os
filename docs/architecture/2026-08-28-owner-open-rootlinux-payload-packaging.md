# ADR: package owner-open runtime as a Root Linux payload

Date: 2026-08-28  
Status: **accepted for R5 owner-open dogfood source development**

## Decision

The selected Host, execution core, Codex runtime, Python interpreter and
owner-open Python tools are Root Linux userland artifacts. They must not be
installed as Android executables under `/system_ext/bin` unless they are
separately built against Android bionic and qualified as Android-native
programs.

The owner-open Android product therefore installs:

```text
Android-native bootstrap and emergency-stop executables
Android init and profile configuration
one read-only Root Linux payload image plus a digest manifest
```

The Root Linux payload contains:

```text
trillionnium-owner-open-r5-host
trillionnium-owner-open-r5-core
Codex executable/runtime
Python runtime or frozen owner-open tools
Codex MCP bridge
connection broker
Codex qualification supervisor
ADB smart-socket relay
ADB exact-argv qualifier
provider adapter and required shared libraries
```

## Layout

Read-only product payload:

```text
/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.squashfs
/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.image-manifest.json
/system_ext/etc/trillionnium/owner-open/profile-v3.json
```

The staging manifest is named owner-open-rootfs.manifest.json and is consumed only by the image builder. The Android install pair uses the distinct image manifest name owner-open-rootfs.image-manifest.json.
The repository's profile-v2 file is the source-selection envelope; the
runtime profile installed on Android is profile-v3 and is validated by the
native bootstrap.

Writable device state:

```text
/data/trillionnium/owner-open/overlay
/data/trillionnium/owner-open/state
/data/trillionnium/owner-open/events
/data/trillionnium/owner-open/jobs
/data/trillionnium/owner-open/spool
/data/trillionnium/owner-open/credentials
```

Runtime mount:

```text
read-only payload lowerdir
+ private writable overlay upper/work dirs
-> /data/trillionnium/owner-open/root
```

The exact filesystem mechanism may be overlayfs, a loop-mounted writable image
or another reviewed Root Linux mechanism. The product profile must select one
before strict image qualification.

## Android-native boundary

Android init starts only reviewed Android-native bootstrap and emergency-stop
artifacts. The bootstrap establishes the Root Linux mount/namespace, verifies
the payload manifest, sets UID/GID/cgroup/resource boundaries and starts the
Root Linux supervisor.

The Root Linux supervisor, not Android init, owns the Host, broker, provider and
ADB relay child processes. Android init observes bootstrap health and retains an
out-of-band stop path.

The init handoff has an explicit data-filesystem barrier: `early-init` resets
`trillionnium.owner_open.data_ready` to `0`; the `post-fs-data` action creates
and `restorecon_recursive`s the private owner-open tree, then sets that property
to `1`. Bootstrap starts only from the combined trigger
`ro.trillionnium.owner_open.enabled=true &&
trillionnium.owner_open.data_ready=1`, so either order of the enabled property
and `post-fs-data` event is fail-closed until the directory action has run.

## ABI boundary

A Root Linux executable is never assumed to run directly under Android merely
because both systems use AArch64. The evidence package must bind:

```text
ELF architecture
interpreter / dynamic loader
shared-library closure
libc family and version
kernel feature requirements
Root Linux rootfs digest
Android target kernel/build fingerprint
```

If a component is rebuilt as Android-native, it receives a separate Soong
module, SELinux domain and qualification path.

## Payload manifest

The payload manifest binds each required entry by:

```text
role
absolute path inside the payload
file type
mode
UID/GID
SHA-256
byte count
ELF interpreter and dependency metadata where applicable
source/provenance identity
```

The bootstrap must fail closed before starting the Host if the payload or
manifest is missing, malformed or inconsistent. This is mechanical integrity,
not semantic command authorization.

## Credentials and mutable state

Provider credentials and ADB keys are not baked into the read-only payload.
They are owner-provisioned into private writable state or supplied through
sealed descriptors. Logs and job/event stores never share the credential path.

## Updates

A payload update is a versioned product artifact. In-place mutation of the
read-only lowerdir is forbidden. Dogfood updates may install a new versioned
payload and atomically switch the selected manifest after verification. Signed
OTA/AVB/rollback integration remains an L6 property.

## Alternatives rejected

### Install Host/Core directly in `/system_ext/bin`

Rejected because the current Host/Core are Root Linux Rust/userland artifacts,
not demonstrated Android-bionic executables. This would hide an ABI mismatch
behind a package name.

### Copy mutable tools into `/data` without a product payload

Rejected as the normal product path because provenance and rollback become
ambiguous. `/data` remains suitable for owner dogfood overrides only when the
active artifact hashes and override status are explicit.

### Run all components as Android apps/services

Rejected for the current owner-open direction because it would collapse the
Root Linux development environment and direct process substrate into the
Android framework boundary. Android-native clients/bootstrap remain thin.

## Consequences

- the Android product profile v2 reserves a rootfs-image module rather than
  pretending Root Linux binaries are Android executables;
- Soong materialization remains open until the payload image and native
  bootstrap artifacts exist;
- init/SELinux work is scoped to the native boundary and client admission;
- Root Linux child lifecycle and filesystem evidence become first-class L3-L5
  requirements;
- the original unselected profile remains historical source material and is
  not the release-candidate product selection.
