# R5 Batch E — Root Linux payload Android product profile

Status: **source contract and strict state machine implemented; artifact materialization and Android build open**

## Selected product architecture

The owner-open Host/Core/Codex/Python runtime is packaged inside one read-only
Root Linux payload. Android installs only:

```text
rootfs payload image
rootfs digest/provenance manifest
Android-native bootstrap
Android-native emergency stop
init configuration
profile configuration
```

Canonical source selection:

```text
android-integration/owner-open-profile/profile-v2.json
android-integration/owner-open-profile/generated/owner_open_packages_v2.mk
tools/generate-owner-open-android-profile-v3.py
tools/verify-owner-open-android-profile-v3.py
.github/workflows/owner-open-r5-android-profile-v3.yml
```

Machine contract:

```text
docs/contracts/owner-open-r5-android-profile-selection-v1.json
```

## Why this replaces the earlier package shape

A Linux AArch64 executable is not automatically an Android-bionic executable.
Installing the current Root Linux Host/Core directly under `/system_ext/bin`
would hide the dynamic loader, libc and userland dependency boundary.

The v2 profile instead reserves:

```text
/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.squashfs
/system_ext/etc/trillionnium/rootlinux/owner-open-rootfs.manifest.json
```

The payload is mounted read-only and combined with private writable state under
`/data/trillionnium/owner-open/`.

## Current source truth

The checked-in profile remains deliberately unselected:

```text
selected_in_current_product = false
source_contract_only = true
rootlinux_payload_bound = false
android_bootstrap_bound = false
soong_modules_bound = false
init_services_bound = false
selinux_domains_bound = false
target_files_built = false
image_included = false
physical_device_observed = false
public_release = false
```

Every Root Linux payload entry is `UNBOUND_ROOTFS_ENTRY`; the payload image and
manifest are unbound; every Android product module is
`UNBOUND_SOONG_MODULE`; services/endpoints remain contract-only or host-source
only.

## Strict v3 promotion requirements

Strict verification requires all of the following simultaneously:

1. the v2 profile is explicitly selected by the current product;
2. `source_contract_only=false`;
3. Root Linux payload image and manifest are bound;
4. every required Root Linux entry is bound by hash/provenance;
5. Android-native bootstrap and emergency stop are bound;
6. every product module is a reviewed Soong module;
7. Android-init services are `BOUND_INIT_SERVICE`;
8. Root Linux supervisor services are `BOUND_ROOTLINUX_SERVICE`;
9. every local endpoint is `BOUND_ENDPOINT`;
10. init and SELinux source compile;
11. target-files and image claims are true;
12. the current product includes the v2 generated fragment;
13. no forbidden Authority/lease/P01/old-shell package remains.

Claim implications are enforced. For example, `image_included=true` cannot
precede payload/bootstrap/target-files binding, and physical/release claims
cannot precede image/device evidence.

## E1 — payload builder

Implement a deterministic builder that accepts exact source artifacts and emits:

```text
owner-open-rootfs.squashfs
owner-open-rootfs.manifest.json
SBOM/provenance record
reproduction command log
```

Required validation:

- AArch64 ELF class/machine/interpreter;
- libc and shared-library closure;
- file type/mode/UID/GID;
- SHA-256 and byte count for every entry;
- no credentials or mutable event/job state;
- no group/world-writable executable;
- no symlink escaping the rootfs;
- reproducible sorted filesystem input.

## E2 — Android-native bootstrap

Implement a minimal native bootstrap that:

1. validates profile, payload and manifest;
2. establishes mount/user/PID/network namespaces as selected;
3. creates private writable overlay/state paths;
4. applies UID/GID, resource and cgroup limits;
5. mounts the read-only payload plus writable layer;
6. starts one Root Linux supervisor;
7. reports bounded health to Android init;
8. refuses partial or changed payload state;
9. exposes no command semantics; and
10. responds to independent emergency stop.

The bootstrap is an integrity/lifecycle boundary, not a planner or approval
engine.

## E3 — endpoint and SELinux selection

Select one Android-native client ingress. The current profile intentionally
leaves it unselected because the Python filesystem broker alone is not a
sufficient Android SELinux boundary.

The selected boundary must bind:

```text
client UID/GID
server domain
connectto/socket permissions
owner token or equivalent connection binding
Root Linux broker handoff
frame/queue/client limits
disconnect and cancellation truth
```

AiShell receives only the thin client domain. Unrelated apps and shell domains
must be denied.

## E4 — Soong and product integration

After real artifacts exist:

- create reviewed `prebuilt_etc` modules for payload, manifest, profile and init
  files;
- create native binary modules for bootstrap and emergency stop;
- bind exact module source hashes;
- update v2 profile states to bound values;
- include only the generated v2 package fragment;
- remove forbidden legacy packages from the owner-open product;
- run strict v3 verification before target-files.

## E5 — evidence

L3 requires clean target-files plus exact package/init/SELinux/payload evidence.
L4 requires physical same-turn shell, durable job and ordinary ADB effects. L5
requires provider/Host/broker/bootstrap/USB/reboot/ENOSPC/power-loss cases and
an emergency-stop proof independent of Codex/provider availability.

The profile, fragment and verifier remain L0 source evidence until those gates
execute.
