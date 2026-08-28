# R5 Batch E — Android owner-open profile split

Status: **unselected source contract landed; Soong/init/SELinux/image work remains open**

## Purpose

This batch creates a clean owner-open product boundary without pretending that
unbuilt Host artifacts are already Android modules.

Canonical profile:

```text
android-integration/owner-open-profile/profile.json
```

Generated, intentionally unselected make fragment:

```text
android-integration/owner-open-profile/generated/owner_open_packages.mk
```

Generator and verifier:

```text
tools/generate-owner-open-android-profile-v2.py
tools/verify-owner-open-android-profile.py
```

## Current truth

The profile states:

```text
selected_in_current_product = false
soong_modules_bound = false
init_services_bound = false
selinux_domains_bound = false
target_files_built = false
image_included = false
physical_device_observed = false
public_release = false
```

Required product module names are therefore marked
`UNBOUND_SOONG_MODULE`. The generated make fragment must not be included by the
current product until materialization and strict verification are complete.

## Product boundary

The owner-open profile requires source for:

- selected v5/v7 Host package;
- Codex MCP bridge;
- local connection broker;
- release Codex qualification supervisor;
- release byte-transparent ADB relay; and
- release exact-argv ADB qualifier.

Target product modules are reserved for:

```text
trillionnium-owner-open-host
trillionnium-owner-open-core
trillionnium-owner-open-python-tools
trillionnium-owner-open-profile-config
```

The names are a product contract, not evidence that Soong currently resolves
them.

## Forbidden legacy graph

The profile forbids the pre-r3 semantic closure, including:

```text
AiAuthority
Capability Lease
legacy egress guard
operation/P01 custody and receipt nodes
old shell broker/worker
legacy semantic ADB package
legacy plan submission markers
```

Foundation verification reports exact occurrences in the checked-in audit
overlay as W6 holds. Strict verification treats every remaining occurrence as a
hard error.

## Foundation versus strict verification

Foundation mode is expected to pass source-shape checks while reporting:

```text
current overlay legacy-package holds
unbound Soong modules
profile not selected
image not claimed
```

Strict mode passes only when all of the following are true:

1. `selected_in_current_product=true`;
2. every product module is `BOUND_SOONG_MODULE`;
3. Soong, init and SELinux binding claims are true;
4. target-files and image inclusion claims are true;
5. the current product includes the generated owner-open fragment;
6. the current product contains zero forbidden legacy packages; and
7. generated source has no drift.

The CI gate deliberately requires strict verification to fail on the current
unselected/unbound tree. A surprise strict pass would be a false promotion and
therefore fails CI.

## Next implementation work

### E-A — artifact materialization

- cross-compile the selected Rust Host and core for the target Root Linux/ARM64
  environment;
- select a Python runtime or freeze the release tools into reviewed executables;
- create Soong modules with exact source/artifact hashes;
- generate install manifests and SBOM/provenance records.

### E-B — lifecycle

- define Android init bootstrap for the Root Linux environment;
- define Root Linux supervisor units for Host, broker and ADB relay;
- separate executable, configuration, credential, event, job and spool paths;
- define finite restart and crash-loop behavior;
- provide emergency stop independent of Codex/provider health.

### E-C — admission and SELinux

- choose Android abstract socket versus Root Linux filesystem socket per
  endpoint;
- bind UID/GID and SELinux peer domains;
- ensure AiShell receives only the owner-open client domain;
- prevent unrelated apps/processes from reaching Root Linux effect sockets;
- test path replacement, symlink and namespace boundaries.

### E-D — AiShell

- implement the thin turn/MCP/job client;
- implement bounded flow-window and cursor recovery;
- show unknown-after-disconnect without offering blind retry;
- expose emergency-stop status without becoming a semantic approval gate.

### E-E — evidence

- clean target-files build;
- package/service/init/SELinux inclusion and exclusion manifests;
- physical same-turn shell, pipe/PTY job and ordinary ADB effects;
- provider/Host/broker/client/USB/reboot/ENOSPC/power-loss matrix.

No profile contract or generated make fragment raises the project above L0 by
itself.
