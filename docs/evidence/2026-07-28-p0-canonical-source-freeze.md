# 2026-07-28 P0 canonical source freeze

## Decision

This checkpoint freezes one local exact Android source graph and a
remote-assisted escrow for every locally orphaned project head. It is not a
remote-reproducible release source, a mode-safe fresh builder lane, or an
offline self-contained Android mirror.

The exact decisions are:

- `PASS_LOCAL_EXACT_CLEAN_GRAPH`
- `PASS_LOCAL_REMOTE_ASSISTED_ESCROW`
- `HOLD_REMOTE_CANONICAL_CLOSURE`
- `HOLD_OFFLINE_SELF_CONTAINED_SOURCE_FREEZE`
- `HOLD_MODE_SAFE_FRESH_LANE`
- `HOLD_BUILD_SIGN_OTA_DEVICE`

No source ref was pushed. No build, signing operation, OTA generation, device
write, install, reboot, or release promotion was authorized or performed.

## Unique local source candidates

The only control-plane candidate is:

```text
/home/qian-qi/trillionnium-release-sources/control-plane-full-hardening-20260716
```

Its pre-report implementation head was
`ce8637115d138be57edbeddafdb56ea1b66ea9ec`. Other worktrees and the
non-Git `trillionnium-d-direct-tree.ofcd1J` directory are not canonical
inputs.

The Android source candidate is:

```text
/home/qian-qi/android/lineage-fogos
```

The current checkout is source material only. Its ancestor and checkout modes
remain unsuitable for a release clean-lane PASS, and it already has build
output. A future builder must use a new mode-0750 lane with no local manifests
or pre-existing `out/`.

## Exact Android graph

The tracked and locally selected manifest is:

```text
.repo/manifests/trillionnium-fogos.xml
```

Its SHA-256 is
`2508f5a104fa87440ebbc321f6bb8f8e5b7174a7baec78af864c0c7c8b8491b7`.
It contains 1,172 unique projects. At the freeze:

- every project path existed;
- every checkout `HEAD` equalled its exact manifest revision;
- every project worktree was clean, including untracked-file inspection;
- every revision was an exact SHA;
- no `local::` provenance remained;
- the active selector contained only
  `include name="trillionnium-fogos.xml"`;
- the floating `.repo/local_manifests/roomservice.xml` truth was removed from
  the active checkout and retained in the external escrow for recovery.

The manifest repository head is
`d558b74b53bd6df9be617f295d13c7db6c42c0e7`. It is local-only at this
checkpoint.

## Two distinct custody sets

The fixed critical gate is deliberately narrow. It is named the
`Direct/agent/release-authority critical subset`, not the complete product
source union.

It contains 14 projects:

1. `packages/apps/TrillionniumAiShell`
2. `packages/apps/TrillionniumAiAuthority`
3. `packages/apps/Dialer`
4. `trillionnium-sdk`
5. `vendor/trillionnium`
6. `external/XMP-Toolkit-SDK`
7. `external/google-highway`
8. `external/skia`
9. `external/android-key-attestation`
10. `device/trillionnium/sepolicy`
11. `system/sepolicy`
12. `trillionnium-os/tools`
13. `trillionnium-os/contracts`
14. `trillionnium-os/schemas`

The subset has 11 private and three public Foundation repositories. Dialer,
Android key attestation, and platform sepolicy use expected private canonical
names that do not yet exist or are not visible. XMP, highway, and skia are
public Foundation forks. Ten of the 14 exact heads remain unpublished and
contain 52 commits beyond their nearest local remote-tracking ancestors.

The complete manifest exception set is larger:

- 88 project heads are not contained by any local remote-tracking ref;
- those heads contain 136 commits beyond their closest remote ancestors;
- the raw local object payload is 2,683,849,740 bytes;
- 50 of those projects have modified files directly intersecting the current
  fogos `droid` input graph.

The 14-project gate must never substitute for 1,172-project manifest closure.

## External remote-assisted escrow

The external package is:

```text
/data/trillionnium-p0-canonical-source-freeze-20260728
```

It contains:

- a 1,172-project path/name/revision/head/tree/remote inventory;
- 88 verified thin Git bundles, one per remote-exception project;
- exact prerequisite SHA and remote-tracking ref bindings;
- full bundles for the five standalone Android repositories and the manifest
  repository;
- a final full control-plane bundle;
- four Chromium WebView Git LFS payloads whose SHA-256 values equal their LFS
  object IDs;
- the retired selector and floating local manifest;
- exact manifest candidates, generator HOLD receipt, evidence hashes, restore
  instructions, and a top-level checksum closure.

The 88 thin bundles total 1,818,824,655 bytes. They are remote-assisted:
each requires its recorded prerequisite. A force-push, repository deletion,
or server garbage collection may make recovery fail. Four WebView payloads
totalling 834,528,114 bytes are separately escrowed, so their bytes do not
depend on a later LFS fetch.

The tree-object scan covered 1,648,755 records and found zero missing objects.
The manifest also contains 67 gitlinks across 12 projects. Their target
repositories are indexed but not separately escrowed, so offline source
closure remains HOLD.

## P0-1/P0-3 ordering constraint

A product-path `launch_package` device loop cannot currently precede the final
payload work:

- production provider admission stops before provider spawn;
- fixed provider/tool cgroup custody is absent;
- journal first-use and allocator/transport product constructors are absent;
- Android activation, exact result, outer ACK, and publisher wiring are not
  connected;
- the attached device runs the older Bridge/CommandCenter/tar-rootfs image.

The only honest P0-1-before-P0-3 interpretation is a separately signed,
explicitly enabled `userdebug`/`eng` non-product device-conformance lane. It
must keep all product availability and exactly-once claims false. No such lane
was promoted by this checkpoint.

Current P0-3 assets are host foundations only. The minimal Bookworm EROFS base
repeats byte-for-byte on one host, but trusted independent builder approval is
0/2; final Codex/OpenClaw payloads, fs-verity product wiring, clean
target-files, a current signed OTA, locked-green device evidence, and fault
matrix proof remain absent.

## Required next authority

Remote closure requires an explicit publication decision because the current
policy forbids pushes:

1. create or approve canonical repositories for every retained local fork;
2. publish or explicitly revert all 88 remote-exception heads, plus the
   control and manifest heads;
3. prove exact object reachability from a second empty-cache checkout;
4. create the mode-safe fresh builder lane;
5. only then promote the narrow non-product device-conformance slice or change
   the P0-1/P0-3 ordering.

