# Minimal Bookworm / EROFS host reproducibility checkpoint

Date: 2026-07-28

Status: **HOST ARTIFACT PASS / PRODUCT AND RELEASE HOLD**

This checkpoint covers a new Debian Bookworm arm64 base built in two disjoint
temporary trees on one host. It does not contain the final daemon, Codex or
OpenClaw provider payload, does not update an Android product pin, does not
enable fs-verity on Android, and does not authorize a mount, device write, OTA
signature or release promotion.

## Frozen inputs

- Contract:
  `tools/evidence-factory/minimal-bookworm-rootfs.contract.v1.json`
  - SHA-256:
    `7a07c25b0a605417989118cd934171b4ca2720f8eee3c7a6e58fa2fd19117d36`
  - Debian snapshot: `20260727T000000Z`
  - exact resolved allowlist: 35 packages, including versions and
    architectures
  - every production, product-pin, device, signing and promotion authority:
    `false`
- Minimal builder SHA-256:
  `a18504fc5b9d49a95f04ea8fd335e535bc8756b0dfb06c2a22eee4ccb7454cce`
- Immutable-image builder SHA-256:
  `3cedcf805a9e8a96a80f022be1c11536591587498c39f022be57e2471bfa7b2a`
- Debian keyring package:
  - version: `2025.1`
  - bytes: `179244`
  - SHA-256:
    `9ea7778e443144ca490668737a8ab22dd3e748bb99e805e22ec055abeb3c7fac`
  - extracted keyring SHA-256:
    `506b815cbb32d9b6066b4a2aa524071e071761e7e7f68c3ac74f3061ba852017`
  - independent-origin approval remains `false`
- Both exact snapshot `InRelease` files passed `gpgv` with the frozen
  keyring. Their byte counts and SHA-256 values are bound by the contract and
  repeated in each receipt.
- `mmdebstrap`, `dpkg-deb`, `dpkg-query`, `gpgv`, `zstd`, `mkfs.erofs` and
  `fsverity` were SHA-256 pinned before use.

## Two-build results

The two builds used distinct `mmdebstrap` roots and distinct final output
paths. Exact byte comparison passed for all five outputs:

| Artifact | Bytes | SHA-256 |
| --- | ---: | --- |
| normalized `rootfs.tar.zst` | 10,959,228 | `aca0b46b938db2eacc8095f9f265308cb87656c993126cb9fab603b9092e5ba1` |
| SPDX 2.3 SBOM | 22,757 | `93662fa0447fa1ddfd192f3bae79db05d21eb09c34a07deb9acecc984070fe36` |
| host receipt | 4,003 | `a1777fbc37ca7bf83333e67f0ec8042726c1c5d7933998f1fda56e68124edaa5` |
| EROFS image | 26,816,512 | `058ad3a0d2eb2507ecffb5a7478d60cd73d66141460db47ce7c36583d2436ca4` |
| EROFS descriptor | 1,544 | `41c1f614e64361d2e29a2f9451bcc0702cb3d522f011209896248fa9c2616fa3` |

Both receipts have receipt ID
`c4a013d39b2b203d9f42dc56209970f2e6a25ee6c3416bfc8e92235ff9e9e815`.
The normalized archive has 2,221 members and 61,122,933 regular-file bytes.
All members are owned by `0:0`; directories are `0555`, regular files are
`0444`, executables are `0555`, and special files and filesystem write bits
are absent. `/root` and `/home` are empty, and builder-host hostname, hosts,
resolver and machine identity files are absent.

Both EROFS builds passed `fsck.erofs`. Both produced fs-verity SHA-256 digest
`28bd52342571cbb6d538a3f6f44d64b2656992ec3677ac1b31c84ef1ac0847b3`.
This is a host digest only. The descriptor requires Android to enable
fs-verity on the exact published image and re-measure the same digest before
any read-only EROFS mount.

The focused Python suite passed 18/18 tests, including exact snapshot and tool
pins, complete package inventory, non-authorizing flags, host-state removal,
read-only modes, hardlink ordering, symlink confinement, canonical tar order
and special-file rejection.

## Fail-closed observations

Exploratory builds were not published:

1. A custom package set without `perl-base` stopped when Debian maintainer
   scripts could not execute the Debconf frontend.
2. The first contracted run stopped on Debian's default `/root/.bashrc`.
   The builder was then tightened to empty `/root` and `/home` before the
   existing forbidden-path gate, and the two successful builds restarted from
   new trees.

## Remaining gates

This checkpoint cannot refresh the checked-in Android rootfs archive or close
the Root Linux product row. The following remain mandatory:

1. independently approve the keyring origin;
2. produce exact-source, authenticated final daemon/Codex/OpenClaw payloads;
3. atomically bind the final payload, SBOM, archive/image and Android pins;
4. select the immutable image admission path in a clean Android product build;
5. enable and re-measure fs-verity before mount on a locked-AVB user device;
6. obtain clean target-files, two full reproducible Android builds, signed OTA
   and dual-Agent device evidence.
