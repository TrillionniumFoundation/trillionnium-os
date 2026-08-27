# Root Linux path-closed AArch64 candidate remains product HOLD

Date: 2026-07-24

> Historical checkpoint. Lanes `g`/`h` remain valid only for their recorded
> candidate. Current-source lanes and the daemon-only v6 custody receipt and
> dry-run are recorded in
> `2026-07-24-root-linux-v6-current-source-daemon-dry-run-hold-p0.md`.

## Verdict

Fresh evidence lanes `g` and `h` independently produced five byte-identical
AArch64 ELF artifacts with maximum required GLIBC 2.34 against the explicit
Bookworm AArch64 sysroot's GLIBC 2.36 ceiling. This removes the earlier
above-ceiling daemon ABI incompatibility from the candidate build.

The build contract is exactly
`path-closed-measured-host-tcb`. It is deliberately recorded as
`hermetic=false`, `host_runtime_pinned=false` and
`dependency_cache_independently_approved=false`: the selected host tools are
path-closed and measured, including the actual Bash process bound through
`/proc/$$/exe`. Each lane also has a complete, byte-identical prebuild
`CARGO_HOME` manifest. The dependency-cache origin and ceremony approval remain
absent, however, and the host ELF loader/dynamic libraries, kernel, filesystem
implementation and CPU remain external unpinned TCB. This is reproducible
candidate evidence, not a production builder proof, payload promotion or
release receipt.

No rootfs archive, vendor payload, product pin or production trust material was
changed. Builder approvals remain 0/2 and the external rollback-resistant epoch
high-water authority remains absent.

## Closed build-input boundary

`build-root-linux-arm64.sh` now requires explicit absolute, regular,
non-symlink paths for Cargo, rustc, the AArch64 linker and private archiver
wrapper, the host linker and archiver, and one exact AArch64 sysroot. It also
requires one non-writable directory containing exactly the 17 named host tools
used by the script. Before Cargo, it requires the actual interpreter realpath
and inode at `/proc/$$/exe` to equal that directory's fixed Bash and records its
SHA-256. A direct shebang invocation with the ambient Bash is independently
rejected before Cargo. The build then runs through `env -i` with the fixed
directory as the complete `PATH`, locked/offline Cargo, a private Cargo home, a
fresh target directory and an explicit `SOURCE_DATE_EPOCH`.

The script measures every selected tool and the sysroot libc, requires the
linker-reported sysroot to equal the explicit sysroot, keeps the loader,
`libgcc_s.so.1` and `libc.so.6` providers inside that sysroot, rejects ambient
Cargo configuration and build flags, and validates the resulting ELF
interpreter, `DT_NEEDED`, hardening, build-path and GLIBC contracts.

The lane-local Cargo homes were independently extracted, and a canonical
prebuild manifest records every regular file's metadata and full-content
SHA-256, every symlink's metadata and complete target, and every directory's
metadata. The two manifests are byte-identical. This binds the exact cache
content used by these lanes but does not independently approve its origin or
ceremony custody. The controls also do not measure or pin the dynamic runtime
of the host tools and therefore do not make the build hermetic.

## Attempt lineage

Only fresh lanes `g` and `h` are final evidence:

- the earlier lane `a` missing-host-`ld` failure and lane `c` raw-archiver
  private-`libbfd` failure remain excluded discovery records;
- earlier lanes `e` and `f` passed, but are superseded because they did not bind
  the executing Bash through `/proc/$$/exe` or independently manifest each
  prebuild Cargo home;
- the new follow-up's first two source-snapshot attempts used an invalid tar
  option order and are excluded; corrected snapshots `c` and `d` are
  byte-identical;
- the first lane `g` cache-manifest attempt stopped before Cargo because of a
  runner working-directory bug and left its incomplete evidence preserved; it
  is not a build lane;
- final lanes `g` and `h` each used independently fresh source, Cargo home,
  target and output directories, the same fixed measured host/toolchain
  material and byte-identical prebuild dependency-cache manifests.

The canonical artifact manifests from lanes `g` and `h` compare byte-for-byte
equal. Their SHA-256 is
`386ce2304da4b0c2f852b994d1d67acbd6cf4363d5737c4ccb561e8a5bf6ad68`.
They are also byte-identical to the superseded lane `e` artifacts.

## Reproducible candidate artifacts

| Artifact | SHA-256 | Maximum GLIBC |
| --- | --- | --- |
| `trillionnium-agent-system-api` | `02f3f0702538f4c370954af4a88511733d16f2da33591d795eaac3a7752fbb00` | 2.34 |
| `trillionnium-agent-accessibility` | `119c67068aac50c716447dfc5d99f4ed104071c2eee88eeb80513eb6923dc56f` | 2.34 |
| `trillionnium-agent-adb` | `c84658a6747cd746d0c5b95de1bb33a494c695e9443a4c806e2b84d7b9988eb9` | 2.34 |
| `trillionnium-system-api-replay-sync` | `6eeee58209dee132a7fa0224d18c9d7f2a39cf45e3a11f7b37974f2659c20f9b` | 2.34 |
| `trillionniumd` | `667e782274d2f92839a68158708f5b47d6aac274fe8d4b5ea61ecb17540ae1ba` | 2.34 |

The daemon Build-ID is
`ce2682664031f3305c440ca73cb86b7b7613b833`. All five are stripped AArch64
PIE executables with NX stack, RELRO and BIND_NOW, no RPATH, RUNPATH or TEXTREL,
and the exact `DT_NEEDED` set `libgcc_s.so.1,libc.so.6`.

The final evidence directory is
`/data/trillionnium-root-linux-interpreter-cache-followup-20260724.KAw1p8oo`.
Its `evidence-manifest.txt` SHA-256 is
`0a5e55b23fd09078e514c49bef4d0d230975f0b576037b2a96249d46df0563b0`.
It supersedes the prior
`c95541eb3ac7def6b95851e0df1dc263e5d1bb5027d6fbd2391190f009a277de`
manifest.

The final manifest records:

- fixed Bash SHA-256
  `bc5945feb8bd26203ebfafea5ce1878bb2e32cb8fb50ab7ae395cfb1e1aaaef1`,
  `/proc/$$/exe` realpath/inode PASS and direct-shebang rejection before Cargo;
- source snapshot SHA-256
  `cd89f7fdf4ca47bd4df9c791df0e493e3a0c63c1547565077ce7533bb1dedb39`
  over 965 entries;
- equal lane `g`/lane `h` prebuild Cargo-home manifest SHA-256
  `f26649416740c416ae98efac49ed259316484946735b8068fcfa6a3409b17ac8`
  over 13,089 regular files, 2,260 directories and 14 symlinks;
- `build_relevant_source_recheck=PASS` with live and lane `g` non-document
  source SHA-256
  `c6ecbd8f10cd6c2c27317b436151c6e0990f6026df989f19a4625aaf5df9211c`;
- `bash_syntax=PASS`, `cargo_fmt=PASS`, Agent API UDS 9/9, Direct-tools unit
  tests 123/123, MCP stdio 2/2, privilege-broker unit tests 126/126 with one
  intentional ignore, ancillary 1/1, startup silence 2/2, no-deps Clippy and
  `git_diff_check=PASS`;
- `lane_g_lane_h_byte_comparison=PASS`.

Three canonical documentation files changed concurrently after the frozen
`g`/`h` source snapshot. The manifest records that exact docs-only drift and
excludes it from the build-input claim; the complete non-document source set
still matches lane `g` byte-for-byte. The Root lane did not edit documentation.

## Post-v5 refresh-v6 split-baseline repair

Later source work does not promote the frozen `g`/`h` candidates. It repairs
the refresh model around the real checked-in split baseline, separates
`PT_INTERP` from the exact three-entry `DT_NEEDED` closure, binds the complete
source-fixed builder TCB through the v6 receipt, refresh plan and trusted
builder statement, and corrects the high-water transaction to five protected
targets. The focused refresh/builder/high-water suite passes 54/54.

No clean candidate was rebuilt after that source work, no signature or
high-water proof was supplied, and no archive or pin was changed. Current
details and the continuing HOLD are in
`2026-07-24-root-refresh-v6-provider-install-hold-p0.md`.

## Remaining product gates

- The checked-in rootfs archive remains
  `7a3e8f14dedd6e58acdb87b2d9dfee333af625149a99540db2201d86ddb9de9f`
  with stale embedded daemon
  `5723e663155f970cab24d54845babbe78c6a0cf406760b2c6e53efebabc1c1dc`,
  while the current product pin remains
  `d315bc06b98f8ceb1a27b4e5422d5ce3880b5556eee08b2df2cb2f324a076544`.
  The verified product gate must continue to reject that mismatch.
- Convert the path-closed measured-host-TCB result into an independently
  authorized production build with its host runtime pinned or supplied by an
  attested hermetic builder, independently approve the dependency-cache origin
  and material, then close the exact target runtime TCB.
- Obtain two independently custodied, source-fixed production builder
  signatures and the external rollback-resistant epoch high-water proof.
- Only after all of those gates may the existing refresh transaction jointly
  update rootfs, vendor payload and pins, followed by a clean full product
  build. Current production refresh remains 0/2 approvals with
  `rootfs_mutation=false`, `vendor_mutation=false` and `pin_mutation=false`.
