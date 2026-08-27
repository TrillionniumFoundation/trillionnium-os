# Root Linux current-source daemon v6 dry-run remains production HOLD

Date: 2026-07-24

## Verdict

The v6-frozen control source reproduced five AArch64 release binaries
byte-for-byte in two fresh lanes. The daemon then passed the v6 local-custody
`record-build` and daemon-only refresh `dry-run`.

The exact admissible claim is:

> Current-source dual-fresh-lane AArch64 rebuild PASS; daemon-only v6
> local-custody record/dry-run PASS; production builder, signatures,
> high-water, apply, product and release remain HOLD.

This evidence grants no authority:

```text
device_authorization=false
production_activation=false
release_receipt=false
release_apply_authorized=false
```

No canonical archive, pin, manifest, wrapper, policy or source file was
mutated. No device I/O, signing, OTA, apply or release occurred.

## Immutable v6 source anchor

The build input is anchored to:

```text
/data/trillionnium-preflash-staging-20260724/
  CROSS-REPO-SOURCE-FREEZE-v6-semantic-wire-root-tcb-provider-pinned-hold
```

Its top-level identities are:

```text
manifest.txt
  7f31d677aa41c628d517df2cb02fe4c796e2bd864e8e45ec2dc45694a840648b
repositories.tsv
  9721405356630eba17b5c8551404759fb0c04e6034ea5169811ba60e07fb2215
SHA256SUMS
  f9746f530c47959fb41cf2a72a0c7d14ef0fd12dac2038a5d0c04d1c19b94bc3
```

The canonical control HEAD at capture was
`a4f1511ecdb4adfa12a81752ba1336518996fca6`. Its status, tracked patch
and untracked inventory matched v6 before the build.

`record-build` requires a clean Git identity, so the exact v6 bytes were
materialized into an isolated temporary repository:

```text
temporary commit
  4180ea74c9f0ad3606563e946dd4df887fabb120
temporary tree
  8775c36571ab68b83766e2a7b43474679b3f45a2
file count
  987
source inventory
  92ec197c294c190249974a876b4b98828c642483c41f753691092b6e50870cef
```

That commit is only a local v6-anchored materialization identity. It is not
the canonical upstream HEAD, an independently reviewed commit, or production
provenance.

## Two fresh lanes

Both lanes used the same v6 source and source-fixed TCB, but distinct fresh
targets and outputs. Their five release binaries are byte-identical:

| Artifact | SHA-256 |
| --- | --- |
| `trillionnium-agent-system-api` | `c8289660701b46fa08316e877ea6f7c37d473da5d7cfc965e6f8bcc459eb938b` |
| `trillionnium-agent-accessibility` | `715616e364c4374d5bc99b3e2e64d14a380cd5ae3caf5c0820ca39fd0f76932b` |
| `trillionnium-agent-adb` | `a25df4ba11e929bffbd500e902e6cd78f4a2bb5d54992c2bcfa4b92eb8a32646` |
| `trillionnium-system-api-replay-sync` | `f71145725ec8eb02c68f0cb8c8bd472f67f4098a50a115dcf8b98b3a5ac8656b` |
| `trillionniumd` | `606731da2bd04c0ceaa532c765579fe88b89d2c3a5c06f767b17f92e9a4d6997` |

Cargo-home and private-toolchain manifests are unchanged before/after and
across both lanes:

```text
Cargo home
  711d39583b0004485a9e226442f1476a203a32601fac061198c9d6f933520b63
private toolchain
  8ee268e616feb4d5d9cb07ba363d4966c88bfb915d2d0147014cbed6d45a05d2
```

The daemon is an AArch64 PIE with maximum GLIBC 2.34, Build-ID
`5a9019e59b3b94a76912ac83b1298b4027e51044`,
`PT_INTERP=/lib/ld-linux-aarch64.so.1`, and exactly
`libc.so.6`, `libgcc_s.so.1`, `libm.so.6` in `DT_NEEDED`.

These are two reproducibility lanes on the same host and TCB. They are not two
independent production builders.

## Daemon-only v6 custody receipt

The materialized receipt is:

```text
schema
  org.trillionnium.agentd-materialized-build-custody.v6
receipt SHA-256
  f6ded46ae138434d97701410fb1cb131c063706600101ead6664d4a93c4e656a
candidate SHA-256
  606731da2bd04c0ceaa532c765579fe88b89d2c3a5c06f767b17f92e9a4d6997
candidate size/mode/nlink
  6,246,032 / 0755 / 1
runtime closure
  ff3af473782cc0f90e12c78b6c35b0cc8e1368f1f8434318a4d40c6ef86a3e70
provenance class
  custody_only_unproven_build_v6
trusted builder signatures
  0
```

`record-build` did not invoke Cargo and does not bind the two lane logs or
lane identities into a production attestation. It verifies and materializes
the supplied daemon against the clean snapshot and observed TCB. The
reproducibility result and custody receipt therefore support one another but
are not equivalent.

## Daemon-only v6 dry-run

The dry-run produced:

```text
decision
  PREPARED_AGENTD_PAYLOAD_REFRESH_DRY_RUN
schema
  org.trillionnium.android-agentd-payload-refresh.v6
plan SHA-256
  248b83e462fccc5f226bfd260f1e9b616608c170e62a8392eaabe3b4c9ee9dd2
result SHA-256
  4792009b39262dac9303d3383919a48fce0515af7b5c977e1aca604f75255456
```

It verified the split old tuple:

```text
archive
  7a3e8f14dedd6e58acdb87b2d9dfee333af625149a99540db2201d86ddb9de9f
archive member
  5723e663155f970cab24d54845babbe78c6a0cf406760b2c6e53efebabc1c1dc
product payload pin
  d315bc06b98f8ceb1a27b4e5422d5ce3880b5556eee08b2df2cb2f324a076544
runtime closure
  9f4a27065f3fa25279accc2e0e916aed63ffdeee3f09bc7d5659ed6f29ce0aa6
split_baseline
  true
```

The prepared new tuple is:

```text
archive
  5ebb6cade02535c45d50749e66a18aa7372e257f89c89f8ebf43bb6c8664d3e0
daemon
  606731da2bd04c0ceaa532c765579fe88b89d2c3a5c06f767b17f92e9a4d6997
runtime closure
  ff3af473782cc0f90e12c78b6c35b0cc8e1368f1f8434318a4d40c6ef86a3e70
```

All five prepared regular single-link targets match their plan descriptors:

| Target | Prepared SHA-256 |
| --- | --- |
| Root archive | `5ebb6cade02535c45d50749e66a18aa7372e257f89c89f8ebf43bb6c8664d3e0` |
| `Android.bp` | `d11b4f78562f60c910bc9bd1e2408e885981e6ec3038687be3adebd8b0af8fa5` |
| Root manifest | `d654a486b5d904908cadb170b476d676da66c896fcd7fb163c4f28d57159f51f` |
| runtime wrapper | `0ddb6ca6a4c1a3789ec93f927f26dc2c344d2c25002e3bf08f10f9c4239ca8cb` |
| `GatewayPeerPolicy` | `2f0e2153442d1520df1b92219365a34e0c75d1b2f6d7ce05d46a8e68c859679a` |

Independent decompression produced tar SHA-256
`90ccc2ca52f9172562784c2ddd89265a9b565eef5d80f8489b433912fadc484c`;
its `usr/bin/trillionniumd` is the exact `606731da...` candidate.

The local zstd observation is version 1.5.5 with executable SHA-256
`7c5468b370f7c47eda07281e3437fafc568f95d10420051e3aa522709f9342c5`.
Its independently trusted supply-chain provenance remains false.

## Helper non-promotion boundary

The receipt and plan cover only `trillionniumd`, and the refresh replaces only
`usr/bin/trillionniumd`. It does not promote the four newly rebuilt helpers:

| Helper | Current vendor pin/package state | New lane candidate |
| --- | --- | --- |
| System API | `0fbc3568d71733568ef9a141335d63038211cc45823a77020ea1da089adb2084` | `c8289660701b46fa08316e877ea6f7c37d473da5d7cfc965e6f8bcc459eb938b` |
| Accessibility | `db9e4969b3221fc2af3cf9012595813fea85ffd16e3b1f9e4d3468c8c7293a18` | `715616e364c4374d5bc99b3e2e64d14a380cd5ae3caf5c0820ca39fd0f76932b` |
| ADB | `a3a28dbdcf5be7c4b0fb4e72536de851e3ce8d80787f6c6f7677c446f01cf135` | `a25df4ba11e929bffbd500e902e6cd78f4a2bb5d54992c2bcfa4b92eb8a32646` |
| replay-sync | absent product packaging | `f71145725ec8eb02c68f0cb8c8bd472f67f4098a50a115dcf8b98b3a5ac8656b` |

The five-binary build is evidence of current-source reproducibility, not a
complete current-source Root runtime refresh. Any product adoption of the
semantic/wire changes must use a separately reviewed, protected multi-artifact
refresh or product-packaging transaction.

## No-mutation and immutable evidence

After dry-run, all five canonical targets still match their before hashes.
There is no builder statement, signature envelope, high-water record or apply
transaction.

The selected logs, binaries, pre/post manifests, receipt, candidate, plan,
prepared archive and `.after` files were published read-only at:

```text
/data/trillionnium-preflash-staging-20260724/
  ROOT-LINUX-V6-REBUILD-DRY-RUN-EVIDENCE-v1-daemon-only-hold
```

Publication verification:

```text
container files
  32
checksum rows
  31
directories
  9
manifest.txt SHA-256
  9e89d8f3974ac1614c2424276f4d2be395bd5407c5e555e07decfce09cea6c86
SHA256SUMS SHA-256
  4d62b12bd605a1d6e7cbe6718322658ad14dd8f3be9a4a71695bf5888472bc5d
file mode
  0444
directory mode
  0555
writable paths
  0
```

`sha256sum -c SHA256SUMS` passed before and after atomic no-replace
publication.

## Production HOLD matrix

- the build contract remains non-hermetic;
- the two lanes are not two independent builders;
- there are 0/2 trusted-builder signatures and no statement/envelope;
- no external rollback-resistant epoch/plan high-water prepare or commit
  exists;
- the zstd supply-chain provenance is not independently trusted;
- the helper binaries are outside the daemon-only receipt and refresh;
- no apply, canonical pin/archive mutation, product build, device validation,
  signing, OTA or release occurred.

## Next admissible transaction

First close the helper promotion boundary: bind System API, Accessibility, ADB
and replay-sync artifacts into explicit protected product/refresh targets, or
prove that an independently reviewed product build supplies the exact approved
bytes and pins.

Only after that may two genuinely independent builders sign the exact complete
plan with 2/2 canonical low-S approvals. The external rollback-resistant
high-water authority must prepare and commit that same plan. A future apply
must atomically preserve the split archive/member/product-pin model and must
not treat this local custody receipt as production builder authorization.
