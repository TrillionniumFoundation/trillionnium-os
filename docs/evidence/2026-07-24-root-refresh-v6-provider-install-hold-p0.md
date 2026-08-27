# Root refresh v6 and fixed provider artifacts remain production HOLD

Date: 2026-07-24

> The provider/JAR/DEX checkpoint remains current for the slice it records.
> Its statement that Root still needed a new build/record/dry-run is
> superseded by
> `2026-07-24-root-linux-v6-current-source-daemon-dry-run-hold-p0.md`.
> Production/apply authority remains HOLD.

## Verdict

The post-v5 source slice passes its focused control-plane, Root refresh,
provider, enrollment and Soong gates. It closes three source boundaries:

- Root refresh now models the checked-in split archive/payload/pin baseline
  and binds the complete source-fixed builder TCB.
- Both fixed production-identity provider factories and implementations exist
  as real DEX/JAR artifacts with one canonical zipaligned envelope.
- The loader verifies a construction-owned whole-JAR production pin before
  archive parsing, class initialization or provider construction, and the
  destination runtime creates a fresh one-shot invocation for every effect.

This is not device or release authority:

```text
device_authorization=false
production_activation=false
release_receipt=false
```

No Root apply, pin update, product inclusion, target-files build, device
installation, signing, OTA or release occurred.

## Immutable input baseline

The prior source checkpoint remains unchanged at:

```text
/data/trillionnium-preflash-staging-20260724/
  CROSS-REPO-SOURCE-FREEZE-v5-root-bookworm-host-tcb-loader-enrollment-hold
```

Its published top-level identities are:

```text
manifest.txt     7ed848723dcc6e1ade35267d2cf7cf1d768c184964461bd367f296f1a12d25ff
repositories.tsv 9721405356630eba17b5c8551404759fb0c04e6034ea5169811ba60e07fb2215
SHA256SUMS       0381ce1be37f72d4a1f80ae2439e97a0964af0591855a582e0046baafe36d553
```

The post-v5 work is a new dirty-tree source slice. It does not rewrite or
retroactively extend v5.

## Root refresh v6 split-baseline repair

The refresh schema is
`org.trillionnium.android-agentd-payload-refresh.v6`. Its exact old-state
model includes:

```text
archive_sha256
archive_payload_sha256
payload_pin_sha256
runtime_closure_sha256
split_baseline
```

The source-fixed known tuple is:

```text
archive_sha256
  7a3e8f14dedd6e58acdb87b2d9dfee333af625149a99540db2201d86ddb9de9f
archive_payload_sha256
  5723e663155f970cab24d54845babbe78c6a0cf406760b2c6e53efebabc1c1dc
payload_pin_sha256
  d315bc06b98f8ceb1a27b4e5422d5ce3880b5556eee08b2df2cb2f324a076544
runtime_closure_sha256
  9f4a27065f3fa25279accc2e0e916aed63ffdeee3f09bc7d5659ed6f29ce0aa6
split_baseline
  true
```

The transaction protects exactly five targets: the Root archive,
`Android.bp`, the Root manifest, the runtime wrapper and
`GatewayPeerPolicy`. The external epoch/high-water contract records
`protected_target_count=5`. A prepared apply must reopen the archive and
reverify its embedded payload before any target write. Stale v5 refresh plans
and statements are rejected.

The ELF contract treats `PT_INTERP` independently from `DT_NEEDED`. The exact
interpreter is `/lib/ld-linux-aarch64.so.1`; the exact needed libraries are
`libc.so.6`, `libgcc_s.so.1` and `libm.so.6`.

The v6 materialized receipt, refresh plan and trusted-builder statement bind
the complete source-fixed builder TCB. The current candidate-contract SHA-256
is:

```text
6e094ff3cd461085c8fa0a85e50290120e85aad1ac264e029a56f9fe2b34d91f
```

The bound summary includes:

```text
OCI image index
  a736afffbcc4bb1c8350cc5c6f9dbaba5b973aa2c1f7e152731af8602916a8ed
linux/amd64 image manifest
  f45df717ed9d4926691b7906ed5beef6823d308cc1bc093c879ea8a314042130
Cargo-home manifest
  711d39583b0004485a9e226442f1476a203a32601fac061198c9d6f933520b63
private-toolchain manifest
  8ee268e616feb4d5d9cb07ba363d4966c88bfb915d2d0147014cbed6d45a05d2
host-tool manifest
  1970dd9c3fe3e970ebbdb49cb761a6fbc7c5aeedc4faf269d27484c507f9e051
build script
  585a539dddd703fb8b2a0588a33704b746ca65f0beedd10cbe7970bd4f4bad78
```

Focused validation passes 35 refresh tests, 14 trusted-builder tests and 5
epoch/high-water tests. No apply was executed. Production remains blocked by
0/2 builder approvals, empty production pins and the absent external
rollback-resistant high-water authority.

After this source checkpoint, two fresh current-source lanes reproduced five
AArch64 binaries and daemon `606731da...` completed a v6 local-custody
record/dry-run with plan `248b83e4...`. That plan is daemon-only and does not
promote the four helper candidates. The later result and its immutable evidence
are recorded in
`2026-07-24-root-linux-v6-current-source-daemon-dry-run-hold-p0.md`.

## Fixed provider source and artifact slice

The two closed identities are:

| Role | Factory | Implementation |
| --- | --- | --- |
| receipt | `org.trillionnium.platform.provider.receipt.CapabilityLeaseReceiptVerifierProviderV1` | `org.trillionnium.platform.provider.receipt.CapabilityLeaseReceiptVerifierPluginV1` |
| destination | `org.trillionnium.platform.provider.destination.CapabilityLeaseDestinationConsumerProviderV1` | `org.trillionnium.platform.provider.destination.CapabilityLeaseDestinationConsumerPluginV1` |

The receipt provider performs closed canonical/duplicate-safe JSON parsing,
KeyMint-attestation binding, P-256 low-S signature verification and exact
receipt-ID verification. The destination provider is a pure typed policy
planner; it owns no network, file descriptor, TLS or effect authority.

The final source-disabled artifacts are:

```text
receipt JAR
  b0d834f34c8d6aaa8c9086b771d334eebff0876c479a9ad6053a62268c67a367
  29,038 bytes
receipt classes.dex
  f77afed0ff79f761e0e29bab2baf31ff6e34183de8cfc8e689353de5db554453
  193 method IDs

destination JAR
  4fb87709406ac536f62e577f38ca86c01cba19f115461a26d7efef328d0486d2
  2,866 bytes
destination classes.dex
  e44e83e05452defd58e822b9dea828e69f052deda98b0a3beaf350cdfaaf8d2c
  12 method IDs
```

Each JAR has exactly two entries: a STORED `classes.dex` with the exact
three-zero-byte local-header padding required for four-byte alignment, followed
by the DEFLATED Soong manifest. `zipalign -c -v 4` passes.

For each provider, the exact genrule output, the install-capable module's
aligned intermediate and the explicitly built development product-out staging
file are byte-identical. That statement is only a build-boundary result.

## Pre-initialization pin and per-effect lifecycle

The fixed-image backend measures the whole JAR from the same already-opened,
sealed bytes and calls the construction-owned
`ProductionArtifactPin.verifyOpenedBytesExactlyOnce` before JAR/DEX parsing,
`Class.forName`, static initialization or constructor execution.

The resulting non-constructible `PinnedArtifactMeasurement` is carried through:

```text
opened bytes
  -> production pin
  -> JAR/DEX/Class/factory/implementation checks
  -> loader runtime binding
  -> adapter binding
  -> RuntimeFactory Loaded* binding
```

No runtime API accepts a raw path or digest as an equivalent measurement.
Wrong digest, wrong identity, cross-construction use and replay all fail before
factory construction; destination failures also occur before any effect.

The destination runtime no longer retains one already-consumed invocation. It
may retain the measured classloader and factory, but every effect requests a
distinct exact plugin instance and a fresh one-shot invocation. Reentry and
factory drift fail closed.

Both production loader entrypoints still throw HOLD before reaching the private
load path.

## Dormant install-capable module boundary

Two lowercase `system_ext_specific` Java modules are defined and explicitly
buildable:

```text
/system_ext/framework/trillionnium-capability-lease-receipt-verifier.jar
/system_ext/framework/trillionnium-capability-lease-destination-consumer.jar
```

They are absent from `PRODUCT_PACKAGES`, `required` edges and current product
configuration. Their generated `product_packages.txt` files are empty.

Explicit module builds staged user-owned mode-0664 files in development
product-out. Those files are not root:root mode-0444 target-files or verified
image evidence. Explicit module build and staging do not prove product
inclusion.

## Validation

The final no-concurrent-source-write validation completed:

```text
Root refresh / builder / high-water
  54/54 passed

control semantic/wire separation
  direct-tools 127 unit + 2 integration passed
  dev-overrides MCP 5/5 passed
  trusted-context-hotpath cargo check passed
  tool-runtime 124 unit + 1 integration passed
  OpenClaw 42/42 passed

Android Soong
  loader, both exact artifacts, both dormant install-capable modules,
  both provider host tests, pending broker, source test and source-contract
  target built successfully

Android host JUnit
  receipt provider 14/14 passed
  destination provider + DEX/JAR gates 25/25 passed
  pending/broker/coordinator/loader suite 136/136 passed
  focused construction/pin adversarial suite 9/9 passed

vendor product-artifact/enrollment/boundary
  59 tests passed with 1 expected final-APK-unavailable skip

source contract
  strict disabled/unreachable gate passed
```

The read-only product inspector recognizes both development JARs and their
closed envelopes, but returns production gate exit 3:

```text
HOLD_CAPABILITY_LEASE_PRODUCT_ARTIFACT_CLOSURE
```

## Independent HOLD matrix

- no authoritative target-files ZIP or target-files-to-verified-image byte
  binding exists;
- no root:root, mode-0444, single-link verified product-image observation
  exists for either provider;
- whole-JAR production pins, two enrollment approvals and live measurement or
  dependency producers are absent;
- no production caller reaches `CapabilityLeaseRuntimeFactory.create(...)`,
  no service is registered and enabled trust remains false;
- route connector/session definitions are excluded from the current platform
  JAR, the replay-sync publisher executable is absent, and token mutation,
  ACK/lease producers and the network/FD/TLS effect consumer remain unwired;
- Root refresh remains non-hermetic, at 0/2 builder approvals and without an
  external high-water authority;
- the checked-in Root archive/payload/pin split remains intentionally
  fail-closed, so no clean full product or release claim is available.

## Next admissible slice

Product packaging and target-files evidence must be a separate reviewed
change. It must preserve the same opened JAR bytes from measurement through
class loading, factory construction and instance binding. The loader,
RuntimeFactory caller, service and effect must remain disabled until production
pins, dependency producers, target-files/verified-image proof and exact
system-UID/SELinux/device evidence close together.

Root refresh now has a current daemon-only clean record/dry-run. It may advance
only after the four rebuilt helpers receive an explicit protected
multi-artifact promotion path, two genuinely independent builders provide 2/2
canonical low-S signatures over the complete plan, and the external
rollback-resistant high-water authority prepares and commits that same plan.
Those requirements must be satisfied in one transaction; neither this source
slice nor the later dry-run authorizes apply.
