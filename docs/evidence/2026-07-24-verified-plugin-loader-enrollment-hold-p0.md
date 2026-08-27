# Verified plugin-loader and enrollment prerequisites remain production HOLD

Date: 2026-07-24

> Historical v5 evidence. Current post-v5 provider, pre-initialization pin,
> zipaligned artifact and lifecycle truth is recorded in
> `2026-07-24-root-refresh-v6-provider-install-hold-p0.md`. Statements below
> that no real provider implementation/JAR or closed construction ABI exists
> are retained only as earlier checkpoint history.

## Verdict

The SDK now has a build-only, source-disabled prerequisite for loading two
fixed capability-lease plugin identities. It measures and structurally checks a
fixed JAR image before delayed class initialization, and its JAR/DEX parsers
accept the two actual test-only Soong fixtures. This closes a bounded source
engineering slice only.

There is no production receipt-verifier JAR, destination-consumer JAR,
installable loader, target-files proof, construction dependency ABI,
measurement producer, runtime-factory call site or enabled trust. Both
production loader entrypoints unconditionally throw their explicit
construction-ABI HOLD before the private load path. Nothing in this evidence
was installed on a device or may be treated as a production provider,
measurement pin, activation result or release receipt.

## SDK source-disabled boundary

The parent-loaded public `@hide` boundary remains limited to four passive
SPI/immutable DTO types. The package-private adapter, loader, Android backend
and JAR/DEX structure gates are all excluded from the configured installable
`org.trillionnium.platform` module. The adapter is compiled only by its host
suite; the loader, backend and parsers are compiled into a separate private,
non-installable source-disabled library. None is product-wired.

The two loader specifications are source-fixed:

| Role | Artifact identity | Entry class |
| --- | --- | --- |
| receipt verifier | `system_ext/framework/trillionnium-capability-lease-receipt-verifier.jar` | `org.trillionnium.platform.provider.receipt.CapabilityLeaseReceiptVerifierProviderV1` |
| destination consumer | `system_ext/framework/trillionnium-capability-lease-destination-consumer.jar` | `org.trillionnium.platform.provider.destination.CapabilityLeaseDestinationConsumerProviderV1` |

Callers cannot select a path, identity, class, interface or digest. The
source-disabled backend:

- opens the fixed absolute path once with `O_RDONLY|O_CLOEXEC|O_NOFOLLOW`;
- requires a root:root regular file with one link, exact mode 0444 and size at
  most 8 MiB, then rechecks the same inode metadata after the read;
- measures the whole JAR while copying it into read-only `SharedMemory`;
- requires exactly `classes.dex` followed by the fixed Soong manifest, with
  exact ZIP headers, compression, descriptor, CRC and no prefix or trailer;
- caps DEX at 6 MiB, archive entries at two, provider classes at 128, type IDs
  at 4,096 and method IDs at 8,192;
- checks DEX magic, checksum, signature, map, namespace, exact direct SPI,
  public-final concrete entry shape, prohibited methods and absence of native
  methods;
- creates an `InMemoryDexClassLoader` behind a restricted parent and calls
  `Class.forName(..., false, ...)` only after the image, archive and DEX checks;
- binds the whole-JAR digest, child class loader, exact class and instance into
  a private one-shot wrapper.

Those statements describe source that is unreachable from production. They do
not prove the two fixed files exist in target-files or on a device.

## Hard construction and activation HOLDs

`loadReceiptVerifierSourceDisabled()` throws
`capability_lease_receipt_plugin_os_trust_clock_attestation_construction_abi_unresolved_hold`.
The verifier still lacks the reviewed OS-owned trust, clock and attestation
dependency injection required to construct it safely.

`loadDestinationConsumerSourceDisabled()` throws
`capability_lease_destination_plugin_exact_network_fd_tls_effect_construction_abi_unresolved_hold`.
The consumer still lacks the exact-Network, file-descriptor, TLS and effect
custody ABI required to preserve the approved resolved set.

The private shared load method is therefore unreachable from either production
entrypoint. Further independent HOLDs remain:

- exact root:root, one-link, mode-0444 target-files and installed-file evidence;
- promotion of the now-source-bound loader/measurement/enrollment identities
  into exact production provider bytes and target-files evidence;
- a producer that turns the measured whole-JAR bytes and loaded instance into
  the factory's exact private measurement input without a swap window;
- real production provider implementations and their complete dependency
  closure;
- source-fixed production pins, enabled trust and a reviewed
  `CapabilityLeaseRuntimeFactory.create()` caller.

No placeholder token, caller-supplied digest or test fixture may satisfy any of
those gates. The source identity gate fixes the status
`identity_source_contract_closed_product_artifacts_unavailable_hold`: source
constants are closed, while production artifact identity/evidence remains
unavailable.

## Test-only artifact evidence

The two provider fixtures use
`org.trillionnium.platform.internal.testplugin`, not either fixed production
package. Their raw libraries and generated JARs are private and non-installable.
They exist only to test the exact Soong ZIP topology and DEX parser:

| Test-only artifact | SHA-256 |
| --- | --- |
| receipt-verifier fixture JAR | `bd80e3025f9d21e61c3155b06b604d1616a9d6b50e0974411917d2f83b5d93dd` |
| destination-consumer fixture JAR | `dd30bf3f9bde0d817b8b0783423cf6d3a3f23c0b3f742b57e8762162b793b2ae` |
| repackaged source-disabled loader library JAR | `b9763e36f70ea7c89cab3b3bfe1200550b084aa91c8b1b33a23bea0c7542215d` |
| host JUnit module JAR | `44da827c5da48527568390f165eff5c4749d573b6a5e31bdc9a592ea22b1d606` |

The unified 14-target Soong build passed. Direct host JUnit passed 113/113;
`tests/agent_system_api_capability_lease_source_contract.sh` and
`tests/open_uri_lease_semantics_contract.sh` passed in the loader lane; and an
independent current-source sweep passed all seven related SDK source/contract
gates plus `git diff --check`. The current JAR plus DEX structure gates accepted
both actual generated fixture JARs. These results validate only the
source-disabled and test-only boundary. They do not exercise the fixed
production file path, Android file-stat gate, production class identity,
dependency construction, target-files packaging, measurement enrollment,
factory activation or device installation.

## Vendor enrollment stays fail closed

The vendor enrollment generator now source-fixes the same two artifact paths,
provider descriptors, SPI descriptors and 8 MiB/6 MiB bounds. Its bounded ZIP
envelope check is only a prefilter. Every production provider artifact that
reaches the end of that prefilter immediately calls
`_require_production_provider_construction_abi_closure()`, whose complete body
is the unconditional failure
`production_provider_construction_abi_unresolved_hold`.

Payload fields, CLI arguments, fixture bytes and caller-selected policy cannot
remove that HOLD. The generator does not claim that its Python ZIP prefilter is
a production DEX verifier, and downstream production-fixture tests may reach
later plumbing only by explicitly mocking the construction closure. Existing
empty production authority/tool pins, unavailable ceremony-host evidence and
disabled installed trust remain separate earlier or later HOLDs.

The final source-only cross-repository gate binds:

- both relative artifact identities and absolute loader paths;
- both provider FQCN/descriptors and parent-loaded SPI descriptors;
- the shared 8 MiB JAR and 6 MiB DEX bounds;
- both measurement artifact identities;
- backend root:root, one-link, exact-0444 requirements and the target-files
  evidence HOLD;
- both construction-ABI HOLDs and the source-closed/product-artifact-unavailable
  identity status.

The Soong
`TrillionniumCapabilityLeaseProductEnrollmentBoundaryTest` target built
successfully. Its testcase carries all four required SDK Java sources and
compares each with its canonical source. Run without `ANDROID_BUILD_TOP` in a
clean environment, the packaged boundary ran four tests: three passed and one
existing final-APK inspection test skipped with
`Android source tree unavailable`; the new SDK/vendor identity test explicitly
passed. The packaged enrollment unit ran 32/32. Canonical direct unit plus
boundary execution ran 36 tests: 35 passed and the existing final-APK test
skipped because `current fogos final APK outputs unavailable`. The SDK source
contract and `git diff --check` also passed.

The packaged gate additionally drives a structurally legal provider envelope
to the unconditional construction HOLD. None of these results prove real
provider bytes, target-files installation/mode, product signing or pins,
whole-JAR-measurement-to-loaded-instance provenance, either construction
dependency ABI, `CapabilityLeaseRuntimeFactory` construction or product
activation.

## Next admissible slice

Define and review both provider construction/dependency ABIs without widening
the existing lease wire. Produce real independent provider JAR modules at the
now-source-fixed identities and prove the required ownership/mode/link state in
target-files. Then carry the closed source identity into a loader-private
wrapper that atomically binds one opened image's bytes, whole-JAR measurement,
class loader, class and instance into the factory inputs.

Only after those artifacts, production pins, trusted producers and all existing
factory gates close together may the source exclusions and unconditional
construction HOLDs be reconsidered. Production activation must remain false
until that joint change.
