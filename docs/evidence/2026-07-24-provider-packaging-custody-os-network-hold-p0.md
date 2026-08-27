# Provider packaging, custody and OS Network/TLS remain production HOLD

Date: 2026-07-24

## Verdict

The source-disabled Android capability-lease slice now closes three additional
consumer-side boundaries:

- a host-only packaging contract binds both dormant provider modules, exact
  current JAR/DEX observations and future target-files locations while
  rejecting any product-graph inclusion;
- production loader entrypoints accept only private typed product-enrollment
  custody and currently fail on a literal-null producer before backend I/O or
  provider initialization;
- an OS-owned exact-Network/TLS effect boundary carries approved literal
  addresses, one parent-bounded absolute deadline, exact Network identity,
  fixed port 443, SNI/hostname and verified peer identity through one
  non-retrying effect.

Independent review found and closed a receipt-pin null-terminalization bug, a
`StrictJarFile` constructor-failure FD leak and a missing source-disabled Soong
dependency. The repaired slice passes its focused tests and source contracts.

This is a source-disabled PASS only:

```text
device_authorization=false
production_activation=false
product_packages_inclusion=false
target_files_authoritative=false
verified_image_authoritative=false
release_receipt=false
```

No provider was added to a product, loaded by a production caller or executed
on a device. No signing, OTA, installation or release occurred.

## Read-only provider packaging contract

The new contract is:

```text
vendor/trillionnium/prebuilt/common/contracts/
  capability-lease-provider-packaging-hold-v1.contract.json
```

The final source identities are:

```text
contract
  dd70f4b168b3ba911131a188745090629473704bb9745df062df2d86246f37d8
inspector
  cbef740d3c56a0e983f62b93af511702e43ba210b552907ee801a0e239897d63
test
  70d5ccd262e525a81d2655a66aaf2694140c97b9fc9d812691b77a3f290354bc
```

Its host-only inspector verifies:

- the exact raw, exact-envelope and lowercase install-capable Soong module
  identities;
- both install-capable modules remain absent from `PRODUCT_PACKAGES`,
  `PRODUCT_PACKAGES_DEBUG`, `required` edges and the resolved product graph;
- exact-envelope and installable outputs are byte-identical;
- current JAR/DEX shape and observations match the fixed source slice;
- an optional synthetic target-files archive can pass only a bounded
  prefilter and can never become authority.

The observations remain:

| Role | JAR SHA-256 | DEX SHA-256 | Size / methods |
| --- | --- | --- | --- |
| receipt | `b0d834f34c8d6aaa8c9086b771d334eebff0876c479a9ad6053a62268c67a367` | `f77afed0ff79f761e0e29bab2baf31ff6e34183de8cfc8e689353de5db554453` | 29,038 / 193 |
| destination | `4fb87709406ac536f62e577f38ca86c01cba19f115461a26d7efef328d0486d2` | `e44e83e05452defd58e822b9dea828e69f052deda98b0a3beaf350cdfaaf8d2c` | 2,866 / 12 |

Those hashes are explicitly labeled
`current_source_disabled_build_observation_not_production_pin`.

The future paths are fixed:

```text
/system_ext/framework/trillionnium-capability-lease-receipt-verifier.jar
/system_ext/framework/trillionnium-capability-lease-destination-consumer.jar
```

The contract expects future authoritative target-files and verified-image
evidence to bind root:root, mode 0444 and `nlink=1`. No such authoritative
artifact exists now. The inspector has no mutation, pin, approval, signing,
install, activation or device input and always returns structured HOLD.

## Private product-enrollment custody

The two public-to-private production loader roots now follow:

```text
production entrypoint
  -> productEnrollmentCustodySourceDisabled()
  -> literal null
  -> exact stable HOLD
```

The source contract locks that order. The HOLD occurs before the private load
method, backend open, archive parsing, `Class.forName`, static initialization
or constructor execution.

`ProductEnrollmentCustody` and `ProductArtifactBinding` are private final
nested types with private constructors. No overload accepts a path, digest,
raw construction, boolean, policy snapshot or caller-implementable
measurement interface. The future consumer edge can carry only:

```text
target-files / verified-image / enrollment binding
  -> exact construction-owned production pin
  -> construction-owned PinnedArtifactMeasurement
  -> opened bytes / JAR / DEX / Class / factory / implementation
  -> construction-owned LoadedRuntimeBinding
  -> RuntimeFactory
```

`CapabilityLeaseRuntimeFactory` now accepts the two concrete
`LoadedRuntimeBinding` types, not a raw measurement or package-forgeable
interface. Destination runtime binding retains the already measured
classloader/factory but creates a fresh construction, plugin and one-shot
invocation for each effect.

The source-disabled loader module is `installable: false` and private. The
installable platform framework excludes the loader, Android backend, adapter,
JAR/DEX gates and OS Network/TLS effect.

## Repaired fail-closed paths

Independent security review found three issues before final validation.

### Receipt null digest

The receipt `ProductionArtifactPin` previously reached a null-unsafe digest
comparison. A null observation could throw before setting the pin terminal and
revoking its owner. The comparison now returns false on either null, so the
existing mismatch branch terminalizes the pin, clears the owner and revokes
the construction. The new regression proves:

- first null use returns the exact pin-mismatch denial;
- the same pin cannot be replayed with the correct digest;
- the owner cannot issue another pin;
- factory construction remains zero.

### Parser FD ownership

The Android backend duplicates the sealed JAR FD for `StrictJarFile`. If the
constructor fails before returning an owning object, the backend now closes
that duplicated FD directly. If a partially constructed parser already closed
it, the secondary close error is ignored so the original fail-closed exception
is preserved. On successful construction, `StrictJarFile.close()` remains the
owner.

### Source-disabled compile closure

Adding the exact URI validator and OS effect exposed a missing
`OpenUriLeaseSemanticsV1Contract.java` dependency in the private loader
module. The exact module source list now includes it. The source contract also
locks:

- the URI validator, OS effect and URI contract compile closure;
- `installable: false`;
- private visibility;
- absence of `installable: true` and partition-specific installation.

## OS-owned exact Network/TLS effect boundary

`CapabilityLeaseOsNetworkTlsEffectV1` implements the existing
`ExactNetworkTlsEffect` seam but has no production producer or caller.

Its injected `ExactNetwork` exposes only connection to already approved
literal address bytes. It has no hostname/DNS lookup API. Each invocation:

1. reconstructs and revalidates the immutable approved destination;
2. requires exact URI authority equal to the approved host;
3. binds the approved address-set and proof digests;
4. requests a parent absolute elapsed-time deadline;
5. chooses `min(parent deadline, invocation start + 5 seconds)`;
6. rechecks clock, parent authority identity and exact Network identity;
7. opens one parent-owned connected socket to the literal set on port 443;
8. performs one verified TLS session with authority equal to SNI and hostname;
9. binds the connected address and stable verified peer-chain identity into
   the exact HTTPS-root request;
10. executes once with no retry or reentry, then closes TLS before the owned
    socket/FD on every path.

Sequential invocations use fresh socket and TLS session objects. Clock
rollback, missing/expired parent deadline, Network drift, deadline-authority
drift, address substitution, SNI/hostname drift, peer drift, effect failure and
reentry all fail closed.

This is an interface/state-machine boundary, not proof of Android platform
enforcement. There is no concrete selected-`Network`, socket/FD, TLS engine,
parent deadline or RuntimeFactory producer, and no service caller.

## Validation

Final focused validation:

```text
authoritative current-source bp4a Soong
  loader, PendingBroker, source-contract and two packaging host targets passed
PendingBroker / loader / construction aggregate
  153/153 passed
independent focused construction/loader/OS-effect JUnit
  34/34 passed
receipt + destination provider JUnit
  20/20 passed
exact source-disabled loader Android javac
  18-source compile passed
OS Network/TLS focused JUnit
  14/14 passed
provider packaging HOLD
  9/9 passed
vendor artifact/enrollment/boundary aggregate
  67 passed, 1 expected final-APK-unavailable skip
Root refresh / builder / high-water
  54/54 passed
source contract
  strict disabled/unreachable contract passed
targeted diff checks
  passed
```

The production packaging inspector and existing product-artifact inspector
continue to return HOLD. A successful host compile or synthetic target-files
prefilter does not change any authority flag.

The final machine packaging verdict is:

```text
exit
  3
verdict
  HOLD_CAPABILITY_LEASE_PROVIDER_PACKAGING
source_slice.complete
  true
target_files.provider_slice_verified
  false
production_activation
  false
```

## Independent HOLD matrix

- neither provider is in the resolved product graph;
- there is no authoritative target-files ZIP, verified `system_ext` image,
  AVB/release binding or root:root/0444/single-link product observation;
- whole-JAR production pins, signed enrollment approvals and a typed
  target-files/verified-image custody producer are absent;
- `productEnrollmentCustodySourceDisabled()` literally returns null;
- no concrete OS selected-Network, socket/FD, TLS or parent-deadline producer
  exists;
- no RuntimeFactory production caller, Binder/service registration, enabled
  trust or live action-lease route exists;
- there is no device execution, install, signing, OTA or release evidence.

## Next admissible slice

Keep product inclusion and activation separate. First build an independently
reviewed target-files and verified-image evidence producer that binds the same
provider bytes, filesystem metadata, signed enrollment and whole-JAR pins into
the private custody type. Separately implement the concrete Android-owned
selected-Network/socket/TLS/deadline producer and prove same-FD, no-DNS,
hostname/SNI, peer validation, deadline enforcement and close-order behavior.

Only after both producers, system-UID/SELinux policy, product graph,
authoritative target-files/image evidence and device tests close together may
the literal-null custody source change. RuntimeFactory callers, service
registration and sensitive effects remain final joint activation work.
