# `open_uri` consumer HOLD and deadline-resolver engineering smoke

Date: 2026-07-24

## Verdict

The P0 capability-lease runtime remains source-disabled and product HOLD. This
batch corrected an unsafe effect claim, added a bounded Android DNS adapter,
made the configured installable framework module and target-product output
compile again, and ran a reversible engineering-device smoke. It did not
install that framework output on the device or create a production consumer,
verified artifact loader, product trust material, live service, release build
or lease effect.

The earlier runtime checkpoint described
`CapabilityLeaseAndroidOpenUriConsumer` as launching an implicit
`ACTION_VIEW`. That is no longer current. An implicit browser launch discards
the approved address set, permits a second DNS resolution, and transfers the
effect to an unmeasured browser. It cannot satisfy
`destination_consumer_binds_resolved_set=true`.

The production-named consumer now revalidates the typed destination and throws
`capability_lease_resolved_set_consumer_unavailable` before any Android
effect. The only `ACTION_VIEW` implementation is a test-only dispatcher built
into a non-privileged, non-platform-signed `android:testOnly` instrumentation
APK. During the test, instrumentation temporarily adopts exactly
`INTERACT_ACROSS_USERS_FULL` from the shell identity so it can call
`startActivityAsUser(UserHandle.SYSTEM)`, then drops that identity in teardown.
That is test-harness authority, not product identity. The runtime factory,
service and product package graph do not construct that dispatcher.

## Source-disabled deadline resolver

`CapabilityLeaseAndroidDeadlineResolver` implements the existing destination
policy resolver interface without adding a protocol or trust field. It:

- captures one active Android `Network` and requires INTERNET, VALIDATED,
  NOT_SUSPENDED, NOT_VPN and TRUSTED capabilities;
- rechecks that exact active network before, between and after queries;
- launches explicit A and AAAA queries with no retry, cache lookup or cache
  store;
- gives both families the same absolute elapsed-realtime deadline and requires
  both terminal outcomes;
- rejects wrong-family bytes, empty combined results, network drift, clock
  rewind, deadline overflow, main-looper use, interruption, launch failure and
  late completion;
- bounds global in-flight work to four, defensively copies answers and cancels
  both families on failure; a throwing cancellation listener cannot skip the
  other cancellation or leak a permit.

No runtime or service constructs this class. It also does not carry the exact
Android `Network` into `ApprovedDestination`, hold a partial wake lock across
possible suspend, or bind the eventual TLS socket to that network and address
set. Those are product blockers, not properties inferred from the resolver
tests.

## Build and host validation

The following Soong targets completed successfully for
`trillionnium_fogos-bp4a-userdebug`:

- `org.trillionnium.platform`;
- `TrillionniumCapabilityLeaseAndroidOpenUriDeviceGateTest`;
- `TrillionniumAgentSystemApiCapabilityLeaseSourceContractTest`;
- `TrillionniumCapabilityLeaseBrokerSourceContractTest`;
- `TrillionniumCapabilityLeasePendingBrokerTest`;
- `TrillionniumAgentSystemApiCapabilityLeaseSourceTest`.

The abstract root-route connector and its session constructor remain
`PRODUCT_WIRED=false` and are deliberately excluded from the configured
installable core-platform module until the hidden abstract-socket API is placed
behind a separately measured platform artifact. The source-only plugin adapter
is also excluded until verified bytes, measurement and loaded instance can be
atomically bound; only its passive parent-loaded SPI/DTO types remain in the
module. The unified current-source rebuild produced the target-product output
framework JAR with SHA-256
`0532d1293932377883a46064662432fe827da2b3810b39611e15e52e4086a95c`.
That hash is unchanged from the earlier consumer/resolver build. DEX inspection
found all four passive public SPI/DTO types and none of the five explicitly
excluded source-disabled internals. It was not pushed or installed on the
physical device. This is configured-module boundary evidence only, not a
product pin or proof that the private loader ran.

After the later source-disabled loader prerequisite was added, current-source
direct host JUnit execution passed:

- pending/broker/coordinator/SPI-adapter/source-disabled-loader suite: 113/113;
- capability-lease handler/protocol suite: 18/18.

All seven related SDK shell/source-contract gates pass from the source tree.
The Open URI, System API capability-lease and broker gates also pass from their
packaged testcase layouts. The Open URI and System API gates package the
complete production Java source closure. They prove that the adapter is
excluded from the installable module; the System API gate additionally rejects
any production reference to the adapter class or either
`adapt*SourceDisabled` method. The broker gate scans its packaged source list
instead of a checkout-only glob.

## Engineering-device smoke

The test APK SHA-256 was
`9e70c6e2d523411426efafd9847ec4148ea919dc87c5ba619793617ac2085d08`.
It is test-only, debuggable and AOSP-test-key signed. It has no platform
certificate, privileged/product identity or product package inclusion. It is
the prior consumer/resolver smoke APK, not an artifact rebuilt from the later
loader-source state.

On device `ZY32JLVHGN`, fingerprint
`trillionnium/trillionnium_fogos/fogos:16/BP4A.251205.006/eng.qian-q:user/release-keys`,
SELinux Enforcing and verified boot orange, the runner:

1. recorded the original user-0 browser role;
2. installed the unique test package with `-t`;
3. made its recorder Activity the exclusive browser role holder;
4. verified exact URI resolution to that recorder;
5. ran 19 tests: three dispatch-boundary tests and sixteen deterministic,
   no-network resolver tests;
6. force-stopped and uninstalled the package;
7. restored the original `org.trillionnium.browser` role and independently
   verified no package or process remained.

Result: `OK (19 tests)`. This proves only that the production consumer stays
HOLD, the isolated fixture can exercise Android dispatch as user 0, and the
resolver state machine handles its injected cases. It is not DNS, socket, TLS,
product-browser/network-navigation, lease, locked-device, release or
end-to-end Agent evidence.

## Browser and artifact-loader blockers

The current Servo product cannot be used as the measured consumer:

- exported `org.servo.servoshell.MainActivity` accepts public VIEW plus
  caller-supplied `servoargs`/`servolog`, including certificate and developer
  controls;
- the current URL-only Java/JNI/Rust path has no typed approved-route field;
- the prebuilt is a large debug-signed artifact and is re-signed with an AOSP
  development key in this build;
- the current consumer measurement would not cover the browser APK, native
  library, component and signer.

The two fixed verifier/consumer identities still have no production Soong
provider modules or provider artifacts. Four public `@hide` parent-loaded
SPI/immutable DTO types close only the type-visibility prerequisite. The
package-private adapter remains excluded from the installable module and
forbidden from all production references.

A separate private, non-installable source-disabled module now contains a
fixed-path loader prerequisite plus exact JAR and bounded DEX structure gates.
Its two actual Soong provider fixtures use a test-only package and both pass the
current JAR/DEX parser. They are not the fixed production identities. Both
production loader entrypoints unconditionally throw explicit construction-ABI
HOLDs before the private load path. A packaged source gate now keeps the SDK
loader/measurement and vendor-enrollment constants aligned, but exact
target-files root:root/single-link/0444 artifact evidence, real provider
dependencies, a measurement producer and atomic factory binding are still
absent. No loader or provider was installed on the device. Detailed evidence is
in
[`2026-07-24-verified-plugin-loader-enrollment-hold-p0.md`](2026-07-24-verified-plugin-loader-enrollment-hold-p0.md).

The next acceptable consumer slice is an explicit-only Activity receiving a
kernel-unforgeable one-shot Binder token, with system_server checking the
calling browser UID and exact package/signer/APK/native/component measurement
before atomic consumption. A dedicated navigation lane must use an exact-
Network-bound, approved-address socket while preserving the original URI host
for HTTP Host, TLS SNI and certificate validation. It must deny raw extras,
fallback VIEW, redirects, subresources, proxy, pool reuse, reload/history and
replay until separately authorized. A future admitted loader must keep the
public parent-loaded SPI/DTO boundary while supplying loader-private verified
wrappers that atomically bind bytes, measurement, Class and instance before the
adapter can be admitted to the installable module. The current source-disabled
wrapper is test/build evidence only and cannot satisfy that production gate.

Production activation still requires real final release APKs, independent
offline approvals, locked flags-0 release-key AVB, acceptable KeyMint 400/400
attestation, hermetic ceremony-host evidence, exact non-empty pins, packaged
root-route/publisher/token/ACK producers, and locked-device Agent E2E. None was
fabricated or enabled in this batch.
