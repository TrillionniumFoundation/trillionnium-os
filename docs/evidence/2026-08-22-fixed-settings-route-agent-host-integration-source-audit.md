# Fixed Settings route / Agent Host integration audit (source-only)

Date: 2026-08-22 (Asia/Shanghai)

## Scope and boundary

This audit is limited to the canonical source tree
`/data/toshiba-dev/TrillionniumOS/rootfs/home/qian-qi/trillionnium-release-sources/p0-agent-native-integration-20260731/trillionnium-os`.
It does not build, flash, install, write, reboot, or otherwise contact a
device, and it does not modify an image or an OUT directory.

The intended first vertical slice is:

`Agent Host/Codex -> launch_package(com.android.settings, user 0) -> durable result/ACK -> restart/replay`.

## Audit result

The existing production Codex host seam configures the direct MCP server
`trillionnium-agent-system-api` at
`/usr/local/bin/trillionnium-agent-system-api` (see
`crates/trillionnium-tool-runtime/src/supervised_codex.rs`,
`configure_codex_direct_mcp`). The production System API entry point accepts
only the semantic/MCP modes after its hidden launch-context and post-exec
checks. Its trusted call path requires product effect custody, rejects a
pending outer ACK, opens the durable operation journal, and then enters the
production transport.

The production transport still has no constructible OS logical-call allocator:
`TrustedAdapterContext::allocate_product_tool_call` returns
`ToolCallAllocationUnavailable`. Therefore a real device effect cannot be
admitted from this source snapshot. This is the required fail-closed result,
not a release or device-readiness claim.

`fixed_settings_route` has no production call site. It is a source-only
durability/replay helper and does not create a rollback anchor, lease issuer,
daemon allocator, Android ACK authority, or product effect authority. No
production wiring was added in this audit.

The module declaration is now cfg-gated to test,
development-compatibility-lane, or the separate
device-launch-package-conformance lane, so ordinary product compilation
cannot link this helper accidentally.

## Minimal safe seam added

`crates/trillionnium-agent-direct-tools/src/system_api.rs` now contains the
strict `#[cfg(test)]` test
`fixed_settings_route_binds_to_system_api_test_seam_and_replays_once`.
It connects the existing typed `system_api::call` callback to a bounded local
Unix-domain test listener:

1. The route admits only the fixed semantic request
   `launch_package(com.android.settings)` for Android user 0.
2. The test listener validates the protocol, package, user, and route-authored
   operation/request identity, then returns a typed success response.
3. The route durably publishes its receipt and outer ACK.
4. The endpoint is removed, the route is dropped and reopened, and the exact
   response is replayed without invoking the callback again.
5. The backend accept/effect counter remains exactly one.

Because the test is compiled only under `cfg(test)` and uses a temporary local
socket, it cannot select the production System API binary, a device socket, a
conformance binary, or any authority implementation.

## Verification

Targeted command:

```text
cargo test --lib -p trillionnium-agent-direct-tools --no-default-features \
  fixed_settings_route_binds_to_system_api_test_seam_and_replays_once -- --nocapture
```

Run result (using an isolated temporary Cargo target and the canonical
manifest): 1 passed; 0 failed; 269 filtered out (exit 0). The only output
was the pre-existing dead-code warning for
TrustedAdapterContext::binding_inbox_bytes_sha256. The command is
source-only; this pass cannot be treated as physical device evidence.
A non-test default-feature cargo check --lib also passed with the route
module absent; an explicit development-compatibility-lane library check
passed with the route present.
The route's full source unit set also passed: 8 passed; 0 failed, covering
target pinning, stale PREPARED recovery HOLD, epoch drift, callback/response
HOLDs, receipt promotion, and exactly-once replay.
The device-launch-package-conformance library check also passed only when
the explicit non-product build identity was supplied as
TRILLIONNIUM_P01_CONFORMANCE_BUILD_VARIANT=userdebug; without that identity
the build script rejected the lane before compilation, as intended.

The full direct-tools library suite also passed: 270 passed; 0 failed.
A production-durable-hotpath library check also passed while the route stayed
absent from that non-test compilation surface.

## Remaining production prerequisites

Before this seam can become a real device loop, the OS still needs a
root-authenticated per-call allocator/high-water or rollback authority, a
daemon-to-adapter delivery transport, product kernel launch custody, and the
dedicated Android/outer ACK replay-sync path. Those prerequisites must be
implemented and separately validated before enabling any production route.
