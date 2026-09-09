# Trillionnium sealed legacy tool runtime

> **HISTORICAL_NON_AUTHORITATIVE.** This component is excluded from the
> `owner-open-core` default profile and cannot define current product behavior.
Lifecycle classification: **`sealed_legacy_tool_runtime`**  
Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)  
Default owner-open source closure: **not selected**

## Purpose

This crate retains the pre-G1 tool transport, validation and explicitly gated conformance implementation.

## Authority and product boundary

It is excluded from the default owner-open closure and cannot use legacy Authority effects as a fallback.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

`legacy-authority-effects` and `dev-conformance-fault-hook` are non-product. `p0-launch-package-provider-conformance` is a fixed userdebug source lane and remains non-authorizing.

The active graph separates byte-preserving bridging in `trillionnium-owner-open-tool-bridge` from lifecycle mechanics in `trillionnium-owner-open-runtime`.

## Related module contracts

- [MOD-TOOL-RUNTIME](../../docs/modules/MOD-TOOL-RUNTIME.md)
- [MOD-ANDROID](../../docs/modules/MOD-ANDROID.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionnium-tool-runtime --all-targets
```

Feature-gated compatibility or conformance tests must name their feature set
explicitly. Do not use an all-features build to combine mutually exclusive,
legacy or non-product authorities.

## Change and retirement rule

Any change that makes this package reachable from `workspace.default-members`,
the selected packaging graph or an Android product requires an explicit
lifecycle update, dependency review, exact-head CI, non-author approval and the
evidence level required by the affected gap. Compilation alone never promotes
this component.
