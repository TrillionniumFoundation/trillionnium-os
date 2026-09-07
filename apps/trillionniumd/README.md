# Trillionniumd sealed monolith

Lifecycle classification: **`sealed_legacy_monolith`**

Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)

Default owner-open source closure: **not selected**

## Purpose

This package retains the pre-G1 daemon composition root and its compatibility and conformance surfaces.

## Authority and product boundary

It is not selected by the G1 default owner-open source closure. Its default build does not authorize legacy plan execution, mutation, automatic retry, Android device access or public release.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

`p0-launch-package-device-conformance` is a non-product userdebug conformance lane. `legacy-plan-conformance` enables historical protocol vectors only and must remain absent from the owner-open product graph.

The active default composition root is `apps/trillionnium-owner-open-host`; separated owner-open registries, runtime, provider and event-store crates own the corresponding mechanical responsibilities.

## Related module contracts

- [MOD-EXECUTION-CORE](../../docs/modules/MOD-EXECUTION-CORE.md)
- [MOD-TOOL-RUNTIME](../../docs/modules/MOD-TOOL-RUNTIME.md)
- [MOD-PROVIDER](../../docs/modules/MOD-PROVIDER.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionniumd --all-targets
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
