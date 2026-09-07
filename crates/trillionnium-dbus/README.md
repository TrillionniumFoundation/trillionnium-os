# Trillionnium retired D-Bus integration

Lifecycle classification: **`sealed_retired_platform_integration`**

Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)

Default owner-open source closure: **not selected**

## Purpose

This crate retains historical desktop and alternate-distribution integration code required by compatibility tests.

## Authority and product boundary

The active product is Android-managed headless Root Linux. D-Bus cannot become an alternate product ingress, policy plane or state writer.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

`legacy-plan-execution` is historical conformance only and enables retired Authority behavior; product builds leave it disabled.

There is no active D-Bus product surface. The owner-open host is the selected mechanical composition root.

## Related module contracts

- [MOD-TRANSPORT](../../docs/modules/MOD-TRANSPORT.md)
- [MOD-EXECUTION-CORE](../../docs/modules/MOD-EXECUTION-CORE.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionnium-dbus --all-targets
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
