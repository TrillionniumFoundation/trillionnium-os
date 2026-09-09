# Trillionnium sealed semantic policy system

> **HISTORICAL_NON_AUTHORITATIVE.** This component is excluded from the
> `owner-open-core` default profile and cannot define current product behavior.
Lifecycle classification: **`sealed_semantic_policy`**  
Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)  
Default owner-open source closure: **not selected**

## Purpose

This crate retains historical policy data structures required by sealed compatibility code.

## Authority and product boundary

The provider is the sole semantic principal. This crate cannot select goals, tools, commands, targets, retries or compensations in the owner-open product.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

No default product feature exists. A dependency on this crate must remain outside the selected owner-open closure.

There is intentionally no mechanical replacement for a second semantic policy plane.

## Related module contracts

- [MOD-EXECUTION-CORE](../../docs/modules/MOD-EXECUTION-CORE.md)
- [MOD-PROVIDER](../../docs/modules/MOD-PROVIDER.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionnium-policy-system --all-targets
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
