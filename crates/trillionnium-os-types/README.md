# Trillionnium OS legacy types

Lifecycle classification: **`sealed_legacy_contracts`**

Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)

Default owner-open source closure: **not selected**

## Purpose

This crate retains pre-G1 shared contracts and device-conformance models used by explicitly selected source and compatibility tests.

## Authority and product boundary

It is not the active owner-open protocol authority and must not re-enter the default graph through a dependency or feature.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

`p0-launch-package-device-conformance` exposes only the fixed source-conformance model. It does not grant Android launch or effect authority.

`crates/trillionnium-owner-open-types` is the active default protocol and identity component.

## Related module contracts

- [MOD-PROTOCOL](../../docs/modules/MOD-PROTOCOL.md)
- [MOD-TOOL-RUNTIME](../../docs/modules/MOD-TOOL-RUNTIME.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionnium-os-types --all-targets
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
