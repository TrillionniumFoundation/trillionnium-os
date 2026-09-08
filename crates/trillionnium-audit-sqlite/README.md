# Trillionnium legacy SQLite audit store

> **HISTORICAL_NON_AUTHORITATIVE.** This component is excluded from the
> `owner-open-core` default profile and cannot define current product behavior.
Lifecycle classification: **`sealed_legacy_store`**  
Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)  
Default owner-open source closure: **not selected**

## Purpose

This crate retains a pre-G1 SQLite audit representation for compatibility and migration inspection.

## Authority and product boundary

It is not an authoritative writer for current owner-open event or operation state. Audit absence is never proof that an effect did not start.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

The package has no active default feature lane. Explicit tests exercise source behavior only.

`crates/trillionnium-owner-open-event-store` owns the selected bounded event, replay and recovery records.

## Related module contracts

- [MOD-EVENT-STORE](../../docs/modules/MOD-EVENT-STORE.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionnium-audit-sqlite --all-targets
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
