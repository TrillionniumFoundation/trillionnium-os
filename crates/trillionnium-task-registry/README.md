# Trillionnium legacy task registry

Lifecycle classification: **`sealed_legacy_registry`**

Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)

Default owner-open source closure: **not selected**

## Purpose

This crate retains the pre-G1 combined task registry model for compatibility tests and source archaeology.

## Authority and product boundary

It must not become an alternate writer for active call or job state, and missing legacy state never authorizes an effect.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

The package has no feature-selected product lane. Explicit compilation is not product admission.

The active graph separates call ownership and job ownership into `trillionnium-owner-open-call-registry` and `trillionnium-owner-open-job-registry`.

## Related module contracts

- [MOD-EXECUTION-CORE](../../docs/modules/MOD-EXECUTION-CORE.md)
- [MOD-JOB-RUNTIME](../../docs/modules/MOD-JOB-RUNTIME.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionnium-task-registry --all-targets
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
