# Trillionnium sealed privilege-broker protocol

Lifecycle classification: **`sealed_authority_protocol`**

Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)

Default owner-open source closure: **not selected**

## Purpose

This crate retains the closed draft-v2 lifecycle contract used by former privilege-broker and conformance code.

## Authority and product boundary

A privilege or Authority hop is not part of the owner-open default graph. Parsing a request never grants mutation or execution authority.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

`p0-launch-package-device-conformance` is a fixed source-conformance feature, not an installed Android service.

Owner-open protocol and tool-runtime modules provide mechanical contracts without a second semantic authority.

## Related module contracts

- [MOD-PROTOCOL](../../docs/modules/MOD-PROTOCOL.md)
- [MOD-TOOL-RUNTIME](../../docs/modules/MOD-TOOL-RUNTIME.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionnium-privilege-broker-protocol --all-targets
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
