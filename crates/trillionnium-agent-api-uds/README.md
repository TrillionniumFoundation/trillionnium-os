# Trillionnium Agent API UDS compatibility transport

Lifecycle classification: **`sealed_legacy_transport`**  
Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)  
Default owner-open source closure: **not selected**

## Purpose

This crate retains the historical Agent API Unix-domain-socket message and compatibility surface.

## Authority and product boundary

The G1 selected host and owner-open protocol own active ingress. This crate may not become a second semantic or transport authority.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

`legacy-plan-methods` exists only for historical vectors; Android production and the default owner-open closure leave it disabled.

Use `apps/trillionnium-owner-open-host` with `crates/trillionnium-owner-open-types`.

## Related module contracts

- [MOD-PROTOCOL](../../docs/modules/MOD-PROTOCOL.md)
- [MOD-TRANSPORT](../../docs/modules/MOD-TRANSPORT.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionnium-agent-api-uds --all-targets
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
