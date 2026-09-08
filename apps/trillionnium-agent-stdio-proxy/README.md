# Trillionnium Agent stdio proxy

Lifecycle classification: **`sealed_fixed_fd_proxy`**  
Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)  
Default owner-open source closure: **not selected**

## Purpose

This source-only executable preserves a byte-exact fixed-control-file-descriptor MCP stdio proxy boundary for compatibility and negative testing.

## Authority and product boundary

It is excluded from the selected owner-open product entrypoint. It cannot select another provider, invent a command, widen a target, create effect authority or turn a transport result into semantic success.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

The package has no default features. Building it explicitly does not install it or make the fixed control descriptor available on a target.

The active owner-open host provides the selected ingress and transport composition root.

## Related module contracts

- [MOD-PROTOCOL](../../docs/modules/MOD-PROTOCOL.md)
- [MOD-TRANSPORT](../../docs/modules/MOD-TRANSPORT.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionnium-agent-stdio-proxy --all-targets
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
