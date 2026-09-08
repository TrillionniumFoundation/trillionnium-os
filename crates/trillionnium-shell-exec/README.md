# Trillionnium sealed typed shell execution

Lifecycle classification: **`sealed_typed_shell`**  
Lifecycle authority: [`governance/component-lifecycle.v1.json`](../../governance/component-lifecycle.v1.json)  
Default owner-open source closure: **not selected**

## Purpose

This crate retains typed shell clients, adapters and explicit host/Android conformance binaries.

## Authority and product boundary

It is not selected by the default owner-open source closure and must not substitute a typed semantic broker for exact shell bytes and observations.

This component cannot authorize semantic intent, silently select a substitute
backend, fabricate a terminal result or automatically redispatch an uncertain
effect. A successful source test does not establish installed-target, Android,
physical-device, destructive-fault or release qualification.

## Feature and build boundary

`root-linux-mcp-adapter`, `android-product` and `host-conformance` are explicit mutually scoped lanes. The package publishes no crate and no default binary authority.

The active owner-open job runtime and tool bridge own process lifecycle and byte-preserving tool transport.

## Related module contracts

- [MOD-TOOL-RUNTIME](../../docs/modules/MOD-TOOL-RUNTIME.md)
- [MOD-ROOTLINUX](../../docs/modules/MOD-ROOTLINUX.md)
- [MOD-ANDROID](../../docs/modules/MOD-ANDROID.md)

The module documents describe current logical ownership. This README describes
only this concrete sealed component and does not override the machine module
catalog.

## Local source verification

From the repository root:

```sh
cargo test --locked -p trillionnium-shell-exec --all-targets
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
