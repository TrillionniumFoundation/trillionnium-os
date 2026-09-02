# Trillionnium Owner-Open Types

This Cargo component implements the shared protocol and identity contract for [`MOD-PROTOCOL`](../../docs/modules/MOD-PROTOCOL.md). The machine authority is `docs/machine/module-catalog.v1.json`; the formal module document explains the cross-component contract.

## Purpose

The crate defines and validates canonical versioned envelopes and the identities needed to correlate provider, host, broker, transport, runtime, job, event, stream and evidence records. A wire value is accepted only after its version, shape, bounded fields, duplicate/conflict semantics and unknown-field rule have been checked.

The crate is deliberately free of semantic policy. Types do not grant authority, choose a command, select a device, schedule a goal, retry an operation or infer completion.

## Identity invariants

Request, call, job, turn, connection, target, module, service and evidence identities are domain-separated. Reusing an identity with changed content is a conflict. When a digest is part of a protocol contract, equality of the human-readable operation kind is insufficient; the exact canonical content and broker-assigned lineage must match.

Unknown or partial identity is rejected before an effect is admitted. A parser never supplies a security-sensitive default for a missing principal, target, epoch or ordering field.

## Versioning and encoding

The active API schema identifier is `org.trillionnium.mod_protocol.api.v1`; the active state schema identifier is `org.trillionnium.mod_protocol.state.v1`. Concrete public wire names include `protocol_envelope_v1`, `protocol_identity_v1` and `protocol_error_v1`.

Incompatible changes require a new version. Unknown fields are rejected under the current contract. Canonical encoding must be deterministic wherever content is hashed or signed. Duplicate JSON members, non-finite numbers, oversized values and unsupported versions fail closed.

## Resource and security boundary

The catalog values are finite source ceilings, not measured benchmark results. Protocol parsing must bound allocation before decoding nested or repeated content. Logs expose structural error classes and version information without emitting prompts, credentials, command bodies or raw secrets by default.

Protocol validation may reject unauthenticated, stale, malformed or over-budget input. It may not convert input into a more privileged identity or loosen a trust boundary during incident recovery.

## Build and verification

The root G1 source gate formats, tests and runs strict Clippy against the locked workspace. Protocol changes require unit, negative, property or fuzz-style boundary tests for canonicalization, duplicate identity, changed-content conflict, size limits, unknown fields and unsupported versions.

Passing source tests does not establish installed-target interoperability. An installed or cross-language claim must bind the exact producer and consumer binaries, schema versions and retained wire observations.

## Change checklist

Update the formal module document and machine contracts in the same exact-head change whenever a public type, field, version, identity domain, canonical encoding rule, error or compatibility behavior changes. Preserve fail-closed decoding and no automatic redispatch across every version boundary.
