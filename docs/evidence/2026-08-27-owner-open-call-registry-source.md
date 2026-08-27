# 2026-08-27 owner-open call registry source record

Evidence level: **L1 source-authored, validation pending**  
Branch: `codex/owner-open-r4-foundation-20260827`  
Source: `crates/trillionnium-owner-open-call-registry`

## Scope

This record covers an isolated process-local call registry for the future Rust
owner-open Host. It binds exact request facts to one turn-scoped call ID, grants
at most one process spawn generation, exposes a shared cancellation signal and
keeps disconnect/terminal uncertainty explicit.

It does not parse provider events, start a process, persist durable state, retry
an operation, contact Codex or run on Android.

## Source set

| Path | Purpose |
| --- | --- |
| `crates/trillionnium-owner-open-call-registry/Cargo.toml` | Dependency-free nested workspace package |
| `crates/trillionnium-owner-open-call-registry/src/lib.rs` | State machine and concurrency boundary |
| `crates/trillionnium-owner-open-call-registry/tests/concurrency.rs` | Multi-thread and generation-binding tests |
| `crates/trillionnium-owner-open-call-registry/README.md` | Scope and non-claims |
| `docs/implementation/owner-open-call-registry-v1.md` | Integration and uncertainty semantics |
| `docs/status/owner-open-r4-w1-w2-call-registry-status.json` | Machine claim ceiling |

## Intended source facts

1. The key includes session/profile/task/turn/turn-stream/call IDs.
2. The bound request includes exact request digest, binding fingerprint, tool and
   target correlation.
3. Exact duplicate `begin` returns existing state without another accepted
   event.
4. Any bound-request difference under the same key is conflict.
5. A global mutex serializes transitions; cancellation uses one shared atomic.
6. Only `claim_spawn` allocates a non-zero monotonic spawn generation.
7. Cancellation or disconnect before spawn permanently inhibits that call ID.
8. Disconnect after spawn is unknown and never triggers retry.
9. PID and terminal records require the exact spawn generation.
10. Exact duplicate PID/terminal writes are idempotent; conflicts fail.
11. A late terminal closes an unknown disconnected call.
12. Bounded event history exposes its earliest available sequence.
13. Active entries cannot be removed by terminal cleanup.

## Authored concurrency matrix

| Test | Intended proof |
| --- | --- |
| 32 concurrent exact begins | one New, all others Existing |
| 32 concurrent spawn claims | exactly one Granted generation |
| two concurrent request variants | one accepted, one call-ID conflict |
| identical labels in different scopes | independent generations |
| PID/terminal generation binding | idempotent exact writes and conflict rejection |
| cancel before spawn | shared signal plus permanent inhibition |
| cancel after spawn | active state plus shared stop request |
| disconnect/reconnect/late terminal | uncertainty is monotonic and terminal closes it |
| capacity and cleanup | active calls retain capacity until explicit terminal cleanup |

Embedded unit tests additionally cover bounded history, exact cancel-event
idempotency and disconnect-before-spawn proof.

## Required validation

```sh
cargo fmt --manifest-path \
  crates/trillionnium-owner-open-call-registry/Cargo.toml -- --check
cargo test --manifest-path \
  crates/trillionnium-owner-open-call-registry/Cargo.toml
```

The package is intentionally a nested workspace for this source slice. After
standalone validation it must be imported into the owner-open Host in a separate
reviewed graph change and tested again in the complete outer workspace.

## Current hold

No observed Rust 1.93 runner has formatted or compiled this source. The outer
Host does not import it, the process runtime does not publish PID/terminal
callbacks into it, and there is no durable store or restart reconciliation.

The registry's in-memory history is not replay evidence across a Host crash.
Absence of an entry after restart is not proof of not-started.

## Accurate statement

> A dependency-free in-memory exact-call/no-double-spawn state machine and its
> unit/concurrency tests have been authored. Compilation and Host/runtime
> integration remain unproven.
