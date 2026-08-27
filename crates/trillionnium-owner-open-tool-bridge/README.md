# Trillionnium owner-open tool bridge

This isolated W1/W2 source package connects the in-memory call registry to the
direct shell/raw-ADB process runtime. It is the first source slice that can
place a real local process behind a scoped call ID without importing the pre-r3
plan, Authority, capability-lease, shell-broker or typed-ADB graphs.

## Handoff

```text
codec-authored canonical request bytes
  -> BoundToolCall / request SHA-256
  -> CallRegistry.begin
  -> CallRegistry.claim_spawn
  -> direct shell or ordinary adb process runtime
  -> PID/output/terminal events
  -> CallRegistry.record_pid / complete
  -> embedding Host event sink
```

## Mechanism invariants

- the bridge hashes canonical bytes itself;
- an optional caller digest must match those bytes;
- the registry binds request digest, binding fingerprint, tool and target;
- exactly one concurrent caller obtains a spawn generation;
- duplicate callers attach to existing in-memory state;
- pre-spawn cancellation/disconnect inhibits spawn;
- registry cancellation is bridged to the runtime cancellation token;
- PID is generation-bound;
- raw runtime events are forwarded without semantic reclassification;
- a local observation digest binds call/tool/target/generation and ordered
  accepted/started/output/terminal bytes;
- runtime validation, monitor creation and sink failure paths close the registry
  with a terminal record rather than leaving an unbounded Started entry;
- exact terminal facts are recorded before a bridge error is returned.

## Canonical-request trust boundary

The bridge does not parse JSON or duplicate the owner-open codec. The embedding
codec supplies the exact canonical bytes it validated into the typed runtime
request. The first Host integration must prove that both values come from one
parse/normalization result; arbitrary callers must not be allowed to bind bytes
that do not describe the supplied process request.

## Source tests

- shell stdout/stderr, PID, one terminal and observation digest;
- two concurrent duplicate dispatches produce one real process effect;
- conflicting canonical bytes do not spawn again;
- claimed digest mismatch fails before registry admission;
- registry cancellation terminates a running process group;
- fake ordinary adb receives unknown argv unchanged and no target/serial
  injection;
- spawn failure still records a terminal state.

## Current hold

This crate is a nested standalone workspace and has not run under an observed
Rust 1.93 runner. It is not yet imported by `trillionnium-owner-open-host`, and
its canonical request bytes are supplied by tests rather than the production
codec. It does not prove a live Codex turn, durable replay, Root Linux identity,
real ARM64 adb, Android image or physical effect.

## Validation

```sh
cargo fmt --manifest-path \
  crates/trillionnium-owner-open-tool-bridge/Cargo.toml -- --check
cargo test --manifest-path \
  crates/trillionnium-owner-open-tool-bridge/Cargo.toml
```
