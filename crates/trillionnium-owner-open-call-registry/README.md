# Trillionnium owner-open call registry

This crate is the isolated W1/W2 in-memory call-state substrate for the r4
owner-open Host. It provides correlation, no-double-spawn, cancellation and
uncertainty mechanics. It does not interpret command meaning, approve a tool,
retry an effect, persist authority or confer execution permission.

## State model

A call is scoped by:

```text
session_id
profile_id
task_id
turn_id
turn_stream_id
call_id
```

and is bound to the exact:

```text
request_sha256
binding_fingerprint
tool
target_id
```

The effective states are:

- `Accepted`;
- `Started { generation, pid? }`;
- `CancelledBeforeSpawn`;
- `ProvenNotStartedAfterDisconnect`;
- `UnknownAfterDisconnect { generation, pid? }`;
- `Terminal { generation, observation }`.

## Implemented invariants

- an exact duplicate begin attaches to the existing call;
- the same scoped `call_id` with different request/binding/tool/target bytes is
  rejected;
- only one concurrent caller receives a spawn generation;
- all later spawn claims attach to the existing state;
- cancellation before spawn permanently inhibits that call;
- disconnect before spawn permanently proves no spawn and inhibits it;
- disconnect after spawn is unknown until a terminal observation arrives;
- process identity and terminal records are generation-bound;
- identical PID/terminal records are idempotent;
- conflicting PID/terminal records are rejected;
- cancellation is a shared atomic signal and its event is recorded once;
- bounded history exposes an explicit earliest available cursor;
- only terminal records are removed, and cleanup is explicit.

## Explicit non-claims

This crate is currently a nested standalone workspace. It is not yet imported
by `trillionnium-owner-open-host` or `trillionnium-owner-open-runtime` and has
not been compiled by an observed Rust 1.93 runner. It does not prove:

- a provider tool-call decoder;
- one real shell/ADB process spawn;
- process PID callbacks from the runtime;
- durable accepted/started/terminal storage;
- resume across Host restart;
- a live Codex turn;
- Root Linux/Android integration;
- physical-device or release evidence.

The source claim ceiling remains `L1_CALL_REGISTRY_SOURCE_ONLY` until its tests
run and a reviewed Host graph imports it.

## Validation

```sh
cargo fmt --manifest-path \
  crates/trillionnium-owner-open-call-registry/Cargo.toml -- --check
cargo test --manifest-path \
  crates/trillionnium-owner-open-call-registry/Cargo.toml
```

After a successful standalone run, integration must still prove that the Host
calls `begin` and `claim_spawn` before the process runtime and records the same
generation/PID/terminal after execution.
