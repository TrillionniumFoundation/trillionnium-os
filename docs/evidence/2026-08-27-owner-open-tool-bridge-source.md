# 2026-08-27 owner-open tool bridge source record

Evidence level: **L1 source-authored, validation pending**  
Branch: `codex/owner-open-r4-foundation-20260827`  
Source: `crates/trillionnium-owner-open-tool-bridge`

## Scope

This record covers the first source package that binds one exact owner-open call
claim to the direct local shell/raw-ADB process runtime. It uses the isolated
call registry for no-double-spawn and the owner-open runtime for mechanical
process execution.

It is not yet imported by the production owner-open Host and does not parse a
real provider or wire tool event.

## Source set

| Path | Purpose |
| --- | --- |
| `crates/trillionnium-owner-open-tool-bridge/Cargo.toml` | Isolated bridge graph |
| `crates/trillionnium-owner-open-tool-bridge/src/lib.rs` | Request binding, spawn claim, cancellation and terminal handoff |
| `crates/trillionnium-owner-open-tool-bridge/tests/bridge.rs` | Real local process and fake ordinary-adb integration tests |
| `crates/trillionnium-owner-open-tool-bridge/README.md` | Scope and non-claims |
| `docs/implementation/owner-open-tool-bridge-v1.md` | Detailed ordering and failure semantics |
| `docs/status/owner-open-r4-w1-w2-tool-bridge-status.json` | Machine claim ceiling |

## Intended source facts

1. Canonical request bytes are hashed by the bridge.
2. An optional provider/wire claimed digest must match before registry
   admission.
3. The registry binds request digest, binding fingerprint, tool and target.
4. Only a `Granted` spawn claim may invoke the process runtime.
5. Existing and pre-spawn-inhibited calls return without another process.
6. One shared registry cancellation signal reaches the runtime cancellation
   token through a bounded monitor.
7. Runtime Started events bind PID to the exact spawn generation.
8. Ordered accepted/started/output/terminal bytes feed a local observation
   digest.
9. Raw runtime events are forwarded to an embedding Host sink without command
   classification.
10. Registry terminal completion precedes a returned monitor/runtime/PID/sink
    error.
11. Runtime validation and monitor creation failures create local terminal
    records instead of leaving Started indefinitely.
12. A sink panic is caught, causes cancellation and does not unwind past the
    process lifecycle boundary.

## Authored integration matrix

| Test | Intended proof |
| --- | --- |
| shell stdout/stderr | raw bytes, PID and exactly one terminal reach the bridge |
| two concurrent duplicate dispatches | one real counter-file process effect |
| conflicting canonical bytes | no second process effect |
| claimed digest mismatch | failure before registry entry/process |
| shared registry cancel | `sleep` process group reaches Cancelled terminal |
| fake ordinary adb | unknown argv preserved and no target/`-s` injection |
| missing executable | SpawnFailed still closes registry terminal |

## Canonical-request limitation

The tests author canonical bytes directly. Production integration must prove
that strict owner-open codec normalization and the typed runtime request are
created from one parse result. Until then the bridge is not an externally safe
wire boundary.

## Required validation

```sh
cargo fmt --manifest-path \
  crates/trillionnium-owner-open-tool-bridge/Cargo.toml -- --check
cargo test --manifest-path \
  crates/trillionnium-owner-open-tool-bridge/Cargo.toml
```

A later outer-workspace integration must repeat these tests with the Host's
actual codec and event sink.

## Current hold

No observed Rust 1.93 runner has compiled this source. The existing Host does
not import the bridge, provider events are not normalized, output is not durably
spooled, and no Root Linux/ARM64 adb/Android target is bound.

## Accurate statement

> A source bridge now connects one exact in-memory call claim to direct local
> shell or ordinary-adb process execution, with duplicate/cancel/failure tests.
> Compilation and live Host/provider/device integration remain unproven.
