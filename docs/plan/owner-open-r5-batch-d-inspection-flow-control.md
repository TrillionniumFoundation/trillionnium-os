# R5 Batch D checkpoint: inspection and flow control

This checkpoint implements the next source batch under the active R5 plan.
It does not change the R3 semantic contract or raise the evidence ceiling above
L0.

## Landed source slices

1. selected Host v4 exposes read-only `turn.inspect` and `call.inspect`;
2. active inspection uses the live call registry without cancelling or mutating
   the turn;
3. restart inspection uses validated durable frames and exact request binding;
4. inspection responses are not persisted and never redispatch an effect;
5. `trillionnium-owner-open-stream-window` supplies bounded byte credit,
   pause/resume/close, exact control sequencing and bounded history;
6. Cargo, graph contracts and CI candidate commands include the new source
   closure.

## Required runner gate

The exact commit must run Rust 1.93 formatting, all-target tests and clippy for
the complete owner-open default closure. Until that exists, every new Rust
capability remains `SOURCE_IMPLEMENTED / L0`.

## Next source sequence

1. bind the stream window to Host outbound queues while preserving
   persist-before-delivery;
2. add durable job records and attach/write/resize/close-stdin/kill;
3. run the existing Codex CLI probe in the target Root Linux environment and
   implement the observed native adapter;
4. implement the selected physical ADB topology;
5. cut the Android owner-open product graph.
