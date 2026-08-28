# trillionnium-owner-open-stream-window

Mechanism-only byte-credit and pause/resume state for owner-open event streams.

This crate provides a finite stream window, exact control sequencing,
idempotent duplicate controls, bounded retained history and concurrent credit
reservation. It does not classify commands, approve tools, choose targets,
rewrite data, interpret model output or confer execution authority.

Current source scope:

- `stream.window_update` adds finite byte credit;
- `stream.pause` and `stream.resume` gate new reservations;
- `stream.close` permanently closes the local stream window;
- duplicate controls with identical bytes are idempotent;
- a sequence gap, stale trimmed control or changed duplicate fails without
  mutating state;
- concurrent reservations cannot overdraw credit.

The crate is part of the exact R5 Cargo source closure. Host integration and
executed Rust evidence remain separate gates.
