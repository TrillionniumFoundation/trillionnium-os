# trillionnium-owner-open-provider-jsonl

This crate launches one external provider process for one owner-open turn and
speaks `trillionnium.owner-open.provider-jsonl.v1` over bounded stdin/stdout
JSONL.

The provider may emit model/status events, issue `shell.exec` or `adb.exec`,
receive the complete raw process observation, continue reasoning and then emit
one turn terminal. Provider input is decoded recursively without duplicate JSON
members. Per-direction sequences, line/aggregate stdout limits, bounded stderr,
one process group and timeout/cleanup are enforced mechanically.

Unknown tool labels are returned to the provider as an `invalid_request`
observation; they do not create a semantic policy decision or kill the turn.
The adapter injects no ADB serial, host, port or privilege argument.

Current limits:

- one provider process per turn;
- synchronous tool callback;
- one bounded aggregate `tool.result` frame per call;
- no PTY provider request support;
- no serviceable external cancel while the synchronous provider callback is
  running;
- no durable event store or restart replay.

Current claim ceiling: **SOURCE_IMPLEMENTED / L0** until the exact commit passes
Rust formatting, all-target tests and clippy.
