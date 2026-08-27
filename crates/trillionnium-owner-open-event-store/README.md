# trillionnium-owner-open-event-store

This crate is the R5 append-only observation store. It records provider/tool/
turn events for replay and conservative restart analysis. It is explicitly not
an authorization journal and does not decide whether a direct call may execute.

Source properties:

- one non-blocking exclusive writer lock;
- owner-controlled regular `0600` file opened with `O_NOFOLLOW|O_CLOEXEC`;
- global `store_seq` and per-turn `turn_seq`;
- event identity scoped by session/profile/task/turn/turn-stream/event ID;
- payload digest and chained record digest;
- exact duplicate append is idempotent;
- same event identity with different bytes conflicts;
- strict recursive duplicate-member rejection on reopen;
- truncated, reordered, tampered or over-capacity files fail closed;
- inclusive per-turn replay;
- none/data/full sync policy;
- ambiguous append failure poisons the writer so absence is never misreported as
  proof that no effect occurred.

The embedding owner-open Host must treat store availability as observability.
A storage failure may mark a lineage best-effort/unreplayable, but it must not
silently become a semantic command denial.

Current claim ceiling: **SOURCE_IMPLEMENTED / L0** until the exact commit passes
Rust formatting, all-target tests and clippy. The store is not yet bound into
the R5 Host event path or restart reconciliation.
