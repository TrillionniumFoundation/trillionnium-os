# Owner-open R5 r6 source-gap closure candidate

Status: **SOURCE AUTHORED — exact-head L1 validation pending**  
Plan revision: `2026-08-29-r6`  
Branch: `codex/owner-open-r5-gap-closure-20260829`  
Public release: **false**

This candidate currently includes source changes for portions of:

```text
R5-GAP-JOB-ADMISSION-001       Issue #14
R5-GAP-PROCESS-LIFECYCLE-001   Issue #15
R5-GAP-STREAM-RECOVERY-001     Issue #16
R5-GAP-JOURNAL-CONVERGENCE-001 Issue #17
```

Authored behavior includes:

- finite job capacity is checked while holding the live-job admission lock and
  before durable start acceptance or child spawn;
- post-spawn start failures signal the process group, remove live ownership,
  preserve a conservative registry state and record the strongest available
  terminal/degraded result;
- output drains start before non-empty initial stdin, which is written by a
  separate bounded worker;
- Linux/Android job children configure parent-death signaling with a parent-PID
  race check;
- leader exit is followed by finite process-group TERM/KILL cleanup and cleanup
  uncertainty is a typed process fault;
- `job.output` participates in the selected bounded stream window;
- bounded job-observation retention reports `oldest_available_cursor`, exact
  missing range and durable-fallback availability;
- the job manager retains the first journal failure, advertises unreplayable
  degradation and inhibits durability-required controls;
- terminal process truth converges in the registry even when terminal journal
  persistence fails.

New regressions cover:

- capacity rejection before a marker-producing command can spawn;
- a child that writes one MiB before reading initial stdin;
- exact retained-prefix gap metadata;
- background descendant cleanup after leader exit;
- `job.output` pause/credit behavior.

None of these statements is promoted to `SOURCE_CLOSED_PENDING_EVIDENCE` until
all permanent exact-head gates pass:

```text
cargo fmt --all -- --check
cargo test --locked --all-targets
cargo clippy --locked --all-targets -- -D warnings
complete Python/broker/MCP/graph/gap tests
```

Even after L1 source closure, target Root Linux lifecycle requires L2 and the
crash/ENOSPC/reboot/power-loss matrix requires L5. Automatic redispatch remains
false.
