# Performance Status

<!-- GENERATED. DO NOT EDIT. -->

- Objective mode: `SPECIFIED_BASELINE_NOT_MEASURED`
- Baseline gap: `OPEN`
- Optimization claim: globally coordinated constrained optimization; no claim of unconditional mathematical global optimum

## Hard constraints

- Codex/provider is the only semantic principal
- no mechanism component rewrites valid command semantics
- identity conflict is rejected before effect
- automatic redispatch is false after any uncertain effect boundary
- required durable acceptance precedes effect
- per-ordering-key transitions are linearizable
- stale epochs and fencing tokens cannot write owned state
- all queues, stores, processes, descriptors and frames are finite
- emergency stop remains independent of provider health
- evidence claims never exceed retained evidence level

## Workload profiles

| ID | Workload |
| --- | --- |
| `WL-01` | single client short command |
| `WL-02` | 32 independent short tasks |
| `WL-03` | 128-client admission burst |
| `WL-04` | concurrent long-running pipe jobs |
| `WL-05` | concurrent PTY jobs |
| `WL-06` | large stdout and stderr |
| `WL-07` | durable append and replay |
| `WL-08` | slow client and zero-credit backpressure |
| `WL-09` | provider cancellation storm |
| `WL-10` | broker, transport and core restart |
| `WL-11` | ADB and USB instability |
| `WL-12` | storage saturation, ENOSPC and recovery |

## Required measurements

`throughput`, `latency_p50`, `latency_p95`, `latency_p99`, `latency_max`, `queue_wait`, `lock_wait`, `lock_hold`, `cpu`, `rss`, `fd_count`, `thread_count`, `process_count`, `io_bytes`, `fsync_count`, `recovery_time`, `unknown_rate`, `redispatch_count`, `fairness`

No global performance or optimality claim is promotable until the workload profiles produce retained exact-source artifacts.
