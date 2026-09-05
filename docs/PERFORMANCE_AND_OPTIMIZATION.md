# Trillionnium OS Performance and Global Optimization

Status: **NORMATIVE BASELINE — measurements pending**

## 1. Goal

Trillionnium OS pursues globally coordinated constrained optimization. It does
not claim that a dynamic, partially observed operating system is always at an
absolute mathematical global optimum.

The engineering objective is a reproducible global improvement or Pareto
improvement under non-negotiable correctness, durability, isolation, capacity
and evidence constraints.

## 2. Hard constraints

Hard constraints cannot be traded for throughput:

- sole Codex semantic authority;
- exact identity and conflict-before-effect;
- no automatic redispatch after uncertainty;
- required durable acceptance before effect;
- per-ordering-key linearity;
- finite resources and bounded queues;
- lease expiry and fencing;
- truthful terminal and cursor gaps;
- emergency-stop reachability;
- claim ceiling tied to evidence.

## 3. Soft objective

The control plane may minimize a weighted cost such as:

```text
-global useful work
+ latency P99 penalty
+ error penalty
+ unknown-outcome penalty
+ CPU, memory, I/O and energy cost
+ fairness deviation
+ recovery-time penalty
+ rollout-risk penalty
```

Weights are versioned configuration. They remain inactive until workload
baselines exist.

## 4. Local-to-global optimization

A module reports both utility and marginal resource cost. Local optimization is
evaluated as:

```text
local utility
- CPU price × CPU use
- memory price × memory use
- I/O price × I/O use
- latency penalty
- unknown-outcome penalty
- recovery penalty
```

The global controller adjusts prices and budgets slowly. Modules perform
fast-path queueing and scheduling locally inside their leases.

A module PR may not claim optimization by reporting only its own throughput. It
must also report system P99, resource use, downstream queue effects, unknown
rate and global-objective delta.

## 5. Required workloads

The canonical profiles are defined in
`machine/global-objective.v1.json`:

- WL-01 single short command;
- WL-02 32 independent short tasks;
- WL-03 128-client admission burst;
- WL-04 concurrent pipe jobs;
- WL-05 concurrent PTY jobs;
- WL-06 large output;
- WL-07 durable append and replay;
- WL-08 slow client and zero-credit backpressure;
- WL-09 cancellation storm;
- WL-10 process restart;
- WL-11 ADB/USB instability;
- WL-12 storage saturation and recovery.

## 6. Required measurements

Every workload records:

```text
throughput
P50, P95, P99 and maximum latency
queue wait
lock wait and hold
CPU and RSS
file descriptors
threads and processes
I/O bytes and fsync count
recovery time
unknown-outcome rate
redispatch count
fairness
```

Results bind source commit/tree, toolchain, hardware, kernel, filesystem,
durability policy, module versions, control configuration and artifact digest.

## 7. Performance gates

- Correctness regression: always reject.
- P99 or unknown-rate regression: reject unless a reviewed system trade-off
  improves the versioned global objective and remains within budget.
- New thread, cache, queue or worker: requires explicit resource-budget change.
- Store change: requires I/O amplification, ENOSPC and recovery evidence.
- Broker or ordering change: requires mixed-client fairness and correlation evidence.
- Control-weight change: requires shadow replay and canary plan.
- A benchmark without repeat count, confidence data and environment identity is informational only.

## 8. Control stability

Global decisions use hysteresis, maximum adjustment rate, minimum dwell time,
cooldown and rollback thresholds. A controller never oscillates resource
budgets at request frequency.

The mandatory maturity sequence is OBSERVE, SHADOW, ADVISORY, ACTIVE_CANARY,
then ACTIVE. Reinforcement learning or self-tuning policies are not permitted
before deterministic baselines, hard-constraint enforcement and rollback are
proven.
