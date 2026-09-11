# Trillionnium OS Performance and Global Optimization

Status: **NORMATIVE SOURCE QUALIFICATION CONTRACT — controlled measurements pending**

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

### 7.1 Stable-batch qualification protocol

`tools/perf/performance_qualification.py` is the fail-closed source contract for
comparison admission. It accepts exactly three same-binary baseline batches
(`A1`, `A2`, `A3`) and three candidate batches (`C1`, `C2`, `C3`). Each batch
must preserve every raw sample for WL-01 through WL-10 in both `cold_start` and
`steady_state`, with at least 50 measured repetitions per series and no outlier
deletion. The verifier recomputes median, P90, P95, P99, maximum, median
absolute deviation, standard deviation and a declared 95% mean confidence
interval. A median or P95 inter-batch spread above the reviewed 10% ceiling
returns `UNSTABLE_ENVIRONMENT` and prevents candidate comparison.

The installed L2 mode additionally requires observed, non-null values for the
full Broker/Host/journal/Provider/tool/delivery stage matrix and every core
resource counter, including CPU user/system time, current/peak RSS,
FD/thread/process peaks, context switches, cgroup CPU/memory/I/O/pids, read and
write bytes, fsync count, queue depth/wait, lock wait/hold, unknown rate, zero
automatic redispatch and fairness. An explicit `unavailable` value is valid for
an L1 source fixture but makes an L2 decision impossible; it is never converted
to zero. WL-11 remains an L4 physical-device hold and WL-12 remains an L5
destructive-fault hold.

The qualification policy is loaded from the checked-in, closed-world registry
`tools/perf/performance_qualification_policy_registry.v1.json`. Every batch and
report records its exact registry version and byte SHA-256; caller-supplied
thresholds, repeat minima, sample semantics, redispatch or release flags must be
byte-for-byte equal to that authoritative entry. The verifier also recomputes a
content-addressed work contract over workload-configuration digests, phases,
repetition count and every per-sample operation denominator, and requires that
contract to be identical across all six batches.

The fixed policy compares median, P95 and P99 latency and normalized throughput
against a 25% regression ceiling, derives unknown rate from the raw
`unknown_outcome` booleans, rejects any contradiction with an observed counter,
rejects every L2 unknown outcome, and bounds fairness loss. Input artifacts are
opened nonblocking and no-follow, then accepted only as singly-linked regular
files before bounded descriptor reads. Passing source mode returns
`SOURCE_COMPARISON_PASS_NOT_L2`; it does not install a target, close an external
gap or authorize release.

## 8. Control stability

Global decisions use hysteresis, maximum adjustment rate, minimum dwell time,
cooldown and rollback thresholds. A controller never oscillates resource
budgets at request frequency.

The mandatory maturity sequence is OBSERVE, SHADOW, ADVISORY, ACTIVE_CANARY,
then ACTIVE. Reinforcement learning or self-tuning policies are not permitted
before deterministic baselines, hard-constraint enforcement and rollback are
proven.
