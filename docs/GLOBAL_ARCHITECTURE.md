# Trillionnium OS Global Architecture

Status: **NORMATIVE**  
Architecture revision: **modular-control-plane-v1**

## 1. Four planes

```text
┌────────────────────────────────────────────────────────────┐
│ Semantic plane                                             │
│ Codex/provider: intent, context, target, tool, retry,       │
│ compensation and interpretation                            │
└────────────────────────────┬───────────────────────────────┘
                             │ exact semantic requests
┌────────────────────────────▼───────────────────────────────┐
│ Global mechanical control plane                            │
│ module registry, budgets, admission, placement, leases,    │
│ epochs, fencing, health, rollout and reconciliation        │
└──────────────┬───────────────────────────────┬─────────────┘
               │ plans and leases              │ read models
┌──────────────▼───────────────────────────────▼─────────────┐
│ Execution plane                                             │
│ ingress, broker, transport, core, provider adapter, turn,   │
│ direct runtime, jobs, streams, Root Linux and Android       │
└────────────────────────────┬───────────────────────────────┘
                             │ facts and observations
┌────────────────────────────▼───────────────────────────────┐
│ State, telemetry and evidence plane                         │
│ WAL, indexes, snapshots, metrics, objective projection,     │
│ qualification artifacts and release evidence                │
└────────────────────────────────────────────────────────────┘
```

The control plane does not sit synchronously in every event path. It issues
finite leases and plans; modules perform local fast-path scheduling within those
leases.

## 2. Module graph

The canonical module list is machine-readable in
`machine/module-catalog.v1.json`. The stable logical graph is:

```text
protocol
 ├─ broker ─ transport ─ execution-core
 ├─ provider ─ turn-engine ─ tool-runtime
 ├─ job-runtime ─ event-store
 ├─ stream
 ├─ telemetry ─ global-control
 ├─ Root Linux ─ Android
 ├─ ADB
 └─ evidence
```

Dependencies must form a directed acyclic graph. Composition roots may depend
on lower-level modules, but lower-level mechanism modules must not import
product semantic policy.

### Logical owners versus build components

`MOD-TOOL-RUNTIME` owns the dependency-free call registry, process runtime and
tool bridge. The registry is a low-level mechanism, not part of
`MOD-EXECUTION-CORE`; provider and turn code can consume it without importing the
Host composition root. Job registry ownership remains with `MOD-JOB-RUNTIME`.
The Host Cargo component implements execution-core and transport, whose module
contracts explicitly declare their producer dependencies.

`docs/generated/COMPONENT_STATUS.md` is generated from root Cargo membership,
catalog source ownership and lifecycle classification. Local manifest edges are
checked against the declared module graph, including optional/target/dev edges.
This is a conservative declaration projection; the source/feature-isolation gate
still verifies the actual Cargo-selected graph. The two planned components stay
in their separate workspace. Python bindings are assigned to their own broker,
provider, Root Linux, ADB or evidence module rather than one shared tools owner.

## 3. State ownership

Every mutable state family has one authoritative owner:

| State | Authoritative module |
| --- | --- |
| broker request custody | broker |
| transport delivery journal | transport |
| live turn state | turn engine |
| call registry and live direct-call handles (volatile) | tool runtime |
| job registry and operation journal | job runtime |
| turn observations and indexes | event store |
| delivery credit and cursor window | stream |
| provider session epoch | provider |
| module leases and control epoch | global control |
| metric windows and objective projections | telemetry |
| install and service topology | Root Linux / Android projection |
| evidence and promotion records | evidence |

Copies outside the owner are read models. A read model cannot authorize a state
transition. Provider sessions, live turns and direct-call handles are volatile;
the product Host coordinates their durable acceptance/terminal observations with
the event store. The evidence index is a navigation projection over externally
retained immutable packages, not a runtime journal.

## 4. Consistency model

Consistency is selected by state family, not by one global database:

- effect identity and per-operation transitions require linearizable per-key ordering;
- event streams require monotonic sequence and explicit gaps;
- global metrics are eventually consistent read models;
- module placement and write ownership require epoch and fencing;
- deployment manifests and evidence objects are immutable content-addressed records.

Cross-module workflows use explicit durable transitions and reconciliation. A
mechanical module never schedules a semantic compensating effect or redispatch.
Slow work stays outside shared metadata locks.

## 5. Concurrency partitions

Each request carries or derives an ordering key. Work with the same key is
serialized; independent keys may proceed concurrently within budget.

Typical partitions:

```text
turn_stream_id
call_id
job_id
operation_id
client_id + request_id
module_id + state_partition
target_id + operation_id
```

Global locks are permitted only for bounded metadata transitions. No lock may be
held across process spawn, external I/O, fsync, provider response, device
transport or other unbounded slow paths unless a written proof and benchmark
justify it.

## 6. Leases and fencing

The global control plane issues leases containing:

```text
control_epoch
lease_id
module_id
module_instance_id
partition
resource budget
maximum concurrency
priority class
fencing token
issued_at
expires_at
```

A module validates the lease at admission and validates the fencing token when
mutating owned durable state. An expired or superseded instance may finish
read-only cleanup but cannot continue authoritative writes.

Control-plane outage behavior is bounded and declared per module:

- existing non-expired leases may continue;
- new effectful admissions stop when required authority expires;
- read-only inspection and cleanup remain available where possible;
- no control-plane recovery action automatically repeats an uncertain effect.

## 7. Failure domains

Process, module, host, Root Linux, Android boot, storage, USB/device and control
plane are separate failure domains. Each module publishes health facts without
claiming semantic success.

Recovery follows:

```text
detect
  -> fence stale writer
  -> inspect durable and live facts
  -> classify exact, terminal, unknown or reconciliation-required
  -> restore mechanical service
  -> expose truth to Codex/operator
```

## 8. Evolution policy

The current repository remains a modular monorepo. A module moves to an
independent repository only after its API and state schema are stable, its
release cadence is independent and cross-repository atomic changes are no
longer routine.

Process isolation is selected by failure, credential and lifecycle boundaries,
not by a rule that every module must be a service.
