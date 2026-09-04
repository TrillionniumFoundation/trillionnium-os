# Trillionnium OS Module Development Standard

Status: **NORMATIVE**

## 1. Module definition

A module is not merely a directory or Rust crate. It is a stable unit that owns:

- one coherent responsibility and explicit non-goals;
- versioned inputs, outputs and errors;
- authoritative mutable state, or an explicit declaration that it owns none;
- ordering keys and concurrency semantics;
- finite resource contracts;
- SLI/SLO and benchmark profiles;
- failure, recovery and degraded-state behavior;
- compatibility and migration rules;
- source, installed and fault evidence;
- a primary and backup team.

The canonical list is `machine/module-catalog.v1.json`.

## 2. Required contract

Every module entry must declare:

```text
module ID and version
plane
owner and backup teams
source paths
responsibilities and non-goals
dependencies
owned state
ordering keys
resource contract
SLO
API compatibility
state-schema compatibility
rolling-upgrade support
maturity and open gaps
```

A missing field blocks integration.

## 3. Dependency rules

- Dependencies form an acyclic graph.
- Shared contracts may not import product composition roots.
- Mechanism modules may not import semantic policy.
- State owners expose APIs or events; consumers do not write owner storage directly.
- Test-only dependencies cannot enter product feature unification.
- Cross-module imports must use declared interfaces, not private source paths.
- New dependencies require producer and consumer review plus cycle verification.

## 4. State ownership

Each state family has exactly one authoritative owner. Replicas, caches,
indexes and dashboards are explicitly read models.

The owner defines:

- key and partition;
- consistency and durability class;
- writer epoch and fencing behavior;
- retention and capacity;
- schema version;
- recovery and migration;
- authoritative terminal and unknown states.

A module must never infer permission from missing data in another module.

## 5. Concurrency contract

Each operation declares:

- admission resource;
- ordering key;
- maximum concurrency or lease source;
- lock/actor scope;
- slow paths;
- timeout and cancellation semantics;
- backpressure behavior;
- behavior after lease expiry;
- behavior on duplicate and conflict.

Locks across process spawn, network/device I/O, provider waits or fsync require a
written exception, lock-hold measurement and fault proof.

The current `resource_contract.queue_items` is the module resident admission
ceiling, including running work; declared `max_concurrency` cannot exceed it.
A future separate waiting-queue/worker model requires an explicit contract
revision rather than comparison against a global schema maximum.

## 6. Resource contract

At minimum:

```text
CPU share or weight
memory budget
file-descriptor budget
process/thread budget
I/O rate and durability class
queue item and byte limits
store and retention limits
timeout and recovery budget
```

A module cannot improve local throughput by consuming unbounded global
resources. Budget changes are part of the module API and require system
performance review.

## 7. Testing pyramid

Required as applicable:

1. codec and validation unit tests;
2. state-machine property tests;
3. duplicate, conflict and ordering tests;
4. concurrency and contention tests;
5. process and I/O integration tests;
6. migration and rollback tests;
7. performance and capacity tests;
8. target installation tests;
9. destructive fault tests.

Every bug in a correctness or evidence boundary produces a permanent negative test.

## 8. Compatibility

- Public API and protocol use semantic versioning.
- Durable state has an independent schema version.
- A rolling upgrade supports at least the explicitly declared read/write matrix.
- Incompatible changes require dual-read or dual-write, migration, drain, backup
  and rollback steps.
- Unknown extension fields are preserved where the protocol declares extensibility.
- A downgrade that cannot safely read current state fails closed and remains inspectable.

## 9. Delivery and rollback

A module change includes:

- source and generated contract changes;
- module tests and benchmark delta;
- affected requirement and gap records;
- compatibility matrix;
- canary and rollback conditions;
- evidence level and negative claims.

Local benchmark improvement does not override a system-level regression.

## 10. Human ownership

One engineer may have one primary module assignment, but every module must have
at least two maintainers. No critical state, protocol, deployment or release
module may depend on one person's undocumented knowledge.
