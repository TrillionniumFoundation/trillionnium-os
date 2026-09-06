# Trillionnium OS Global Modular Development Program

Status: **ACTIVE CANDIDATE**  
Program revision: **2026-08-31-g1**

## 1. Program objective

G1 converts the existing Owner-Open implementation into a team-scalable,
globally coordinated modular system without weakening semantic authority,
effect identity, durability or evidence boundaries.

The program has two orthogonal axes:

- **capability milestones** describe end-to-end product closure from L1 source
  through L6 release;
- **module workstreams** provide stable long-term ownership for parallel teams.

A work package is not complete because source exists. Completion requires the
observable exit stated by its capability and gap records.

## 2. Current baseline model

The program distinguishes:

1. protected trunk;
2. latest exact source-CI result;
3. latest unqualified source parent;
4. this documentation candidate.

These identities are recorded in `machine/current-baseline.v1.json`. The
checked-in candidate does not embed or infer its own Git commit. CI emits the
exact head, tree, lockfile, commands, jobs, artifacts and review state.

## 3. Phases

### G1-P0 — truth convergence and document reset

Deliver:

- one active document set;
- deletion of historical development plans and status snapshots from the tree;
- one machine source for baseline, program, module, requirement, gap, objective
  and evidence state;
- generated status and traceability views;
- exact-head documentation verification.

Exit: `GAP-DOC-SINGLE-TRUTH-001` has L1 evidence and independent review.

### G1-P1 — module contracts and ownership

Deliver:

- stable module IDs and logical team ownership;
- responsibility and non-goal boundaries;
- unique mutable-state ownership;
- versioned APIs and state schemas;
- resource, SLO, fault and evidence contracts;
- dependency-cycle and forbidden-edge checks.

Exit: every active product path maps to one or more catalogued modules, and no
state family has conflicting authoritative owners.

### G1-P2 — concurrency and persistence scalability

Deliver in order:

1. Broker multi-inflight protocol with exact result isolation and per-key ordering.
2. Job admission tokens and per-key transitions without slow-path global locks.
3. Segmented, indexed Event Store with bounded group commit and recovery.
4. Sharded registries preserving per-key linearity.
5. Event-driven cancellation and bounded turn event storage.
6. Repeatable mixed-workload performance baseline.

Exit: all P0 concurrency gaps reach source closure and installed L2 evidence.

### G1-P3 — global control in shadow mode

Deliver:

- module instance registry;
- resource and concurrency leases;
- control epochs and fencing;
- telemetry read models and cost curves;
- deterministic shadow decisions;
- controller-outage behavior;
- decision audit and rollback.

The progression is mandatory:

```text
OBSERVE -> SHADOW -> ADVISORY -> ACTIVE_CANARY -> ACTIVE
```

No active control is enabled before shadow predictions are compared with
measured outcomes and hard constraints are machine-enforced.

### G1-P4 — installed Root Linux and Android integration

Deliver:

- one content-addressed install manifest;
- installed product entrypoint and internal children;
- Codex/provider identity and exact bytes;
- cgroups, namespaces, mounts, stores and restart;
- clean Android Soong/init/SELinux graph;
- target-files binding and emergency stop.

Exit: L2 and L3 evidence.

### G1-P5 — physical and destructive qualification

Deliver:

- same-turn Root Linux shell;
- pipe and PTY job control;
- ordinary ADB and visible physical effects;
- provider/core/transport/broker/client crashes;
- storage saturation and corruption;
- USB loss, ADB server loss, reboot and power-loss recovery.

Exit: L4 and L5 evidence with zero automatic redispatch.

### G1-P6 — optional sealed/public profile

Deliver only after productive dogfood:

- explicit sealed-profile restrictions;
- signing and transparency;
- AVB, rollback and OTA;
- key custody and revocation;
- multi-user review;
- independent human go/no-go.

Exit: L6. This phase is never a prerequisite for owner-open dogfood.

## 4. Critical path

The machine critical path is in `machine/program-state.v1.json`. Operationally:

```text
exact G1 docs CI and review
 -> integrate R15 source parent through protected chain
 -> Broker multiplexing
 -> Job and Registry concurrency
 -> Event Store v2
 -> system performance baseline
 -> shadow global control
 -> Root Linux L2
 -> Android L3
 -> physical L4
 -> fault L5
 -> optional release L6
```

## 5. PR sequence for P0–P3

Recommended narrow integration sequence:

1. `DOC-G1` — this document reset and machine truth.
2. `MOD-G1` — generated module manifests and path ownership gates.
3. `PERF-G1` — workload harness, measurements and baseline artifact schema.
4. `BROKER-MUX-V2` — bounded multi-inflight protocol and implementation.
5. `JOB-ADMISSION-V2` — capacity tokens and per-key start state machine.
6. `REGISTRY-SHARD-V1` — stable shard function and contention tests.
7. `EVENT-STORE-V2` — segmented WAL, indexes, snapshots and migration.
8. `TURN-CANCEL-V2` — event-driven cancellation and bounded spooling.
9. `CONTROL-SHADOW-V1` — observe/shadow controller and lease protocol.
10. `CONTROL-CANARY-V1` — limited active coordination after evidence.

Each PR must preserve the exact Effect and evidence hard constraints.

## 6. Decision gates

A phase may advance only when:

- every dependency phase has reached its declared state;
- source and generated documents agree;
- relevant module owners approve;
- compatibility and migration are explicit;
- the system objective does not regress outside approved budgets;
- exact-head CI and required target evidence are retained;
- negative claims remain explicit.

## 7. Things explicitly not authorized

G1 does not authorize:

- direct merge to protected trunk;
- replacement of Codex by a mechanical planner;
- automatic replay after uncertain effect;
- increasing concurrency without bounded capacity and correlation proof;
- performance claims without workload and artifact identity;
- source-only promotion of installed, image, device, fault or release gaps.
