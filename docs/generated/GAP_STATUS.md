# Gap Status

<!-- GENERATED. DO NOT EDIT. -->

- Total: `21`
- OPEN: `7`
- SOURCE_CLOSED_PENDING_EVIDENCE: `6`
- EXTERNAL_HOLD: `7`
- CLOSED: `1`

| Gap | Priority | Class | Status | Exit | Modules | Summary |
| --- | --- | --- | --- | --- | --- | --- |
| `GAP-ANDROID-GRAPH-001` | `P0` | `integration` | `EXTERNAL_HOLD` | `L3` | MOD-ANDROID, MOD-ROOTLINUX | Build a clean Android graph with selected owner-open components and no legacy semantic nodes. |
| `GAP-BROKER-CORRELATION-001` | `P0` | `correctness` | `SOURCE_CLOSED_PENDING_EVIDENCE` | `L2` | MOD-BROKER, MOD-TRANSPORT | Bind accepted, forwarded and terminal records to exact request ownership. |
| `GAP-CONC-BROKER-MUX-001` | `P0` | `concurrency` | `OPEN` | `L2` | MOD-BROKER, MOD-TRANSPORT | Replace the single active effect request with bounded multi-inflight multiplexing. |
| `GAP-CONC-EVENT-STORE-001` | `P0` | `concurrency` | `OPEN` | `L2` | MOD-EVENT-STORE | Replace the single-file single-lock write hotspot with indexed segmented durability. |
| `GAP-CONC-JOB-START-HOTLOCK-001` | `P0` | `concurrency` | `OPEN` | `L2` | MOD-JOB-RUNTIME | Remove the global running-map lock from spawn and durability slow paths. |
| `GAP-DOC-SINGLE-TRUTH-001` | `P0` | `governance` | `SOURCE_CLOSED_PENDING_EVIDENCE` | `L1` | MOD-EVIDENCE | One machine truth must generate every current-state and traceability view. |
| `GAP-FAULT-MATRIX-001` | `P0` | `qualification` | `EXTERNAL_HOLD` | `L5` | MOD-EVIDENCE, MOD-BROKER, MOD-TRANSPORT, MOD-JOB-RUNTIME, MOD-EVENT-STORE, MOD-ADB | Execute destructive crash, storage, disconnect, USB, reboot and power-loss cuts. |
| `GAP-GOVERNANCE-001` | `P0` | `governance` | `EXTERNAL_HOLD` | `L1` | MOD-EVIDENCE | Protected integration must bind exact-head checks and a non-author approval. |
| `GAP-INSTALLED-CODEX-001` | `P0` | `integration` | `EXTERNAL_HOLD` | `L2` | MOD-PROVIDER, MOD-ROOTLINUX | Qualify exact installed Codex bytes, identity and same-turn tool callbacks. |
| `GAP-JOB-ADMISSION-001` | `P0` | `correctness` | `CLOSED` | `L1` | MOD-JOB-RUNTIME | Reserve finite capacity before spawn and converge every post-spawn failure. |
| `GAP-JOURNAL-CONVERGENCE-001` | `P0` | `correctness` | `SOURCE_CLOSED_PENDING_EVIDENCE` | `L5` | MOD-EVENT-STORE, MOD-JOB-RUNTIME | Prove storage failure and corruption converge without false no-start claims. |
| `GAP-PERF-SYSTEM-BASELINE-001` | `P0` | `performance` | `OPEN` | `L2` | MOD-TELEMETRY, MOD-GLOBAL-CONTROL, MOD-BROKER, MOD-JOB-RUNTIME, MOD-EVENT-STORE | Establish repeatable mixed-workload throughput, latency, resource and recovery baselines. |
| `GAP-PHYSICAL-ADB-001` | `P0` | `integration` | `EXTERNAL_HOLD` | `L4` | MOD-ADB, MOD-ANDROID | Prove ordinary ADB and visible effects on an authorized physical device. |
| `GAP-PROCESS-LIFECYCLE-001` | `P0` | `correctness` | `SOURCE_CLOSED_PENDING_EVIDENCE` | `L2` | MOD-TOOL-RUNTIME, MOD-JOB-RUNTIME, MOD-PROVIDER | Prove parent-death, reader-before-writer and descendant cleanup on installed target. |
| `GAP-PRODUCT-ENTRYPOINT-001` | `P0` | `integration` | `SOURCE_CLOSED_PENDING_EVIDENCE` | `L3` | MOD-TRANSPORT, MOD-EXECUTION-CORE, MOD-ROOTLINUX, MOD-ANDROID | One install manifest must select the product entrypoint and internal children. |
| `GAP-ROOTLINUX-PLACEMENT-001` | `P0` | `integration` | `EXTERNAL_HOLD` | `L2` | MOD-ROOTLINUX | Bind installed UID, GID, namespaces, cgroups, mounts, stores and restart policy. |
| `GAP-STREAM-RECOVERY-001` | `P0` | `correctness` | `SOURCE_CLOSED_PENDING_EVIDENCE` | `L2` | MOD-STREAM, MOD-TRANSPORT, MOD-JOB-RUNTIME | Prove bounded output, exact cursor gaps and target reconnect behavior. |
| `GAP-CONC-REGISTRY-001` | `P1` | `concurrency` | `OPEN` | `L2` | MOD-EXECUTION-CORE, MOD-JOB-RUNTIME | Shard call and job registries without weakening per-key ordering. |
| `GAP-CONC-TURN-CANCEL-001` | `P1` | `concurrency` | `OPEN` | `L2` | MOD-TURN-ENGINE, MOD-PROVIDER | Replace per-tool polling threads with event-driven cancellation and bounded event storage. |
| `GAP-CONTROL-PLANE-SHADOW-001` | `P1` | `architecture` | `OPEN` | `L2` | MOD-GLOBAL-CONTROL, MOD-TELEMETRY | Implement the mechanical global controller in observe and shadow modes before active control. |
| `GAP-RELEASE-001` | `P2` | `release` | `EXTERNAL_HOLD` | `L6` | MOD-EVIDENCE, MOD-ANDROID, MOD-ROOTLINUX | Bind signing, transparency, AVB, rollback, OTA, key custody and human release authorization. |
