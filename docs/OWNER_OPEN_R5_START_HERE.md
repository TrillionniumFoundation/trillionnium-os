# Owner-open R5: start here

Status: **ACTIVE ENTRY — plan revision `2026-08-29-r6`**  
Semantic baseline: `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`, revision `2026-08-27-r3`  
Implementation baseline: `codex/owner-open-r5-tool-loop-20260827@479e5fb78385d3706b42f83b334025fa2b6ccd50`  
Implementation evidence: **HOST_TESTED / L1**  
Documentation candidate: `codex/owner-open-r5-gap-closure-20260829`  
Documentation candidate evidence: **L0 until exact-head CI succeeds**  
Public release: **false**

R3 remains the product-semantic authority: Codex/provider is the only semantic
principal. R5 r6 is the only active implementation sequencing and gap-closure
plan. Broker, transport, core, runtime, stores and supervisors own mechanical
identity, resource, process, transport, persistence and recovery behavior only.

## Read in this order

1. `TRILLIONNIUM_CANONICAL_DEVELOPMENT_PLAN.md`
2. `TRILLIONNIUM_OWNER_OPEN_R5_EXECUTION_PLAN.md`
3. `status/owner-open-r5-gap-closure.json`
4. `architecture/2026-08-29-owner-open-runtime-authority-and-process-topology.md`
5. `protocols/owner-open-effect-state-machine-v1.md`
6. `operations/owner-open-deployment-lifecycle-and-emergency-stop.md`
7. `qualification/owner-open-evidence-promotion-and-fault-matrix.md`
8. `status/owner-open-r5-status.json`
9. `status/owner-open-r5-traceability.tsv`
10. `contracts/owner-open-forbidden-default-graph-v2.json`
11. `protocols/owner-open-direct-agent-host-v1.md`
12. `protocols/owner-open-provider-jsonl-v1.md`
13. `protocols/owner-open-event-store-v1.md`
14. `protocols/owner-open-inspect-v1.md`
15. `protocols/owner-open-stream-flow-v1.md`
16. `protocols/owner-open-jobs-v1.md`
17. `protocols/owner-open-codex-mcp-jobs-v1.md`
18. `protocols/owner-open-multi-connection-broker-v1.md`
19. `protocols/owner-open-installed-codex-mcp-qualification-v1.md`
20. `security/owner-open-threat-model.md`

Documents under `plan/`, earlier R4 plans and previous batch checkpoints are
provenance. They cannot override the r6 plan or machine gap register.

## Current product path

```text
AiShell / owner clients / local Codex MCP
  -> one final product entrypoint                       [not yet selected]
  -> optional same-trust-domain broker                  [source L1; P0 gaps open]
  -> bounded v5 transport carrier                       [source L1]
  -> job-aware v7 execution core                        [source L1]
  -> installed provider/Codex semantic turn             [L2 hold]
  -> direct shell / ordinary adb / durable shell.job
  -> raw observation returned to the same turn
  -> provider continues
  -> exactly one turn terminal
```

“One semantic principal” does not mean one operating-system process. It means
only the provider/Codex may interpret intent, select target/tool/command,
decide retry/compensation and interpret observations. No mechanism component
may rewrite argv, inject ADB routing, select another provider or automatically
redispatch an uncertain effect.

## Exact known L1 baseline

The current implementation baseline is exact commit:

```text
479e5fb78385d3706b42f83b334025fa2b6ccd50
```

Its permanent GitHub Actions runs include:

```text
owner-open R5 tool loop      run 33244626387  success
owner-open foundation        run 33244626392  success
```

The R5 tool-loop run executed locked Rust 1.93 metadata, formatting,
`cargo test --locked --all-targets`, strict Clippy, generated-code and graph
gates, broker tests, Codex MCP tests and installed-Codex lifecycle fixtures.

This proves an exact-checkout source/host baseline only. It does not prove:

```text
installed target Root Linux Codex
provider authentication
Root Linux UID/GID/namespace/cgroup placement
clean Android image or target-files
physical shell/job/ADB effect
crash/ENOSPC/USB-loss/reboot/power-loss qualification
signed public release
```

The claim ceiling remains:

```text
EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX
```

## Repository P0/P1 blocker chain

The r6 gap register makes these source blockers load-bearing:

| Gap | Issue | Required result |
| --- | ---: | --- |
| `R5-GAP-GOVERNANCE-001` | #20 | exact-head generated evidence, coherent PR chain, protected main |
| `R5-GAP-JOB-ADMISSION-001` | #14 | reserve capacity before spawn; total rollback |
| `R5-GAP-PROCESS-LIFECYCLE-001` | #15 | reader-before-stdin, parent/descendant cleanup truth |
| `R5-GAP-STREAM-RECOVERY-001` | #16 | `job.output` bounded flow and exact cursor gaps |
| `R5-GAP-JOURNAL-CONVERGENCE-001` | #17 | explicit degraded durable states; no dropped critical errors |
| `R5-GAP-BROKER-CORRELATION-001` | #18 | exact request identity, three-stage broker audit, total startup cleanup |
| `R5-GAP-PRODUCT-ENTRYPOINT-001` | #19 | one installable product entrypoint and manifest |

A source PR may move one of these to
`SOURCE_CLOSED_PENDING_EVIDENCE`. It cannot close a higher environment exit by
editing status.

## External evidence lanes

These remain real-environment holds:

| Lane | Issues | Exit |
| --- | --- | --- |
| Installed Codex | #10, #13 | L2 |
| Root Linux placement | #4, #13 | L2 |
| Android graph/image | #2, #13 | L3 |
| Physical ordinary ADB | #5, #8, #13 | L4 |
| Destructive fault matrix | #6, #13 | L5 |
| Signed public release | #13 | L6 |

Missing target binaries, credentials, Android build outputs, physical devices,
signing authority or independently controlled fault infrastructure are evidence
holds. They are not permission to synthesize a pass.

## Development order

```text
A. enforce repository/document/evidence truth
B. close job/process/flow/journal/broker/product-entrypoint source blockers
C. install and qualify target Root Linux + real Codex
D. build clean Android image and execute physical shell/job/ADB
E. execute crash/storage/USB/reboot/power-loss matrix
F. separately authorize a signed L6 release
```

Do not begin a dependent promotion while an earlier load-bearing blocker is
open.

## Effect and recovery rule

Every effect follows the unified protocol:

```text
received
-> validated
-> capacity_reserved
-> accepted_durable
-> effect_attempted
-> started_or_forwarded_durable
-> observations
-> terminal_observed
-> terminal_durable
-> delivery_attempted
```

After an effect attempt, disconnect, timeout, journal failure or restart may be
uncertain. The result is inspected/reconciled; it is never automatically
redispatched.

Client EOF and backpressure detach delivery. They do not imply cancellation.
A capacity rejection may claim no-start only when it occurred before spawn or
upstream write.

## Zero-gap rule

`zero_gap=true` is legal only when every entry in
`status/owner-open-r5-gap-closure.json` is `CLOSED` with exact evidence at or
above its declared exit level.

Fixtures never close installed Codex, target placement, image, physical-device,
fault or release lanes. `public_release` remains false until the L6 release gap
is independently closed and a human go/no-go authorization is recorded.

## Exact-source L1 checkpoint (2026-08-29)

Start with the [exact-source closure evidence](status/owner-open-r5-source-closure-evidence-2026-08-29.md),
then read the [machine gap register](status/owner-open-r5-gap-closure.json) and
[current status](status/owner-open-r5-status.json). Source closure must not be confused with
installed, image, physical, destructive-fault, governance or release evidence.
