# Owner-open evidence promotion and fault-matrix contract

Status: **ACTIVE**  
Plan revision: `2026-08-29-r6`  
Machine gap register: `../status/owner-open-r5-gap-closure.json`

## 1. Purpose

This contract defines what evidence is sufficient to move an owner-open gap
between L0 and L6. It prevents source tests, fixture workflows and aspirational
workflow names from being treated as installed, image, physical, fault or
release proof.

## 2. Evidence object

Every evidence package contains one canonical manifest:

```json
{
  "schema": "org.trillionnium.owner-open.evidence.v1",
  "plan_revision": "2026-08-29-r6",
  "gap_ids": [],
  "evidence_level": "L1",
  "result": "pass",
  "repository": "TrillionniumFoundation/trillionnium-os",
  "branch": "",
  "commit_sha": "",
  "tree_sha": "",
  "dirty": false,
  "inputs": {},
  "commands": [],
  "observations": {},
  "artifacts": [],
  "negative_claims": [],
  "review": {}
}
```

Required global fields:

```text
source commit and tree
Cargo.lock digest
toolchain identities
workflow, run, attempt and job identities
start/end timestamps
command argv and environment allowlist
test counts, skips and expected external-material holds
artifact filename, bytes and SHA-256
claim ceiling
negative claims
reviewer/approval state
```

Evidence with a missing, stale or contradictory field fails closed.

## 3. Checked-in status versus generated evidence

Checked-in status expresses:

```text
allowed vocabulary
known historical baseline
open gap policy
claim ceiling
required evidence
```

It does not prove that the current HEAD passed.

Exact-head evidence is generated inside a permanent workflow from the checkout.
The workflow manifest records `GITHUB_SHA` and the Git tree observed after
checkout. A status promotion references that immutable evidence; it does not
copy a green result from another commit.

## 4. Promotion ladder

### L0 — contract and source shape

Required:

- documents and JSON parse;
- source/graph verifier passes;
- forbidden marker and dependency checks;
- generated constants/schemas are fresh;
- mutation tests prove the verifier fails on drift.

Not sufficient:

- authored Rust/Python tests;
- compiled host process;
- fake provider/adb;
- historical evidence.

### L1 — exact-checkout source and host tests

Required:

- exact commit/tree and clean checkout;
- locked dependency metadata;
- formatting;
- all selected tests;
- strict lint/Clippy;
- process/fixture integration;
- fault injection available inside hosted CI;
- bounded artifacts with hashes.

L1 closes only repository source portions. It cannot close environment exits.

### L2 — installed target Root Linux

Required:

- installed product entrypoint and internal/provider executable hashes;
- exact launch argv/config;
- UID/GID/home, namespaces, cgroup and mount ancestry;
- socket, descriptor/token and store identity;
- installed Codex help/version/capability bytes;
- cryptographic release identity verification before execution;
- authenticated same-turn provider/MCP trace;
- direct shell and real pipe/PTY job;
- restart/reconnect and no hidden retry;
- emergency-stop lifecycle observation.

A local Ubuntu runner that executes unpacked binaries outside the target
placement is not L2.

### L3 — clean Android image

Required:

- exact repo manifest, project heads and patch series;
- clean source assertion;
- Soong/module graph;
- product package inventory;
- init service/socket/property graph;
- SELinux domains, allow rules and file contexts;
- target-files and image hashes;
- installed product manifest matches L2 artifact identities;
- forbidden legacy nodes absent.

A source overlay, generated makefile or static verifier alone is not L3.

### L4 — physical normal path

Required:

- authorized device serial/fingerprint/boot ID;
- image and installed manifest identities;
- physical transport identity;
- AiShell/client connection;
- installed Codex authenticated turn;
- direct Root Linux shell;
- pipe and PTY job controls;
- ordinary ADB `devices`, explicit selected-device operation, deliberate
  failure and visible mutation;
- raw output and final continuation;
- normal emergency stop and explicit recovery.

A fake `adb`, emulator-only effect or local shell is not L4 unless the relevant
gap explicitly defines an emulator exit, which R5 currently does not.

### L5 — destructive fault and recovery

Required fault families:

```text
provider crash
execution core crash
transport crash
broker crash
MCP/client disconnect
job leader/descendant failure
output backpressure
journal ENOSPC/fsync/torn/corrupt record
USB loss
adb-server loss
device reboot
power loss or closest independently controlled equivalent
emergency stop during fault
```

Each cut binds:

```text
precondition
durable record immediately before cut
fault injection method
observed process/transport/device result
post-restart reconciliation
redispatch count
cleanup result
last durable and next cursor
negative claims
```

L5 requires no automatic redispatch and truthful uncertainty.

### L6 — public release

Required:

- exact release source and reproducible artifact identities;
- cryptographic artifact signature verification;
- certificate chain and signer/OIDC identity policy;
- transparency-log inclusion and signed-entry verification;
- AVB, rollback indexes and anti-rollback;
- OTA install/rollback/recovery;
- key custody, rotation, revocation and break-glass review;
- multi-user, lock-screen and data-erasure review;
- legal/commercial/operations/security approvals where applicable;
- explicit human go/no-go authorization.

No workflow may set `public_release=true` by inference.

## 5. Artifact authenticity

Structural cross-binding is useful but is not cryptographic authenticity.

Before L2 execution of downloaded provider artifacts, verify at least:

```text
release metadata identity
archive SHA-256
unique executable-member SHA-256
published checksum-list binding
signature over the exact selected object
certificate chain
expected issuer and subject identity
certificate validity at signing time
transparency-log entry and signed-entry proof
```

The exact policy and trust roots are versioned. A verifier that reports
`cryptographic_signature_verified=false` cannot satisfy this gate.

## 6. Fault matrix

### 6.1 Turn/provider cuts

| Cut | Expected |
| --- | --- |
| before provider spawn | one spawn-failed terminal |
| after provider spawn, before start record | uncertain or reconciled; no retry |
| provider protocol error | one provider-failed terminal |
| provider process-group SIGKILL | terminal/unknown plus bounded cleanup |
| turn.cancel during tool | targeted cancel and exactly one turn terminal |
| delivery EPIPE | provider/effect continues; inspect/replay truth |

### 6.2 Direct call/job cuts

| Cut | Expected |
| --- | --- |
| capacity full | rejection before spawn |
| after spawn before registry commit | guard kills/reaps; truthful terminal |
| child writes before reading stdin | no parent/child pipe deadlock |
| leader exits with descendant | group cleanup or cleanup uncertainty |
| output limit | group termination and terminal |
| operation accepted, Host crash | no automatic operation repeat |
| terminal durable, delivery lost | exact terminal replay |

### 6.3 Broker cuts

| Cut | Expected |
| --- | --- |
| accepted audit fails | zero upstream write |
| write/flush ambiguous | broker uncertain and hold |
| forwarded audit fails | no new effect forwarding |
| delayed same-kind response | cannot satisfy another request |
| owner disconnect | upstream continues; result custody becomes inspectable/undeliverable truth |
| startup bind/descriptor failure | upstream group is terminated/reaped |

### 6.4 Store cuts

| Cut | Expected |
| --- | --- |
| ENOSPC before accepted | fail closed before effect |
| ENOSPC after effect | degraded/unknown, never not-started |
| truncated tail | typed torn-tail recovery or quarantine |
| mid-log corruption | fail/quarantine, no silent truncate |
| writer lock contention | unavailable state, no second writer |
| capacity/retention exhausted | explicit resync/cleanup policy |
| reboot during fsync | conservative reopen and chain validation |

### 6.5 ADB/device cuts

| Cut | Expected |
| --- | --- |
| unauthorized | raw adb result |
| offline | raw adb result |
| multiple devices | raw adb result unless Codex explicitly supplied selection |
| USB unplug before dispatch | spawn/transport result proving no effect where possible |
| USB unplug after dispatch | terminal or unknown; no retry |
| adb-server restart | inspection/reconciliation |
| device reboot | turn/job/ADB uncertainty preserved |
| recovery/bootloader | raw target-specific result |

## 7. Evidence review

An evidence package is accepted only after:

1. schema and hashes validate;
2. source/tree/lock and installed artifacts match;
3. commands and environment are reviewable;
4. expected skips are enumerated and do not cover the claimed requirement;
5. raw logs support the summarized result;
6. negative claims remain explicit;
7. an independent reviewer accepts the evidence boundary for L3–L6.

The implementer may review L0/L1 mechanics, but product/release promotion must
not rely solely on self-approval.

## 8. Workflow naming

Permanent workflow and job names include the evidence level:

```text
L1 owner-open source closure
L2 installed Root Linux Codex qualification
L3 Android target-files qualification
L4 physical device normal path
L5 owner-open destructive fault matrix
L6 signed public release
```

Names such as `physical`, `release-candidate` or `qualified` are prohibited for
jobs that only run source fixtures.

## 9. Retention and reproducibility

Evidence retention records:

```text
artifact expiration
immutable external retention location
reproduction instructions
required secrets/material
whether the environment remains available
```

An expired ephemeral artifact cannot remain the sole basis for a permanent
release claim.

## 10. Gap closure

A gap moves:

```text
OPEN
  -> SOURCE_CLOSED_PENDING_EVIDENCE
  -> CLOSED
```

or remains `EXTERNAL_HOLD` until required material exists.

The verifier rejects:

- duplicate gap IDs;
- a closed gap without evidence at its exit level;
- an external gap closed by fixture evidence;
- `zero_gap=true` while any gap is not closed;
- `public_release=true` while the release gap is not closed;
- evidence bound to a different source/tree/artifact;
- skipped, cancelled, empty or failed workflow conclusions.

## 11. Current claim ceiling

The known implementation baseline at
`479e5fb78385d3706b42f83b334025fa2b6ccd50` is L1 and has claim ceiling:

```text
EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX
```

This document does not promote that baseline or the documentation candidate to
L2–L6.
