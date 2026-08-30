# Owner-Open R5 exact-source-head L1 closure evidence

Status: **A source lifecycle race was repaired after the prior L1 checkpoint; the new exact head is under permanent-workflow qualification. Target, device, destructive-fault and release evidence remains open.**

## Previous immutable L1 checkpoint

| Field | Value |
| --- | --- |
| Repository | `TrillionniumFoundation/trillionnium-os` |
| Branch | `codex/owner-open-r5-gap-closure-20260829` |
| Source commit | `c8790b6b5d0e59dff74f527db1d1173d4a2fb043` |
| Source tree | `02cb419638a7e163c0eb957e6b6e95bb4df54609` |
| Permanent workflow | `L1 owner-open R5 source and gap closure` |
| Workflow run | `33282230585` |
| Result | `L1_SOURCE_CLOSURE_PASSED` |
| Claim ceiling | `EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX` |
| Cargo.lock SHA-256 | `a469d72776978b143f47ba71904325404dc77307b25374214e6dd321147b99a0` |

The permanent workflow checked out the pull-request source head rather than GitHub's synthetic merge
commit. That exact source checkout passed graph and document verification, gap/evidence mutation tests,
Broker and MCP process fixtures, locked Rust 1.93 formatting/tests/strict Clippy, product-entrypoint
source checks, release-path mechanics, ADB relay checks and the foundation suite.

## Previous bound artifacts

| Artifact ID | Name | SHA-256 digest |
| --- | --- | --- |
| `9723329897` | `owner-open-r5-l1-graph-docs-python-c8790b6b5d0e59dff74f527db1d1173d4a2fb043` | `sha256:9d8d2703377e9c93d9299eb4d7696e9d489238cb20b7bbe78301ba241833384d` |
| `9723329308` | `owner-open-r5-l1-rust-c8790b6b5d0e59dff74f527db1d1173d4a2fb043` | `sha256:ddb01b3d5c1e15f5ef9a190346935faa2020100f8c7be12254276d821416bf0a` |
| `9723331596` | `owner-open-r5-l1-candidate-c8790b6b5d0e59dff74f527db1d1173d4a2fb043` | `sha256:159b9ea0465a32ff7e5b60a0f3345ce7c81663d9f7157bfe19343c72f2b45b72` |

## Durable restart race closure

A later exact-head run exposed a real lifecycle race in
`completed_durable_job_never_spawns_again_after_manager_restart`: an already durable terminal could be
reported as `UnknownAfterRestart` when a second in-process manager opened the journal while the old
dispatcher still held the exclusive writer lease.

The repaired implementation removes a redundant post-publication `record_job_terminal` call. The
canonical terminal observation and `job.terminal` record remain atomically appended by
`push_runtime_event` before the terminal becomes visible. The regression now explicitly waits only for
the old dispatcher to release the same-process writer lease, then still proves that the recovered
terminal is present and the command is not spawned a second time.

| Field | Value |
| --- | --- |
| Repair commit | `50e33e3643501fae4f2ce2107ac5bf15f0bbb3ab` |
| Repair tree | `33fc14f3a18a09a0bfe4baa95d1294ba5bd74f58` |
| One-shot validation run | `33283826378` |
| Validation | 50 exact regression repetitions, all workspace tests, strict Clippy, all canonical R5 verifiers and all Python tests passed |
| One-shot control plane | transient patch workflow and helper self-deleted in the repair commit |

This repair changes executable source. Therefore the previous `c8790b6…` source qualification cannot
be inherited. The current human-authored head must pass the permanent pull-request workflows and then
be atomically rebound as the new exact-source identity before any canonical L1 claim is current again.
No L2-L6 claim is promoted by this repair or by this provenance update.

## Source identity versus promotion head

An immutable qualified source identity is distinct from a later state-only promotion head. A promotion
head may update `docs/status/` or import independently reviewed evidence without changing executable
source. It must pass its own repository checks and may not inherit qualification after any source,
Cargo, contract, tool or workflow drift.

The previous checked-in source-evidence promotion was commit
`00348cecc1507c76c8dc87fac306c25e3418c984`, tree
`32368956b98437789d9368207e629d383465562e`, from one-shot run `33283248195`. That run completed its
bind, canonical verifiers, 96 regression tests, diff-boundary check and bot commit, then removed the
transient write-capable workflow.

External evidence bundles must bind their `source_commit` and `source_tree` to the current qualified
exact pair. The promotion script rejects a bundle whose source identity differs from the machine gap
register.

## Gap transitions

- `R5-GAP-JOB-ADMISSION-001` remains **CLOSED at L1** only after the repaired exact head earns a new
  permanent L1 checkpoint: finite capacity is reserved before spawn, conflicting concurrency cannot
  oversubscribe it, and post-spawn cleanup is bounded and tested.
- Process lifecycle, stream recovery, journal convergence, Broker correlation and product entrypoint
  remain **SOURCE_CLOSED_PENDING_EVIDENCE** after new L1 qualification. Their declared L2-L5
  installed/environment evidence still does not exist.
- Repository governance remains **EXTERNAL_HOLD** because protected-main required checks and an
  independent current-head review are repository-administrator and reviewer actions, not source
  artifacts.
- Installed Codex, Root Linux placement, Android image, physical ADB, destructive faults and public
  release remain **EXTERNAL_HOLD** with their exact required material or authority listed in the
  machine gap register.

## Non-claims

This evidence does not prove installation, target UID/GID or namespace placement, Android image
inclusion, physical effects, destructive recovery qualification, signed release, protected-main
configuration or zero-gap completion. `zero_gap=false`, `public_release=false` and
`automatic_redispatch=false` remain mandatory.
