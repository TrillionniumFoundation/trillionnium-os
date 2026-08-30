# Owner-Open R5 exact-source-head L1 closure evidence

Status: **Repaired exact source passed all permanent L1 and repository workflows; target, device, destructive-fault and release evidence remains open.**

## Current exact source identity

| Field | Value |
| --- | --- |
| Repository | `TrillionniumFoundation/trillionnium-os` |
| Branch | `codex/owner-open-r5-gap-closure-20260829` |
| Source commit | `ae2335814b61fc3c5a472d3a207fdb876f9e620c` |
| Source tree | `7e098821b947716cc96c77581259c5422b8b8654` |
| Permanent workflow | `L1 owner-open R5 source and gap closure` |
| Workflow run | `33283935102` |
| Result | `L1_SOURCE_CLOSURE_PASSED` |
| All permanent PR workflows | `16/16 success` |
| Claim ceiling | `EXACT_COMMIT_SOURCE_GATES_PASSED_NOT_INSTALLED_CODEX` |
| Cargo.lock SHA-256 | `a469d72776978b143f47ba71904325404dc77307b25374214e6dd321147b99a0` |

The permanent workflow checked out the pull-request source head rather than GitHub's synthetic merge
commit. The exact source passed graph/document verification, gap/evidence mutation tests, Broker and MCP
fixtures, locked Rust 1.93 formatting/tests/strict Clippy, product-entrypoint checks, release mechanics,
ADB relay checks, Android source-profile checks, Root-Linux packaging checks and the foundation suite.

## Bound artifacts

| Artifact ID | Name | SHA-256 digest |
| --- | --- | --- |
| `9723810264` | `owner-open-r5-l1-graph-docs-python-ae2335814b61fc3c5a472d3a207fdb876f9e620c` | `sha256:0176d8753ea6bed28a585e0d46004dd19bde2852335292e2394fad820b9fb62f` |
| `9723815400` | `owner-open-r5-l1-rust-ae2335814b61fc3c5a472d3a207fdb876f9e620c` | `sha256:e2844b373ad2613012099b64a43b77a13281363d61b953843b1e5dccab15f88f` |
| `9723817403` | `owner-open-r5-l1-candidate-ae2335814b61fc3c5a472d3a207fdb876f9e620c` | `sha256:8b86b72774b3281829eb3c6ae4cf4d352965bca2957ad0f12962a7cbe7d89ba4` |

## Durable restart race closure

A previous exact-head run exposed an intermittent same-process writer-lease handoff race in
`completed_durable_job_never_spawns_again_after_manager_restart`. The implementation removes the
redundant post-publication terminal write; the canonical terminal observation and `job.terminal` record
remain atomically durable before terminal visibility. The regression waits only for the old dispatcher
to release its writer lease and still proves the recovered terminal prevents a second spawn.

Repair commit `50e33e3643501fae4f2ce2107ac5bf15f0bbb3ab` was validated by one-shot run `33283826378` with 50
exact regression repetitions, all workspace tests, strict Clippy, all canonical R5 verifiers and all
Python tests. The repaired human-authored exact head above then passed all sixteen permanent PR
workflows, so no historical L1 result is inherited.

## Source identity versus promotion head

`ae2335814b61fc3c5a472d3a207fdb876f9e620c` / `7e098821b947716cc96c77581259c5422b8b8654` is the immutable qualified source identity. A later state-only
promotion commit may update machine status or import independently reviewed evidence without changing
that source pair. It must pass its own repository checks and may not inherit qualification after source,
Cargo, contract, tool or workflow drift.

External evidence bundles must bind their `source_commit` and `source_tree` to this exact pair. The
promotion script rejects a bundle whose source identity differs from the machine gap register.

## Gap transitions

- `R5-GAP-JOB-ADMISSION-001` is **CLOSED at L1**.
- Process lifecycle, stream recovery, journal convergence, Broker correlation and product entrypoint
  are **SOURCE_CLOSED_PENDING_EVIDENCE** and retain their declared L2-L5 exits.
- Repository governance is **EXTERNAL_HOLD** until protected-main enforcement and an independent
  current-head approval exist.
- Installed Codex, Root Linux placement, Android image, physical ADB, destructive faults and public
  release remain **EXTERNAL_HOLD** until their real target or authority evidence exists.

## Non-claims

This evidence does not prove installation, target UID/GID or namespace placement, Android image
inclusion, physical effects, destructive recovery qualification, signed release, protected-main
configuration or zero-gap completion. `zero_gap=false`, `public_release=false` and
`automatic_redispatch=false` remain mandatory.
