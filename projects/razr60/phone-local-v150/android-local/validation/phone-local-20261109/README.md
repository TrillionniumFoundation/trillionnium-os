# Phone-local qualification snapshot — 2026-11-09

**Reliable end-to-end phone operation is not yet accepted.** Local Hexagon
inference, real signed Android builds and exact-source CI are established.
The phone task results below retain failures and incomplete runs. The PR
remains a draft and does not select a universally reliable final model.

This is a versioned project evidence snapshot, not a current device-state
authority or activation into the G1 default product graph.

## Results and evidence

| APK | Configuration | Original task scope | Retained strict outcome |
|---|---|---|---|
| Code16 | Bolt E4B / NPU4096 | Original full nine | 6 pass / 3 fail |
| Code16 | Gemma E4B QAT / NPU4096 | Original full nine | 7 pass / 2 fail |
| Code17 | Gemma E4B QAT / NPU4096 | Original targeted four | 2 pass / 2 fail |
| Code17 | LFM3 QAD / NPU8192 | Original targeted four | 0 pass / 4 fail |
| Code18 | LFM3 QAD / NPU8192 | Same targeted four | 0 pass / 4 fail |
| Code19 | Gemma E4B QAT / NPU4096 | Same frozen full-nine plan started by another visible controller | 1 pass / 1 unknown / 7 not_run |

The Code19 controller lost its host connection. Host recovery records include
a reboot and twice-checked network restoration. The second phone task later
ended naturally with known cleanup, but that observation does not retroactively
complete or pass the interrupted original suite. Starting another controller
before ownership is coordinated would introduce competing phone control.
Ordinary Start, sustained work with the Activity in the background, Stop and
a new task after restart still require independent acceptance.

The Code16 pair is the completed same-version full-suite comparison. Different
versions, context sizes, generated actions and initial/thermal states must not
be combined into an equal-workload ranking.

- [Code16 Bolt and Gemma original safe summaries](../code16-model-comparison/README.md).
- [Code17 pair, independent audit and retained build history](../code17-build-and-qualification/README.md).
- [Code18 independent phone summary](../code18-build-and-qualification/phone-regressions/PUBLIC-SUMMARY.md)
  and [machine-readable safe data](../code18-build-and-qualification/phone-regressions/PUBLIC-SUMMARY.json).
- [Code19 build, bounded observation contracts and exact-source CI](../code19-build-and-qualification/README.md).
- [Chinese Hexagon/model/MoE research, revision v5](../code17-build-and-qualification/phone-regressions/RESEARCH.zh-CN.md).

## What the fixes establish

Code17 exposed current editable values and factual dispatched history. Its
long-history prompt budget could still delete current buttons and their
grammar choices. Code18 prioritizes current actionable nodes, compresses
factual transitions, records omissions and aligns allowed opens with the
resolved catalogue. Fresh LFM3 configurations now default to NPU8192;
existing explicit configurations are preserved.

The Code18 LFM3 rerun retained all relevant calculator choices but still
failed all four tasks. In the find-app case a separate 1024-byte recent-history
cap dropped explicit read-only call provenance: the actual two rows were
1047 bytes and the complete conservative context would still have fit 8192.
This is a demonstrated integration factor, not proof of the sole cause.
The failure is retained. Code19 changes the observation settling cap only
and does not fix that separate history issue.

Code19 lets the internal stability collector use at most the original
ten-second caller window. It does not extend the 480-second task deadline,
renew deadlines on reset, weaken the 200 ms stable-frame requirement,
change action ownership/freshness or replace model choices with scripted
answers.

## Source and build identity

The actual Code19 source commit is
`fdb7eca8d3a434c515da547365fcc47bb2f510d3`.
Its complete 866-member manifest has SHA256
`9817f2af3937a402b52176565233c763869495d203080deffd7e279f9f621b69`.
The same-signer APK is version 19 / `0.19.0-local-stable-observation`,
20,612,784 bytes, SHA256
`e9eb1d119c265e12402975bece2db450bd999436e41e64d62cb64cf315668782`.

This evidence addition does not alter that frozen source or create a new APK.
The successful source-build runs remain tied to their exact source commits.
New evidence-head and PR workflows are separately reported in the PR; an
earlier green run is not substituted for a newer failed or pending one.
[PR119's initial CI and bounded retry](PR119-INITIAL-CI.json) preserves the
TLC-download HTTP 504 failures independently of the earlier successful push CI.

All 16 Code19 native members match Code18. The device signer was preserved.
The APK does not declare INTERNET. Phone tests used a local model with retained
native/action bindings and temporarily disabled network preferences;
snapshots do not prove continuous whole-device packet absence.

## Public data boundary

The included phone files contain selected case labels/instructions, statistics,
limitations and content digests. Private UI/model text, task/request secrets,
device identifiers, screenshots, local host paths, installed-app inventories,
signing keys, model weights and APK binaries are not published. The broader
raw evidence remains separate, and unknown outcomes stay unknown.
