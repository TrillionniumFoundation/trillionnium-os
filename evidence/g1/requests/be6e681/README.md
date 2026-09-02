# G1 `be6e681` independent signing handoff

This ops branch is **not** the canonical implementation branch and is not evidence. It carries only a non-promotable request template and an exact repository-controlled artifact ledger for an independently administered signer.

## Immutable request identity

```text
repository          TrillionniumFoundation/trillionnium-os
pull request        34
base commit         4142fe2864f05ac2a35037b4b025f4f1f0a5d35f
base tree           ce143d2d6865622a75e88aee0878927fb1bebeb5
head commit         be6e681c02996ee8c0fd25c29943aad21c66292e
head tree           a686aa24b969557cb6b46d4477a3a03df1216a33
GitHub merge        91c28bd23a04537183d993b04a66b7a3b1209934
ordered merge       8ff66504ed9d19dc620c5bdf19025aede75b30a7
ordered merge tree  a686aa24b969557cb6b46d4477a3a03df1216a33
ordered parents     4142fe2864f05ac2a35037b4b025f4f1f0a5d35f, be6e681c02996ee8c0fd25c29943aad21c66292e
source run          33596149698 (attempt 3)
ordered run         33596149656 (attempt 2)
Android run         33596149688 (attempt 2)
evidence run        33596149679 (attempt 2)
```

Any base/head/ref/PR retarget, source movement or prospective-merge replacement invalidates the request.

## Exact repository-controlled packet

| Role | Artifact ID | GitHub artifact SHA-256 | Expiry (UTC) |
|---|---:|---|---|
| protected exact-head aggregate | `9834572132` | `11027c973971c78f666ed26e88026446a9dc3009ecb71dab695167cf0dede186` | `2026-10-02T06:33:54Z` |
| locked source graph | `9834561669` | `112c02cdfbf5dfdc83ab2d16420b00b6847efb8d982d006763d937019a558e90` | `2026-10-02T06:33:32Z` |
| deterministic ordered merge | `9834387463` | `acac9a78201f6d45c5c700a0414da710099a41d0f986e813d2a6aec311a2ca60` | `2026-10-02T06:27:05Z` |
| Android source matrix | `9834275640` | `9daf669b9040300db0df0bf4b3fecce0b1585c2d94aaa0b0fb86de793c4644f3` | `2026-10-02T06:22:49Z` |
| Android merge matrix | `9834295174` | `363a6ed4bb7eddd416ff7e93b0a23c2edeb1522326d1a5a909f8ab5a9c3650c4` | `2026-10-02T06:23:35Z` |
| evidence source report | `9834284626` | `67dfbc667bda9ab694d55d7bf99995a33bf7b62ec61d3112b098a9f3011e4f12` | `2026-10-02T06:23:10Z` |
| evidence merge report | `9834276975` | `61e79f5cb7701b1d7c7705f9e75570bacbed5eec5a8ddb64799c267e2b395edb` | `2026-10-02T06:22:52Z` |

The aggregate result is `L1_EXACT_PR_WORKFLOW_AGGREGATE_PASSED`. Its embedded report SHA-256 is `2d12e482a1eb11c88ef783662580ee259927298a0050c0bdb63c9f6091d04fce`. This table is discovery metadata only: the signer must query the live APIs, download every required ZIP and independently re-hash the bytes.

## Required independent procedure

1. Read the live PR object and confirm the exact tuple above.
2. Confirm a fresh eligible non-author approval whose review commit is exactly `be6e681c02996ee8c0fd25c29943aad21c66292e`. Do not inherit the stale `e790486…` approval. The PR author and current commit author/committer are ineligible for the current independence role.
3. Query the live workflow, job and artifact APIs for runs `33596149698`, `33596149656`, `33596149688` and `33596149679`; reject any replacement, rerun drift, failure, cancellation or missing required job.
4. Download the protected aggregate and all support artifacts using the exact live artifact IDs. Verify GitHub's artifact digest, independently SHA-256 the downloaded ZIP bytes, reject unsafe archive paths and reject duplicate JSON members.
5. Parse the ordered-merge receipt from run `33596149656` and require merge `8ff66504ed9d19dc620c5bdf19025aede75b30a7`, tree `a686aa24b969557cb6b46d4477a3a03df1216a33` and the ordered parent pair above.
6. Run the live verifier against the current PR/review/run/job/artifact objects and produce the complete v2 unsigned receipt.
7. Under a separately administered, currently valid and non-revoked trust root, sign the complete receipt outside this repository. Pin the receipt bytes and verification material out of band.
8. Run the offline verifier with exact subject, validity, revocation and role-separation checks. A successful verification may propose a non-mutating promotion; it must not silently edit machine truth.

## Prohibited shortcuts

- Do not sign this repository-controlled template.
- Do not treat a SHA-256 content hash as authorization.
- Do not infer the deterministic merge identity from the GitHub prospective merge object.
- Do not use a stale approval, stale run or old source/base artifact.
- Do not let the source author, PR author or repository workflow self-assert the independent signer role.
- Do not merge, deploy, promote, flash, perform destructive tests or release from this branch.

```text
fresh_exact_head_approval=false
signed=false
promotable=false
zero_gap=false
public_release=false
automatic_redispatch=false
```
