# RAZR60 phone-local model — r7-r3 measured checkpoint

**The model runs locally on the phone. The new health request passed. Both new business tasks failed after a successful first application open and a rejected repeated-open proposal. The formal nineteen-case result is 7 PASS / 2 FAIL / 10 BLOCKED; daily-use qualification remains unestablished.**

This checkpoint records the installed `v150-r7-r3` combination. Its three narrowly scoped Binder/file-descriptor permissions were applied with SELinux enforcing and independently audited. Both real business requests then completed their first authorized application open with exit code 0 and a verified target foreground/display. On the second model round, each request proposed opening the same application again. The original no-replay gate rejected that proposal before a second native dispatch. The complete tasks remain failed.

Read the [full quality and resource report](qualification/r7-r3-checkpoint/README.md), [machine-readable result](qualification/r7-r3-checkpoint/QUALITY-PUBLIC.json), and [report provenance](qualification/r7-r3-checkpoint/PROVENANCE.json). The [r7-r2 checkpoint](qualification/r7-r2-checkpoint/README.md) and its [previous top-level README](qualification/history/README-as-published-86c0424.md) remain preserved. Future continuation/history, cancellation and additional application-route candidates are outside this measured combination.

## What runs on the phone

The phone uses GUI-Owl-1.5-2B-Instruct Q4_K_M with its Q8 vision projector, a pinned Android ARM64 llama.cpp runtime, the existing HEPTA native turn/tool journal, and dedicated executor and worker SELinux domains. Inference uses the phone CPU. The combination has no cloud-model fallback or automatic action retry.

The thirteen r7 production Python sources, model, executor, native runtime and budgets are unchanged in r7-r3. The provider accepts a constrained named `mobile_use` JSON projection and preserves the original typed tools, coordinate constraints, identity checks, receipts and business postconditions. This deterministic projection is informed by the official mobile action vocabulary; it does not claim literal cookbook XML/action output. Original responses, model objects, mapping records and mapped decisions remain separate evidence. The mapping-aware collector recomputes the projection from the frozen source and checks the original native and executor records. Model prose is not evidence that an action occurred.

The separate health path keeps the expected nonce answer unconstrained by nonce-specific grammar. Its exact fresh response, one local HTTP request, zero tools, native terminal and cleanup were independently checked.

| Bound | Unchanged limit |
| --- | ---: |
| Phone tools per task | 7 |
| Model rounds per task | 8 |
| Task time | 300 seconds |
| One model HTTP request | 120 seconds |
| Generated tokens per round | 256 |
| Prompt bytes | 24,576 |
| Model context | 4,096 tokens |
| Model execution | 4 CPU threads, 1 slot |

## Current actual results

| Real request | Result | Model rounds / tool dispatches | Prompt / output / total tokens | Model HTTP time | Native persistence observation interval |
| --- | --- | ---: | ---: | ---: | --- |
| Health, auxiliary | PASS | 1 / 0 | 167 / 57 / 224 | 3.147297 s | 3.024657–4.224543 s |
| Visual, E2E-01 | FAIL | 2 / 1 | 2499 / 59 / 2558 | 24.354631 s | 25.544565–26.735961 s |
| Unicode, E2E-02 | FAIL | 2 / 1 | 3411 / 105 / 3516 | 34.236209 s | 35.574165–36.811718 s |

Each real request used one Send. There were **five actual phone-local model HTTP requests** across the three tasks. The two business tasks consumed **6,074 tokens**; health adds 224, for **6,298 tokens** overall. Cached tokens remain part of prompt usage and are not added again. Synthetic host responses do not count as model usage.

HTTP times are sums of original local-model receipt times. The native intervals bound observation of terminal persistence on one sender's monotonic clock. They are not exact event times, host job durations or successful-business completion latency.

### Successful first opens, failed complete tasks

The visual application open ended with executor exit 0 in 530 ms; its native tool lifecycle took 702 ms. The Unicode application open ended with executor exit 0 in 562 ms; its native lifecycle took 765 ms. Both had empty stderr, verified target Activity/foreground/display 0, an actual joined worker, absent process group and closed original receipt/ledger disposition.

The original second requests already contained the successful open observation, the prior “attempted once; do not replay” action entry and the unchanged owner message. The evidence therefore does not show dropped history. The original second-round schemas still offered the same open alias and a screenshot action. Both models selected the same open again; the no-replay rule rejected it before another dispatch.

These observations establish the failure stage. They do not establish that one prompt phrase, history salience or a particular internal model mechanism caused it. Later prompt/history or schema-mask candidates and their offline checks are excluded from this checkpoint.

Neither business task reached an image observation, screenshot grounding/tap, Unicode entry, public readback/receipt, or required return. A successful open alone does not satisfy the whole task's postconditions. Both original native tasks remain `provider_failed`, both business proofs remain false and the verified business-fact count is zero: **0/2 complete, 0/2 verified partial, 2/2 failed**.

All original HTTP workers were joined and slots observed idle. Both dispatched effects were confirmed terminal without replay. Three original drafts were privately compared and restored exactly without submission. Draft restoration is cleanup and does not count as a business return. Selected native checks cover health 3 records/2 adjacent links, visual 8/7 and Unicode 8/7; they do not attest unseen predecessors or the complete global chain.

## Fixed nineteen-case protocol

The formal protocol, per-case budgets and two-layer requirements are preserved. The twelve host/component samples were newly executed under this exact combination; previous-combination results were not relabelled.

| Whole-case status | Cases | Evidence boundary |
| --- | --- | --- |
| PASS — 7 | NEG-03, NEG-06, NEG-10, NEG-11, NEG-12, NEG-13, NEG-14 | Required isolated/component layer satisfied |
| FAIL — 2 | E2E-01, E2E-02 | Two real complete business tasks failed |
| BLOCKED — 5 | NEG-04, NEG-05, NEG-07, NEG-08, NEG-09 | Host layer passed; required physical native-task layer has no current sample |
| BLOCKED — 5 | E2E-03, E2E-04, COMP-01, NEG-01, NEG-02 | No current required sample |

There are **14 fixed-protocol samples**: eleven isolated host cases, one direct geometry component fixture and two real model business tasks. The one real health task is outside both the business-success and fixed-nineteen denominators. There are **462 runtime assertions plus 14 separate original-evidence/process-closure assertions**; these are not additional samples.

The geometry fixture does not qualify a real outer-screen or rotated configuration. Five successful isolated fault layers do not replace their required physical layers. Historical cancellation failures, including the earlier busy-slot result, remain historical and are not current samples. The [host-only interim report](qualification/r7-r3-host-checkpoint/README.md) retains its narrower 7 PASS / 0 FAIL / 12 BLOCKED cutoff; this full report supersedes its scope for the current global result.

## Measured resources and timing limits

Six bounded resource snapshots were taken around health, visual and Unicode. Each snapshot was tied to the same actual model/provider/executor identities and the current combination. The values below divide original kB counters by 1024 to display MiB.

| Snapshot | Model RSS (MiB) | Model lifetime HWM (MiB) | System MemAvailable (MiB) |
| --- | ---: | ---: | ---: |
| Before health | 3028.39 | 3048.59 | 7376.45 |
| After health | 3050.64 | 3070.14 | 7394.83 |
| Before visual | 3050.64 | 3070.14 | 7314.38 |
| After visual | 3081.25 | 3095.73 | 7355.74 |
| Before Unicode | 3081.25 | 3095.73 | 7295.34 |
| After Unicode | 3410.90 | 3427.97 | 7021.38 |

RSS snapshots ranged from **3028.39 to 3410.90 MiB**. Maximum observed lifetime HWM was **3427.97 MiB**, and minimum observed MemAvailable was **7021.38 MiB**. These measurements do not establish a continuous peak or stability under other workloads.

| Snapshot window | Observed elapsed interval | Model CPU increment | Provider CPU increment | Executor CPU increment |
| --- | --- | ---: | ---: | ---: |
| Health | 164.90–166.60 s | 12.23 s | 5.19 s | 0.05 s |
| Visual | 179.68–181.49 s | 95.93 s | 4.56 s | 0.05 s |
| Unicode | 132.30–134.14 s | 134.40 s | 3.29 s | 0.04 s |

CPU increments use same-process user/system ticks and observed HZ=100; CPU seconds can accumulate across cores. These windows include idle time, UI orchestration and collection overhead, and omit already exited workers. They are not per-inference attribution.

Vendor battery capacity, temperature, current and voltage readings are retained in the public JSON with their raw-value qualifications. A `current_now=0` reading does not establish zero power. **Hardware energy and monetary cost remain null, not zero.**

## Three-atom policy change in this combination

The exact r7-r3 increment is:

```text
allow servicemanager trillionnium_owner_open_phone_worker binder transfer
allow system_server trillionnium_owner_open_phone_worker fd use
allow system_server trillionnium_owner_open_phone_worker fifo_file write
```

These permissions are type-wide; they are not limited by application name or one file descriptor. No additional reverse Binder call, FIFO getattr, new type, permissive domain or wider domain attribute was added.

The actual Magisk parser accepted both the delta over the prior live policy and the complete rule set over the original baseline. Their candidate binaries were byte-identical. Two offline audits passed 22 checks each, for 44; the actual live-policy audit passed 24. Offline and live policy serialization hashes differ, while the audited permission and other policy tables agree semantically. SELinux remained enforcing. The [policy summary](policy/r7-r3-ipc/POLICY-PUBLIC-SUMMARY.json) and [rule source](policy/r7-r3-ipc/display-ipc-three-atoms.original.rule) preserve the exact boundaries.

The current two successful opens show that their tested open paths passed the earlier display failure point. That observation does not establish all Android interfaces, a sole historical cause, or complete business qualification.

## Frozen provenance

The public combination omits the private instance-configuration digest and is explicitly not an executable deployment manifest. Its original full-manifest hashes remain provenance references.

| Artifact | SHA-256 |
| --- | --- |
| Original full combination | `e42e6cb00112be91ac9414b04786ad2693b86a9af413b8f90a0e0e42543c81d1` |
| Original canonical combination | `1cfbfcbd919bafed31af23750d448f38303a8ed86680e18b0718df5b0fb3d188` |
| r7 production source seal | `7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab` |
| r7-r3 module manifest | `7a3546dc4ff001920f1522d7fe194d5a5608c6e734544c944ca6357d7ad09570` |
| Current rules manifest | `bc6742c5652b6a705bcd4bcb40efc8b5e7a0eb256c4915bd5c2fa09a1611c418` |
| Complete rule source | `30f3963d10aa4c4eea70c31c8f80278490be3c16986fb029853b5bc217a4b6f8` |
| Current live policy snapshot | `bfe7acc92ba8c5b7a3a1c2360d6faf53f804a19c3e25e20aad336e3220fa0e38` |
| Actual live semantic audit | `e506ed914e40d48992e49e31ec1df874ae3eeb8815710bec261805f348aa20ae` |
| Formal nineteen-case protocol | `74e8f8e6c22ba6240ba85cb610cb46ff8a0f158a39375118385f5012a47efdfb` |
| Current public quality report | `27781648eb66e7cb6b9a36d9a5f37ef936dadd41ea7e23d86ed189cec5017d3f` |

## What this repository update contains

This increment includes explicit source projections for the r7-r3 module and its builders/operators, the current acceptance/support/collectors, resource sampler, the three policy atoms, newly executed host/component harness sources and safe measured reports. The r7 production source remains unchanged.

- [Module source and build/readback explanation](module/r7-r3/README-PUBLIC.md)
- [Acceptance and collection support](acceptance/r7-r3/README-PUBLIC.md)
- [Resource sampler source](operators/resources-r7-r3/README-PUBLIC.md)
- [Full current quality report](qualification/r7-r3-checkpoint/README.md)
- [Current combination projection](qualification/combinations/COMBINATION-v150-r7-r3.PUBLIC.json)
- [Increment source-to-public hash mapping](qualification/publication/PROJECTION-INDEX-v150-r7-r3-checkpoint.json)
- [Cumulative source projection index](PUBLIC-PROJECTION-INDEX.json)
- [Published project manifest](PUBLISH-MANIFEST.json)

Each entry records the original artifact hash, public artifact hash and whether bytes are exact, projected or generated. Public projections replace instance-specific paths, retained-claim/configuration digests and process bindings. They are deliberately not installable packages and were not substituted for the original source during tests. The private sealed archives and original measured evidence remain preserved; their publication hashes do not make their private contents public.

Original requests, nonces, user drafts or draft digests, credentials or credential digests, real scopes/action/process identities, raw native/claim histories, model weights and compiled policy binaries are excluded. No future continuation or cancellation source is part of this measured update.

Build/operator corrections are retained as versioned history. Root rejected the initial sealer and initial readiness paths during static review; corrected versions were used. A large installer was staged through a bounded compressed transfer, checked by full hash and executed once through the approved operator. The current quality builder's first preflight rejected one inherited combination filename before any aggregator execution; a one-line successor then ran the sole final aggregate. None of these host/report corrections count as model samples or business successes.

## Remaining qualification

The five physical fault layers, E2E-03/E2E-04, COMP-01 and NEG-01/NEG-02 still require their original evidence under unchanged limits. Visual and Unicode require fresh complete tasks on a separately frozen candidate if a correction is adopted; old tasks and effects must not be replayed.

A trustworthy daily-use claim also needs repeated representative business outcomes and measured latency/resource behavior. This checkpoint establishes phone-local inference, a fresh bounded health pass, two successful individual application opens and the preserved failures of the two complete business requests.
