> Rendering note (2026-11-04): The [previously published bytes](README-as-published-86c0424.raw.txt)
> remain unchanged. This display copy adds this note and rebases navigation
> links from the former project-root location to this history directory.
> Historical results and qualification statements are unchanged.

# RAZR60 phone-local model — r7-r2 measured checkpoint

**The model runs locally on the phone. The new health request passed. Both new phone business tasks failed. The formal nineteen-case result is 7 PASS / 2 FAIL / 10 BLOCKED; daily-use qualification remains unestablished.**

This checkpoint records the installed v150-r7-r2 combination. Both real business requests reached one authorized Android application operation, whose original worker exited with code 68 and reported “Can't find service: display”. The original tasks, effects and drafts have been independently closed without replay. The actual policy change in this combination is limited to four servicemanager-property file-read permissions. It does not establish that service discovery or the full business flows now work.

Read the [complete quality and resource report](../r7-r2-checkpoint/README.md), [machine-readable result](../r7-r2-checkpoint/QUALITY-SUMMARY.json) and [report provenance](../r7-r2-checkpoint/PROVENANCE.json). The former [r7-r1 checkpoint](../r7-r1-checkpoint/README.md) remains unchanged. Subsequent policy candidates are outside this measured combination.

## What is running on the phone

The phone uses GUI-Owl-1.5-2B-Instruct Q4_K_M with its Q8 vision projector, a pinned Android ARM64 llama.cpp runtime, the existing HEPTA native turn/tool ledger, and the dedicated r6 executor/worker SELinux domains. Inference uses the phone CPU. No cloud model fallback or automatic retry is enabled.

The thirteen r7 production Python sources, model, executor, native runtime and budgets are unchanged in r7-r2. The provider accepts a constrained named mobile_use JSON projection and retains the original typed tools and postconditions. This is a deterministic transport projection informed by the official mobile action vocabulary; it is not a claim of literal cookbook XML/action output. Original model responses, model objects, mapping records and mapped decisions remain separate evidence. The collector recomputes each mapping from the pinned source and checks the original native and executor records. Model prose never proves an action occurred.

The separate health path leaves the expected answer unconstrained by nonce-specific grammar. Its exact fresh response, one local HTTP request, zero tools, native terminal and cleanup were checked independently.

## Current actual results

| Real request | Result | Prompt / output / total tokens | Model HTTP time | Native persistence observation interval | Phone effect |
| --- | --- | ---: | ---: | --- | --- |
| Health, auxiliary | PASS | 172 / 58 / 230 | 3.226108 s | 3.011533–4.206784 s | No phone tools |
| Visual, E2E-01 | FAIL | 1123 / 28 / 1151 | 12.103802 s | 12.765552–13.952773 s | One open_app; worker exit 68 after 65 ms |
| Unicode, E2E-02 | FAIL | 1569 / 32 / 1601 | 15.310555 s | 15.720707–16.872234 s | One open_app; worker exit 68 after 52 ms |

Each real request used one model HTTP round and one Send. The two business requests consumed **2,752 tokens**; health adds 230, for 2,982 across the three requests. Cached tokens are part of prompt usage and are not added again. Synthetic host responses do not count as model usage.

HTTP times come from original local-model receipts. The native intervals use one sender's monotonic clock and bound the observation of persistence; they are not exact event times, remote host job durations or the time to complete a successful business flow.

Both model business actions were legal named open operations. Both workers reached the effect entry, then ended with nonzero exit 68. The executor's state “completed” means its child process ended; it does not mean the command or business task succeeded. Each original child was joined, its process group was absent, and its original receipt and ledger disposition were closed without redispatch.

Neither task reached a usable screenshot, visual grounding/tap, Unicode text entry, public text readback, submission or required return. Both original native tasks remain provider_failed, both business proofs remain false, and the independently verified business fact count is zero. The result is **0/2 complete, 0/2 verified partial, 2/2 failed**. Exact restoration of the original drafts without submission is cleanup, not business return.

The visible error is that the original worker could not find the Android display service. This checkpoint does not infer a particular missing Binder permission from that text or claim zero effects merely because the operation failed. Further diagnosis and any later correction require their own version and measurements.

## Fixed nineteen-case qualification

| Evidence group | Current samples | Meaning |
| --- | ---: | --- |
| Real model business | 2 | Both failed: E2E-01 and E2E-02 |
| Host-isolated negative cases | 11 | Their expected rejection, timeout, cancellation or uncertainty conditions passed |
| Direct geometry component | 1 | NEG-03 rejection conditions passed; no real display/fold qualification |
| Total fixed-set samples | 14 | 2 + 11 + 1; not fourteen passing cases |
| Auxiliary health | 1 | Passed; excluded from business success rate and the fixed nineteen |
| Physical negative-task layer | 0 | Still missing for five dual-layer cases |

The frozen aggregator returns **7 PASS / 2 FAIL / 10 BLOCKED**. NEG-03, NEG-06 and NEG-10 through NEG-14 are PASS. E2E-01 and E2E-02 are FAIL. NEG-04/05/07/08/09 passed their host layers but remain BLOCKED because their required physical-native layers have no current sample. E2E-03/E2E-04, COMP-01 and NEG-01/NEG-02 are also BLOCKED.

All twelve host/component samples were actually executed for this full combination. They comprise 462 runtime assertions and fourteen original-export/process-closure assertions. Assertions are not sample counts, and expected failure in a negative fixture is not model business success. See the [five host-fault report](../../acceptance/r7-r2/host-cancel-faults/REPORT-PUBLIC.json), [seven host/component summary](../../acceptance/r7-r2/host-negative/PUBLIC-SAFE-SUMMARY.json) and the full [case-by-layer table](../r7-r2-checkpoint/README.md).

The formal protocol retains all nineteen cases, original limits, geometry and dual-layer gates. Its published review copy and source relationship are under [acceptance/r7-r2](../../acceptance/r7-r2/README-PUBLIC.md). The older provider/r7/qa historical copy is not the current normative acceptance protocol. Projected files with private bindings removed are not executable qualification manifests.

## Policy, installation and preserved history

The r7-r2 policy adds only worker-to-servicemanager_prop file getattr, open, read and map. The actual installed live policy passed a 26-check semantic audit: exactly these four permission atoms were added, with no deletion, new type, or other checked table expansion. The offline candidate and actual kernel serialization differ in bytes but have the audited equivalent policy content. Enforcing remained enabled. See the [policy summary](../../policy/r7-r2-property/POLICY-PUBLIC-SUMMARY.json) and [rule projection](../../policy/r7-r2-property/README.md).

The prior r7-r1 module was retired before policy application. Its four original groups were independently absent twice, the original supervisor exit was retained, and both historical timed-out actions stayed in their original journal. The new module verified the existing production payload rather than replacing model/provider/executor bytes. Current business actions add two separately closed exit-68 records; none of the old actions was removed or replayed.

The first r7-r2 installer stopped before unpacking or starting a role because its GNU chroot could not read the Android SELinux path. A new operator preserved that failure and checked the exact failed output and absence of installed state. It used the existing host view through /proc/1/root/sys/fs/selinux, without mounting or relaxing permissions, and wrote a separate output directory. The sealed module and combination did not change.

The second installation and readiness observation had actual host, actor and phone exit statuses of zero. Readiness checked 89 startup originals, every one of the 67 module files, 65 sums, 44 payloads and the 22 retained provider/config/service files. Large previous evidence was hashed instead of repeatedly copied into readiness stdout. The following health and two business tasks were new requests under this installed combination.

The historical [r7-r1 measurements](../r7-r1-checkpoint/README.md) remain 1 health PASS and 2 business FAIL with property-read errors and roughly 60-second original tool timeouts. The older [r6-r2 stage02](../checkpoints/QUALITY-v150-r6-r2-stage02.json) remains 7 PASS / 3 FAIL / 9 BLOCKED, including its physical cancellation/slot-busy failure. Their original requests, actions and results were not assigned to r7-r2. The [previous main README](README-as-published-4f7f0886.md) is preserved exactly.

## Resources and evidence limits

Six bounded observations of the same live roles found model RSS of **3,100,508–3,282,128 kB**, or approximately **2.9569–3.1301 GiB**, and a lifetime high-water mark of **3,299,764 kB**, or **3.1469 GiB**. The lowest observed system MemAvailable was 7,359,732 kB. Linux-reported kB is interpreted as KiB for those conversions.

The samples are snapshots, not continuous per-request peaks. CPU differences span wider intervals that include UI, waiting, control and collection work; they are not exact inference cost. Battery vendor values, including current_now=0 and an unchanged percentage, do not establish zero power. Hardware energy and monetary cost remain **unmeasured/null**.

Health and the two business tasks independently verified 3, 7 and 7 selected native records, with 2, 6 and 6 observed adjacent predecessor links. These checks do not attest an unseen global journal chain. Original capture actor/phone exits, actual collector exits, source/mapping/receipt hashes, HTTP joins, idle slots and original draft restoration were independently checked. A collector process returning zero means the evidence program ran; the failed business classification and proof=false remain failures.

The final reporting process reread 373 inputs and executed the frozen aggregate once. An earlier report-preparation attempt failed on the wording of a clock-description label before creating aggregate output. Its original failure is retained; the revised report accepted the two exact labels used by the frozen sender while preserving the same timing and identity checks. No phone request, fixture or aggregate sample was replayed for reporting.

## Frozen identifiers

| Item | Original SHA-256 | Public reference |
| --- | --- | --- |
| Production source seal | 7c20af425fa88cf6fd90aa7b902bd7c5c0cb0f1d4e808ac26ddbd4445f61c4ab | provider/r7 |
| Provider | 8f57e86ec66e4588e2e6f43ea761f17e9ae02361791995ff2f5831a16e46dbe6 | provider/r7/source/provider_phone_local.py |
| Daily entry | 92122fcc8bf01511971075fce2ad94b628dadf2c0c342f0fb940e8b00c636ec3 | provider/r7/source/daily_phone_local.py |
| Module manifest | 1e32540cc2c60ae22bd64a024d0d9545bde50c682aab96c1dba29a3e0731aefd | module/r7-r2 review sources |
| Whole combination | ee2bba801325525f9fa910c2c613352b54c32cb71921f2e7a16d2f25205e94d4 | qualification/combinations/COMBINATION-v150-r7-r2.PUBLIC.json |
| Canonical combination | 1f4763e8bf56cf25392a944298d08e4284495b0b7f44b3edb77060a250b598c5 | Same combination projection |
| Formal protocol | a9f314c4f2b6a7f05cbe7cc129ffcecef709f1f00b01b2dc5d08b0b6360b64e4 | acceptance/r7-r2 review copy |
| Full policy source | e9ffb955ba3872d7b3c453729ef8b6e52b8679f86f05496d25a1b735f9bed7a2 | module/r7-r2/source/sepolicy.rule |
| Actual live policy | 439ebd30f0e003cc4b0f5c08cade8c59b922eedcd3a3302169323a7f0397f089 | policy/r7-r2-property summary; binary private |
| Actual semantic audit | 38761d1076ed1dca8bf01e245bf17d184b445af401f686b4c77421cd6db5f0a5 | policy/r7-r2-property summary |
| Mapping-aware collector | e5fc961d5cec94ab2e075c84dd5672b0d616863a616d59270d92cfd527dfddc7 | acceptance/r7-r2/business-collector review sources |
| Current public quality | 3e926af3685fdf0a8a4f8e813456be8da483cd112c566f8c9d45ee207e6ef64d | qualification/r7-r2-checkpoint/QUALITY-SUMMARY.json |

These original identifiers bind privately retained frozen artifacts. Public projections have their own hashes and are explicitly distinguished from those originals. The complete public file map is in [PUBLISH-MANIFEST.json](../../PUBLISH-MANIFEST.json); [PUBLIC-PROJECTION-INDEX.json](../../PUBLIC-PROJECTION-INDEX.json) and the [r7-r2 increment index](../publication/PROJECTION-INDEX-v150-r7-r2-checkpoint.json) record the source relationships.

## Capture and execution rules

The normal evidence workflow is **preview → capture (includes export) → collect**. The separate [workflow erratum](../../acceptance/r7/business-original-export/WORKFLOW-ERRATA.md) corrects the older four-phase README. A duplicate export refuses an existing archive. It does not justify a new task or another effect.

Every new task requires a fresh one-use contract and original native identity. The unresolved-action gate persists across tasks. A failed effect can be resolved only from its original receipt and supported disposition. Durable intent precedes dispatch; the fixed client and executor verify the peer, dedicated domains, UID/GID 2000 and no supplemental groups. Original exit, joined child and absent group are required terminal facts. Cleanup does not undo an Android action.

The unchanged limits are seven tools, eight rounds, 300 seconds per task, a 120-second model HTTP bound, 256 generated tokens per response and 24,576 prompt bytes. The model runtime retains 4,096 context tokens, four CPU threads and one slot. No extra retry, resolver, tool or budget was added.

## Public reproduction boundary and remaining work

The public tree contains exact generic sources and explicit review projections. Private workspace paths, retained-claim/configuration digests, boot/process bindings and prior operation references are removed or replaced with required placeholders. The index records each original SHA-256 and public byte hash. The projected modules and operators are **not installable packages**, and successful tests are attributed to the original pinned sources.

Model weights, runtime binaries, full compiled policies, deployment archives, private manifests, credentials and their hashes, raw requests/nonces/drafts or draft digests, claims and native/action histories are excluded. Included images are pinned synthetic host fixtures. Existing core reproduction records remain completed historical foundations; this increment does not claim an independent bitwise rebuild of HEPTA, the root filesystem or the complete phone image.

The next independently versioned repair must first be supported by actual policy/interface evidence, then qualified with a new health request and entirely fresh business materials. This checkpoint contains no later Binder-policy change. Complete the remaining physical fault layers and fixed cases before claiming daily use. Outer-display, rotation/fold transitions, representative repeated business reliability, cold boot and energy consumption remain unqualified.
