# Hepta v48 build and qualification record

The exact candidate source is `588e79570b87417dbbc754ecec1ca4fc5a0012ba`
(`0.48.0-local-notes-recovery`). This evidence-only directory was added after
that build. It is not part of its 515-file source inventory and does not change
the source commit embedded in the signed APK.

## Result

The complete strict host gate, Android compilation, original-signature assembly,
and static acceptance passed. **v48 has not been installed or qualified on the
phone.** A live independent operator still held the actual kernel operation lock
at `2026-11-11T06:07:55Z`. Process start identity, boot identity, lock inode, and
owner metadata matched. There was no normal-close record. No other owner was
interrupted and no v48 phone operation was issued.

| Item | Actual result |
| --- | --- |
| Complete source | 515 files verified against Git blob readback |
| Android compiler inputs | 180, bound to the signed embedded build identity |
| Strict host checks | 98 top-level checks passed; Java 8 API release gate |
| Completion stages | Seven passed, including the new Notes recovery stage |
| Recovery default lane | 43 synthetic checks and nine grammar cases |
| Observation worker | 19 strict host cases passed |
| APK assembly | Passed with the existing original signer; no new key |
| Packaged native libraries | 17; arm64-v8a, including Hexagon v79 |
| Declared permissions | Empty, including no INTERNET declaration |
| Phone adapter preparation | Frozen against the actual v48 build artifacts |
| Public query preparation | Frozen on Pocket4 against the actual v48 core |
| v48 installation / native inference | Not attempted / not qualified |
| Notes business completion | Not qualified on v48 |
| Virtual display with simultaneous main-screen use | Not qualified on v48 |
| Flight / shopping business completion | Not qualified |

Nested checks are part of the complete gate, not additional top-level records.
The separate local replay of 12 retained failed-prefix inputs passed 117 checks
and nine grammar cases. Its continuation used synthetic IO; it is not another
phone task or another NPU measurement. Private note bodies and UI histories are
not included in this evidence directory.

## Exact artifacts

- APK: `/home/alex/hepta-local-1d83-20261111/v48-build-r1/out/hepta-local-0.48.0.apk`
- APK bytes: `20846418`
- APK SHA256: `970630c6cd891b9abc24767e08832a4f13a2c62f0b809b85c9a8a3be77b52085`
- Signer certificate SHA256: `202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5`
- Original assembly receipt SHA256: `993d297ac0f47c66a796eadfc18aff73c094c82937c948d0bcd68bf276ae5333`
- Frozen phone core MANIFEST SHA256: `32e2648c45045d2c5f5da9a00ae4104c6ede0709bb185fe4ec67d8274755b378`
- Frozen public query MANIFEST SHA256: `231612acd1aa001527a7b79b8b94da9e0b5a84ffc6a48a93e8ecba35af4b2575`

Raw stage, host, completion, observation, assembly, static acceptance and adapter
receipts retain their original bytes. Five integration evidence hashes bind the
new completion and observation results into the assembler and phone adapters.
`PACKAGE.json` is the earlier source-package receipt; its `built=false` field
records that packaging stage, rather than overriding the subsequent actual
assembly receipt. Likewise, freezer-generated `remote_executed=false` fields do
not claim a device entry ran: the freezer itself did run on Pocket4, while no
phone prepare/run entry ran. `QUALIFICATION-STATUS.json` makes this explicit.

## Retained phone baseline and configuration caveat

`retained-v46-lfm3-performance.json` analyzes the actual retained v46 LFM3 task,
not this v48 build. Twenty NPU requests completed in one worker generation.
Median native latency was 10.400 seconds, TTFT 5.749 seconds, prefill 955.63
tokens/s and decode 26.51 tokens/s. The Notes task itself failed at its 20-step
limit after the first create and 19 open actions. These timings do not establish
business success, a controlled model comparison or a thermal diagnosis.

The last synchronized phone state remains v46. A different operator subsequently
wrote `lfm2.5-8b-a1b-q4_0 / npu / 8192 / 4`; that configuration workflow failed
during accessibility restoration. A later record restored the prior authorized
service while preserving unrelated components. Neither record invoked the MoE
model. Do not assume LFM3 remains selected, and do not call MoE configured and
qualified because its configuration file changed.

The model and NPU review is in the candidate's
[`docs/LOCAL-MODELS-20261110.md`](../../docs/LOCAL-MODELS-20261110.md).
LFM3 is the measured local NPU baseline. Model selection still requires the same
business cases, installed APK, configuration and ordinary app UID. Orvena-4B
and LFM2.5-8B-A1B remain comparison candidates, not demonstrated winners.

## Remaining device work

After the existing operator normally releases its lock, acquire a new owner and
read the actual installed APK/signer/UID, runtime configuration, task terminal
and accessibility state. The prepared installer expects the known v46 APK; a
different current version requires reconciliation rather than bypassing the gate.
Install the same-signer v48 package while preserving app data, models and notes.

Run Notes through the ordinary visible Start entry, retaining actual native
receipts, binary input token IDs, dispatched actions, final UI and cleanup. Run
the background multiplication case with independent main-screen activity and
review both displays. The calculator result must come from the model's current
input/action chain. No host action may stand in for a model action.

The prepared public query adapters permit only `web.search`, `scroll`, `wait`
and `done`. Their completion provider is unavailable and their business
qualification remains false, including when query evidence checks pass. They
can record public search reading; they cannot qualify flight booking, shopping
Apps, orders or payment. No purchase or booking was performed.

Use a preparation output **directory** for `--preparation`, not its `RESULT.json`
path. Preserve failed, partial and unknown terminal results. New testing and
same-case model comparisons remain required before selecting a task default or
claiming full operation in the background.
