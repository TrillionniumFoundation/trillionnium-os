# Explicit local model profiles

Version 0.4.0 / code 4 introduced the explicit, closed artifact allowlist retained
by code 5. The original
LFM3 filename, bytes and SHA256 are unchanged. Its factory default is NPU / 8192; existing explicit configurations, including 4096 and other model selections, are not migrated. The original acceptance driver remains unchanged: LFM3 qualification supplies `--expected-context 8192` explicitly through its candidate plan.
No new Android permission is declared. The worker remains a private subprocess,
without a local HTTP server. Phone execution and model quality are not established
by the host checks in this source package.

| Profile | Pinned GGUF | Bytes | SHA256 |
|---|---|---:|---|
| `lfm3-1.7b-qad-q4_0` | `LFM3-1.7B-QAD-Q4_0.gguf` | 1049615680 | `43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452` |
| `minicpm5-2b-q4_k_m` | `MiniCPM5-2B-Q4_K_M.gguf` | 1561318368 | `ec2d5801640099e97d8d7e8003ad4d81f336e757811f03a26173dddf386602fd` |
| `spark-x2.6-4b-q4_k_m` | `Spark-X2.6-4B-Q4_K_M.gguf` | 3543441312 | `91cb2811aebb47ac916aa619d27d4cdd7f4143106b7917accb8ead4cd7f5cbd9` |

MiniCPM5 source: `openbmb/MiniCPM5-2B-GGUF` revision
`2079a22f3beaa4e306449978533478fe0522f4b3`. Spark source:
`XHToken/Spark-X2.6-4B-GGUF` revision
`9d716770ac7477776de5f891f70cdf98b003a5cd`.

The existing app-private `files/model/runtime-config.json` keeps its strict v1
four-field format for LFM3. To select a different profile, use this complete v2
object in a canonical, app-owned, single-link regular mode0600 file, then restart
the idle application process so its immutable configuration is reread:

```json
{
  "schema": "hepta.local-runtime.v2",
  "model_profile": "minicpm5-2b-q4_k_m",
  "compute": "npu",
  "context_tokens": 4096,
  "threads": 4
}
```

`compute` permits only `npu` or `gpu`; context permits only 4096 or 8192. There
is no arbitrary model path, CPU mode, automatic retry or alternate-model fallback.
The selected artifact must be under `files/model` with its exact original filename
and mode0600. Minimum available physical RAM is 3 GiB for LFM3/MiniCPM5 and 5 GiB
for Spark. These are admission thresholds, not measured peak-memory guarantees.

## Native identity and context admission

Java first verifies the selected artifact's full hash. Its existing process cache
is additionally keyed by profile. The worker independently rehashes the entire
GGUF on **every request**, checks filename, size, uid, mode, link count and
architecture, and holds the verified descriptor. Both tokenizer and inference
open `/proc/self/fd/N`, referring to that same inode. Metadata must remain unchanged
through generation. Rehashing costs time inside the unchanged 55-second controller
deadline; an overrun must remain a failure, not be relabeled a successful test.

The SDK is still GenieX 0.10.0 at
`071f609995470bdb0e0769ab964754adfaab7e47`. Its actual llama.cpp submodule is
`19cce6919992fdffd92e0ac152caaf1e2b8f254e`. The matching public headers and MIT
license are under `native/vendor/llama`; no opaque SDK handle layout is assumed.
The build links the same packaged `libllama.so` already validated by the official
runtime tarball hash. That exact source includes `llama`, `lfm3`, `spark2_5`
model constructors and the `minicpm5` tokenizer preprocessor.

LFM3 retains its original, artifact-specific rendered UTF-8 upper bound. Other
profiles cannot use that proof. For MiniCPM5 and Spark, a vocabulary-only model
performs `llama_tokenize(add_special=true, parse_special=true)` on the actual
rendered chat template. It allocates no neural inference context or weight tensors.
The identical token IDs, with their SHA256 over little-endian int32 values, are
passed directly into `geniex_llm_generate`; GenieX adds no special tokens to this
input path. Count + requested output + reserve256 must fit the selected context.
The SDK's consumed prompt-token count must equal the counted IDs in a successful
receipt. A failed exact tokenizer or admission never falls back to a byte estimate.

Java observation selection for the new profiles uses a clearly labeled sizing
heuristic (half UTF-8 bytes plus a formatting allowance); it is not a tokenizer
proof. The native exact admission is authoritative. An underestimate fails closed;
it does not truncate or change the owner's instruction and does not retry.

Chat templates receive `enable_thinking=false`. Controller history remains text
inside the prompt; native tool-call XML is not used. When the controller supplies
its observation-specific JSON GBNF, template-generated tool grammar is explicitly
disabled so it cannot replace or lazily trigger the controller grammar. The worker
requests temperature 0, top_k 1 and min_p 0. Pinned GenieX treats the zero-valued
temperature and min_p as defaults (0.8 and 0.05); top_k remains 1. These requested
and resolved values are distinct and do not reproduce the model authors' general
chat benchmark settings. Code 5 does not change the sampler.

NPU/GPU selection is checked before model creation and again in the app receipt.
CPU tokenization is intentional. This selection check does not claim every
operator executes on the accelerator; positive layer/buffer offload must still be
established from the native backend logs in phone acceptance.

## Controller change and test drivers

The system prompt now distinguishes candidate apps from the current window,
explains that opening an app can restore an old subpage or associated window,
and requires all ordered parts of the owner task before `done success`. Recent
history adds the actual target package, dispatched flag, clicked node label and
typed text excerpt (with a truncation flag), in real action order. Up to six recent
entries are projected subject to the selected context budget; omission counts
remain explicit. App ranking, action policy and independent success predicates
are unchanged.

Phone-suite candidate JSON accepts optional `model_profile`; an omitted field
retains the original strict LFM3/v1 contract. A supplied field requires the exact
matching v2 on-phone config and matching `model_sha256`. All existing suite API
signatures remain compatible. `phone_acceptance.py run` adds
`--expected-model-profile`; exact-profile collection checks the model identity,
input ID count/hash, context proof, raw output, grammar, UID and resolved device.
No driver selects a model, imports weights or changes runtime configuration itself.

Spark remains an optional candidate: source architecture support is verified;
actual file import, accelerator load, exact prompt count and successful phone tasks
remain separate gates. A matching model name alone establishes none of them.

## Code14 experimental Bolt qualification profile

`nemotron-3.5-bolt-e4b-q4_k_m` selects only the official
`Nemotron-3.5-Bolt-E4B-Q4_K_M.gguf`, 6,180,446,208 bytes, SHA-256
`c8af2b8aea10a690a1d9491db744a9446660173cb38fc489612b556615a69612`,
from `nvidia/NVIDIA-Nemotron-3.5-Bolt-E4B-4GB` revision
`1db54d5b12533ff1bcaa8e42cf4c667988a1f1be`. It is an explicit experimental
`gemma4` text candidate and must use the same full-file verification and exact
native input-ID accounting. It does not select a different artifact or inference
backend automatically, and does not authorize a vision projector.

Its available-RAM admission threshold is **8 GiB**, an engineering qualification
gate rather than a measured peak or RSS claim. Initial qualification plans use
**context 4096** only. E4B QAT remains at 7 GiB; the source's legacy default is
still LFM3. Installing this candidate does not rewrite a saved model configuration.
The official card specifies OpenMDW 1.1; no base-model license is inferred from
the architecture. See `docs/CODE14-WINDOWS.md` for the pinned source,
qualification boundaries and the independent controller changes.

## Code28 experimental mobile-agent profiles

| Profile | Source revision | Artifact | Bytes | SHA-256 |
|---|---|---|---:|---|
| bonsai2-9b-q2_0 | prism-ml/Ternary-Bonsai-2-9B-gguf at 82265ccc78ddaac4700286a35e9badcc32376dd9 | Ternary-Bonsai-2-9B-Q2_0.gguf | 2556640128 | 1f884aa56aacd2bbbb2e4b7abaead2b1102b74a9c75a23fc33dab916813a384d |
| orvena-4b-q4_k_m | mradermacher/Orvena-4B-GGUF at a2f0300d9c43ee0911610d791ec3bfd302aafa6c | Orvena-4B.Q4_K_M.gguf | 2783447904 | c5d6df6e9a0828fa3068dfc6f6ca2ff6c4d950adc7e60e4b7202ece61595aa57 |

Both candidates use qwen35 and exact same-input-ID token admission. The 256-token
output limit, 55-second one-shot deadline, private file checks, closed grammar,
controller prompt and explicit accelerator selection are unchanged. Installing
this candidate does not alter saved configuration. No projector or automatic
CPU/model fallback is admitted. RAM admission gates are 6 GiB for Bonsai and
5 GiB for Orvena; these are not measured peak-memory claims.

Bonsai is official Q2_0, not fork-only PQ2_0/PTQ1_0. The pinned llama.cpp source
includes Bonsai graph transforms, Q2_0 Hexagon kernels and Hadamard processing.
Source support does not qualify packaged binaries, SM8750 load, correct output,
or phone-task completion. Initial qualification selects NPU. Pinned OpenCL
does not advertise Q2_0 matrix multiplication.

Orvena's GGUF is a community conversion; official model source Orvena/Orvena-4B
is pinned at 050579754d478eab021b1b1ba063cfc809b95936. Its published 30-language
evaluation omits Chinese and cannot establish Chinese Android UI performance.
Verify each complete GGUF hash, byte count and actual header before import.
The CLI/inventory registry fix from local commit
99332dc7a94b837d2d2c000f85da47abbe675826 is included. Unknown profiles remain
rejected and existing model identities/order are retained. Host tests do not
establish inference or device qualification.

## Code29 task-local worker lifetime

Version 29 inherits the exact version 28 model identities and CLI registry. Its
controller can retain one model instance within one task, reset it before each
complete prompt and prove actual owned exit at task termination. The full
native weight hash is performed once per owned generation, with held-descriptor
metadata fences for every request. The one-shot diagnostic path still performs
its original per-request load and verification. Initial model-specific RAM
admission, exact token budgets, per-request deadlines, output bounds and
fallback rejection remain in force. See `CODE29-TASK-WORKER.md`; the lifecycle
change does not establish model quality, speed, or phone qualification.

## Experimental Nanbeige4.2 3B profile

`nanbeige4.2-3b-q4_k_m` selects only
`Nanbeige_Nanbeige4.2-3B-Q4_K_M.gguf`, **2684023968 bytes**, SHA-256
`b92d2e35c9876b0c4bc671996360204f4149d0546c23d5954d5eb3b106c81f24`,
from `bartowski/Nanbeige_Nanbeige4.2-3B-GGUF` revision
`210b0d6d6c1046044c7ea9d16c9ce3b5716ec2d2`. It is a community GGUF
conversion of `Nanbeige/Nanbeige4.2-3B` and uses the `nanbeige` architecture.
The full artifact and actual header must be verified before import; a source
registration or upstream LFS identity does not prove a completed download.

The first device qualification plan uses **NPU, context 4096, threads 4**.
The **6 GiB** available-memory gate is an initial admission margin, not a
measured peak. Existing explicit 4096/8192 configuration remains unchanged;
an 8192 experiment requires a separately recorded configuration and evidence.
No default model, saved configuration, version number, tokenizer, prompt,
tool grammar, worker lifecycle or accelerator fallback rule changes here.

The profile requires the existing full native file hash, exact architecture,
held-descriptor metadata fences and exact same-input-ID token proof before
generation. Every request still retains output/reserve and byte limits. The
new profile does not admit a projector, arbitrary model path or CPU fallback.
The installed runtime must still demonstrate real load and correct output
before any tool or phone-task qualification is claimed.

## LFM3-VL 2B observation profile and ordinary runtime selection

The closed `lfm3-vl-2b-qad-q4_0` candidate pairs two official files from
`LiquidAI/LFM3-VL-2B-GGUF` revision
`1add221a5ea6c047fcf1eaaf2d247939d7cf8849`:

| Asset | Exact file | Bytes | SHA-256 |
|---|---|---:|---|
| Language weights | `LFM3-VL-2B-QAD-Q4_0.gguf` | 1049615648 | `621c455376cb96a20891697deb9975c6fb47dd5ea98ed3ad1f3b7e8f24f0b1e6` |
| Vision encoder/projector | `mmproj-LFM3-VL-2B-F16.gguf` | 378996032 | `1d8e6e58eefc093e09d6332f081516e1ddbd5b35cfca7f35463fb270db230b1e` |

The private directory is `files/lfm3-vl-model`. The text LFM3 artifact differs in
both byte count and hash and cannot substitute for the VL language weights.
F16 is the single admitted projector for this profile; the Q8 projector is not
part of this qualification.

Ordinary **选择本地模型** now offers LFM3-VL with the explicit **仅观察** label.
The existing four text choices and GUI-Owl tools choice retain their order and
meaning. Saving the observation choice uses this exact configuration shape:

```json
{
  "schema": "hepta.local-runtime.v3",
  "model_profile": "lfm3-vl-2b-qad-q4_0",
  "compute": "npu",
  "context_tokens": 8192,
  "threads": 4,
  "visual_mode": "observe"
}
```

Settings verify the full language and correct F16 asset hashes before committing,
retain exact original bytes for restore, and reject changes while a task or
unknown cleanup still owns the runtime. The cached service controller captures a
new immutable runtime/delegate pair for each task. Saving a model does not run
inference. The default remains the original text LFM3 configuration.

LFM3-VL accepts only the HTP0 language / GPUOpenCL vision path, 8192 context and
four threads. Four GiB available memory is an admission margin, not a measured
peak. This does not claim that every operator executes on an accelerator.
The source's pinned llama.cpp commit
`19cce6919992fdffd92e0ac152caaf1e2b8f254e` includes LFM3-VL support; the new
separate Android worker is independently rebuilt against the unchanged pinned
SDK libraries. Full model files were verified on the host; this does not establish
ordinary-App load, device acceleration, quality or task completion.

The actual language GGUF records `lfm3`, tokenizer `gpt2` with preprocessor
`lfm2`, and a 12129-byte embedded template with SHA-256
`f45005c50cd2a97329722bf3a2dee9f16c04cdf825a589b280fb7e99e6827818`.
Its explicit `<|startoftext|>` is retained because `add_bos_token=false`.
The worker passes `enable_thinking=false`; the validated assistant suffix is
`<think></think>`. Input-owned role/tool strings are preserved as input text,
and the existing single current-frame media marker and exact chunk accounting
remain mandatory.

This profile's raw result stops before action parsing or dispatch. The existing
current-frame DecisionGrammar is still used for bounded model proposals; this
patch adds no trusted calendar coordinates or free-form observation-to-click
translation. It cannot certify a shopping order or flight task as complete.
Observation and action authority remain separate checks.

The existing canonical VLM result gate includes 318 original GUI cases, 52
LFM3-VL profile/config/result checks, five independent embedded-template renders
and the exact observation configuration fixture. The VLM adapter gate retains
its original lifecycle cases and adds real preflight refusals for missing or
mismatched LFM3-VL assets. The ordinary visual-settings gate retains its original
GUI settings cases and adds LFM3-VL observation selection, restore, per-task
routing and artifact admission cases. These host gates use explicit platform or
positive model-loading fixtures; they do not execute a phone model.
