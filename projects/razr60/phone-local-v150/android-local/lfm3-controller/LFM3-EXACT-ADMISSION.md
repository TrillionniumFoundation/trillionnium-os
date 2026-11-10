# LFM3 exact token admission

## Reproduced failure

The original standalone correction was reviewed on parent
`ec9b4106bf0d4d46267831c14f1102090a3137f6`. Code 34 integrates that correction
onto `e07c6624b7309b0acf3fe10e31b0605a29e3e72d`, retaining its scoped tools,
app-label grammar, Orvena sampler and Nanbeige profile. It does not change the
current controller prompt or merge a different recurrence candidate.

The standalone parent's controller system message contained **3,593 UTF-8 bytes**.
The LFM3 Java admission path adds 512 template units, two BOS/EOS units,
256 generation tokens and 256 reserve tokens. Even an empty user prompt
therefore requires a conservative bound of **4,619**, above the accepted
4,096-context configuration. No normal controller task can reach inference
under that configuration. At 8,192 the same gate leaves only 3,573 bytes for
the complete user prompt, including observation, apps, ordered history and
the owner's instruction. A valid upper bound can still refuse prompts that
fit the real tokenizer. The e07c controller system message retained by code 34
contains **3,794 UTF-8 bytes**, so its corresponding empty-user bound is
**4,820**. The regression extracts that current production text and checks
the current value; neither byte count is a measured LFM3 token count.

## Correction

The Java, native and host registries now set LFM3's existing
`exactTokenizationRequired` / `exact_tokens` / `exact` field to true. This
selects the same existing path already used by the other registered models:

1. Verify the complete pinned GGUF and hold its descriptor.
2. Apply that model's chat template once with thinking disabled.
3. Count and tokenize the rendered prompt with `add_special=true` and
   `parse_special=true` using the pinned vocabulary-only model.
4. Admit only when the exact input count plus the requested output plus
   256 reserve tokens fits the selected 4,096 or 8,192 context.
5. Pass that exact allocated ID array into `geniex_llm_generate`, with no
   alternate prompt-text path or additional special-token insertion.
6. Export the same IDs as little-endian int32 values, bind their SHA-256 and
   count, and require the SDK consumed-prompt count to match in the Java
   and host receipt validators.

The historical byte-bound helper remains in source for existing diagnostic
tests, but no registered profile selects it. Missing exact evidence cannot
fall back to that method. Legacy v1 configuration still selects LFM3; it now
requires the exact receipt too. Profile IDs, model hashes, available-memory
thresholds, context choices and the factory default are unchanged.

The 65,536-byte per-input limit, malformed Unicode/NUL rejection and
262,144-byte rendered-prompt limit remain enforced. The host validator now
also checks that same rendered-byte ceiling explicitly. Full-file integrity,
held-descriptor fences, grammar binding, accelerator selection and task-owned
reset/exit rules remain in force. No tool protocol, sampler, output budget,
controller action policy, runtime binary or saved device configuration changes.

## Meaningful regression coverage

`tests/exact-admission/PromptAdmissionHostTest.java` extracts the real
production system message, prompt builder, pre-native guard and engine text
validation. Its synthetic 30-node observation retains all action targets,
readouts, six ordered history entries and unchanged owner text. The LFM3 case
reproduces the old impossible floor and reaches native admission on this
candidate. Synthetic receipts separately test exact fit, one-token overflow,
missing proof, consumed-count mismatch, historical-receipt rejection and byte
caps. These receipt numbers are fixtures, not measured LFM3 token counts.

`native/tests/test_warm_runtime.py` compiles and executes the actual generated
worker against explicit SDK/tokenizer doubles. Eleven cases check one-shot
and repeated warm requests, reset consistency, byte-for-byte equality of the
counted/generated/exported ID array and its SHA, exact fit, overflow,
second-pass tokenizer disagreement, rendered-byte overflow and existing
lifecycle failures. Rejection cases assert no generation on the refused
request. This does not execute a neural model or accelerator.

The existing parser, grammar, profile, consumer, native publication, reset,
recovery and process-lifetime suites remain required. Test results and source
hashes are retained in the separate host-check report for the exact candidate.

## Required device qualification

Host checks do not establish real LFM3 tokenization, Android ABI correctness,
model output, accelerator execution, performance or phone task success.
Before adoption, use the pinned real artifact and runtime to compare a
short unchanged rendered prompt through the former prompt-text API and the
new direct-ID path. Verify the actual IDs/count/SHA and deterministic output,
then exercise repeated warm requests and a genuine over-context request.
Run ordinary Hepta entry at both explicit context sizes with offline tool tasks
and independent final phone-state predicates.

Code 34 is a separately identified integration candidate. Historical source
manifests and host evidence remain historical. The generated actual compiler
input asset, signed APK identity and fresh device qualification must bind the
new build before adoption; host fixtures do not qualify phone behavior.
