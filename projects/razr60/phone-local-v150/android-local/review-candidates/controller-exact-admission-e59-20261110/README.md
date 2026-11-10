# Exact-token admission: independent alternative candidate

This is a review candidate for the fixed v29 controller source. It has host regression evidence and has not been installed or tested on a phone by this review. The production patch changes only `LocalTaskController.java` and adds `ControllerPromptAdmission.java`.

## Problem and behavior

For exact-tokenizer profiles, the existing Java score is a UTF-8 sizing heuristic, not an actual token count or a proven upper bound. The controller could reject a complete task before the native tokenizer was allowed to evaluate it.

This candidate keeps the heuristic for the original optional-observation reductions: first optional visible text, then nonessential nodes. After those reductions are exhausted, a bounded exact-tokenizer profile may submit the irreducible prompt for native adjudication. OWNER, complete recorded history, the current app page, and required action targets are retained. The controller checks the same submission boundary again in `awaitModel`.

The original `ConservativeTokenBudget.admitted` field remains unchanged. A deferred request may honestly record `admitted=false`, `controller_submission_allowed=true`, and `native_exact_admission_deferred=true`. These fields do not authorize generation or an action. Native exact admission and bound output are still required. The per-text 65536-byte limit, Unicode/NUL checks, output cap, reserve, original LFM3 byte-bound path, one-shot engine, and image engines are unchanged.

## Relationship to the separate v30 implementation

The existing [v30 implementation at ec9b4106](https://github.com/TrillionniumFoundation/trillionnium-os/commit/ec9b4106bf0d4d46267831c14f1102090a3137f6) uses `mayAttemptNative = admitted || exactTokenizationRequired` at both controller gates and sends the bounded observation without first using this heuristic to remove optional content. This comparison was checked by the coordinating reviewer; the host results in this capsule qualify only the exact alternative source pair listed in `BASELINE.json`.

The alternatives have a real tradeoff. This candidate's earlier optional reductions can remove business readings that would help the model, even when exact tokenization would have allowed them. The separate v30 path keeps more observed information, which can also produce a genuine native context overflow. Both retain the engine byte bounds and native exact-token gate. These host tests establish neither superiority nor phone-task success for either implementation, and do not validate the separate v30 build or justify a duplicate deployment.

## Native boundary retained

The fixed generated worker has SHA256 `b2276da3b7066d1da2a48097c58681e6f3b37bb786660c5bb7dc680b03910d0f`. Its lines 395–423 enforce rendered-byte validity, call exact admission, capture the private input evidence, verify unchanged model identity, reset the warm model, and then pass the same counted input IDs to generation. Failure goes to cleanup.

`native/model-runtime.inc` lines 62–82 measure the fully rendered prompt with the fixed vocabulary, require the exact budget, tokenize again, and reject count mismatch or invalid IDs. `native/prompt-budget.h` lines 45–51 require positive token count and `actual prompt tokens + maximum output + reserve 256 <= context`. Each warm request repeats this gate; a failed request terminates the session. The fixed SDK API uses the supplied IDs without adding independent special tokens. Model creation occurs before token admission, so this is not a preparation-latency guarantee.

`LocalModelEngine` independently enforces each input's 65536-byte/Unicode boundary, disallows images in this text path, and requires a valid native receipt. `NativeBudgetVerifier` requires the fixed model/tokenizer, context/output/reserve, direct-ID proof, ID digest, and agreement with the SDK prompt count. Artifact identities are recorded in `BASELINE.json`.

## Reproducible host evidence

The tests patch contains all five new test sources; they are not duplicated as separate files in this capsule. `HOST-RESULTS.json` and `HOST-OUTPUT.txt` are from the public synthetic regression. It passed:

- Baseline reproduction in the extracted production `prompt()` and `awaitModel()` methods.
- The patched production methods, with an explicitly synthetic OWNER, 12 complete history rows, 24 required targets, optional reductions, unchanged submitted bytes, diagnostic fields, Unicode/NUL/byte limits, and native-rejection propagation.
- Policy boundaries and the real `NativeBudgetVerifier`, including size fixtures `(system bytes, prompt bytes, prompt tokens) = (3593, 2523, 1945)` and `(3593, 2499, 2061)`. Their native totals are 2457 and 2573, while their heuristic scores are 4084 and 4072. No private prompt is included.
- The unchanged original LFM3 byte-budget regression in both source variants.
- Six scenarios through the actual unchanged generated native worker: the two synthetic size fixtures; exact 3584-token boundary for context 4096/output 256/reserve 256; first-request 3585-token overflow with **zero generation calls**; second warm request overflow with only the first generation called; second tokenization count mismatch with zero generation calls; and the original one-shot lifecycle.

The Java fixture extracts production method bodies. JSON containers, Rect/clock, and the inference callback are explicit host adapters. The C tests execute production admission/control flow, same-ID dispatch, receipts and cleanup, with an explicit fake SDK and controlled tokenizer. They do not run a model or an accelerator. The host compiler uses Java source/target 8 against the host API, not a release-8 or Android API-compatibility build. These limits are preserved in `VALIDATION.json`.

An independent reviewer checked the exact native guard chain, the two Java gates, the small policy, and current/R5 consumers. The consumers do not use the heuristic step-budget flag as native authorization. They still require successful native admission/output binding; no native call or a refused call cannot become a qualified PASS through the new diagnostic fields. This was a read-only review, not an independent rerun of the tests.

## Apply and run

From an isolated copy of the exact controller baseline in `BASELINE.json`:

```sh
git apply --check /path/to/controller-exact-admission.patch
git apply /path/to/controller-exact-admission.patch
git apply /path/to/controller-exact-admission-tests.patch
python3 tests/controller-exact-budget/run_host_tests.py \
  --baseline /path/to/unmodified-baseline \
  --candidate /path/to/patched-controller \
  --out /path/to/new-host-results
```

The runner pins the baseline and candidate controller hashes and the new policy hash. It also requires the generated worker hash above. It rejects a different implementation, including the separate v30 alternative. Use the existing project native fixtures and C/Java toolchains; the test command does not install dependencies, contact a phone, or call a model service.

## Publication scope

This capsule contains patches, synthetic tests/results, and source/validation hashes only. No device identifiers, original task/request identifiers, real phone instructions, screenshots, UI dumps, private prompts, or raw phone acceptance files are included. Original phone results and the original private host evidence remain unchanged and are not republished here. Increasing context to 8192 is a separate configuration experiment, not this source fix.
