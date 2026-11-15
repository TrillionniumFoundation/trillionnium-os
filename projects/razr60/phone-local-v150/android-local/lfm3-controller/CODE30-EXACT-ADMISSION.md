# Code 30: native exact-token admission

## Problem and scope

Code 29 used the Java UTF-8 sizing projection as a hard limit both while
constructing the prompt and immediately before requesting inference. That
projection is not a proved token bound for profiles marked
`exactTokenizationRequired`. A complete prompt could therefore be refused
before the existing native same-input-ID tokenizer examined it.

One privately retained Code 29 Gemma 4 E4B request used a 3,593-byte system
message and a 4,724-byte user prompt (8,371 bytes after the native template).
Its Java projection was 5,185 tokens; the native receipt counted 2,879 input
tokens, plus 256 generated and 256 reserved tokens, totaling 3,391. The
request ran with an 8,192-token configuration. These counts demonstrate the
4,096-token prefilter's false refusal; they do not qualify this new APK or
replace a new 4,096-token phone test. Raw phone observations remain private
and are not test fixtures in this repository.

## Change

`ConservativeTokenBudget.mayAttemptNative()` separates a Java prefilter
decision from permission to attempt native admission. A refused Java
projection can proceed only for a profile that requires native exact
tokenization. Both controller entry points use this same decision.

For those exact-token profiles, the prompt builder preserves the complete
initially bounded current observation, the existing bounded visible-text
projection, every current actionable target, the current app page and all
ordered action facts. It no longer erases readouts or rejects mandatory
facts because the diagnostic byte projection is large. Original owner text,
system instructions, grammar generation and model profiles are unchanged.

The Java budget receipt retains the original `admitted` estimate, even
when false, and adds `java_admission_role` and
`may_attempt_native_admission`. Neither field claims native admission.
The LFM3 proved byte upper bound retains its original optional reduction
and hard-refusal behavior.

The existing native tokenizer and budget guard remain the admission
authority for exact profiles. Actual overflow fails before generation;
missing or inconsistent same-input-ID receipts cannot qualify model output.
No automatic replay, action retry, dispatch bypass or fallback is added.
The existing engine limit of 65,536 UTF-8 bytes per input and malformed
Unicode/NUL rejection remain enforced.

## Validation

`tools/test_exact_admission.py` compiles the exact production full prompt
builder, pre-native controller guard and engine text validation with
explicit Android geometry / JSON serialization IO fixtures. All
observations are anonymous and synthetic. This test does not run a model,
a tokenizer, Android or a phone.

The regression covers a complete 30-node observation containing 13 action
targets, visible readout/title facts, six ordered action records and an
unchanged owner instruction. It exercises all 11 declared profiles, keeps
LFM3 rejection intact, checks native receipt boundary/overflow/missing-proof
cases, and tests ASCII and supplementary-Unicode inputs around the actual
65,536-byte boundary. It compiles against the frozen Code 29 source and
reproduces the original builder refusal, then passes on Code 30.

The existing complete host runner also retains native C budget tests,
Stop/finalization races, recovery and actual child-process lifecycle tests.
Exact host, Android build and signing receipts are separate artifacts;
retained historical receipts do not qualify this candidate.

## Delivery identity

Version code is 30 and version name is `0.30.0-local-exact-admission`.
The package is unchanged. Assembly must use the existing signing key and
verify the existing signer; an ordinary same-signer version upgrade keeps
the model files and app configuration. The frozen Code 29 APK/source and
its phone evidence remain separate. New phone qualification is required.
