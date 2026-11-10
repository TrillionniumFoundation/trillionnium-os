# Code32 candidate scope and qualification

Code32 (`0.32.0-local-lfm3-cancel-timeline`) combines two independently reviewed
changes on the v30 source parent
`ec9b4106bf0d4d46267831c14f1102090a3137f6`.

## Source changes

LFM3 now uses the same existing exact token admission path as the other
registered profiles. The native worker applies the pinned GGUF chat template
once, tokenizes it, checks the exact context budget, and sends that same ID
array to generation. Java and host validators require matching count and hash
evidence. The input/rendered byte ceilings remain enforced. The prior byte
bound rejected every normal LFM3 controller prompt at context 4096 because the
actual system message alone produced a conservative total of 4619. See
`LFM3-EXACT-ADMISSION.md` for the reproduced failure and regression coverage.

Warm tasks also retain additive parent lifecycle observations in the
`parent_process_timeline` session-receipt object. The owner, request handles
and session share a task/generation-bound recorder. It records first cancel,
destroy, force and observed-exit events using offsets from one parent-process
monotonic clock. Existing cancellation, waits, cleanup, receipt acceptance and
terminal-success rules are preserved. See `PARENT-CANCELLATION-TIMELINE.md`
for event semantics and the limits of causal interpretation.

An invocation record does not prove kernel signal delivery or establish the
cause of a native exit. A `0x2e` or exit-134 observation therefore remains a
runtime diagnostic to investigate, not an inferred hardware diagnosis.

The manifest identifies this combined candidate as versionCode 32. No
recurrence-controller change or Nanbeige profile candidate is included.

## Preserved identities and behavior

The GenieX Android runtime remains version 0.10.0, source commit
`071f609995470bdb0e0769ab964754adfaab7e47`, with llama.cpp source commit
`19cce6919992fdffd92e0ac152caaf1e2b8f254e`. Packaged GenieX libraries must match
the original pinned release archive. The separate MobiMind and UI-Venus
workers retain their independent original pins.

Model IDs and artifact hashes, configured context choices, output budget,
requested accelerator, task ownership, tool grammar and action permissions
are unchanged. Installation preserves the existing app-private model
configuration. The APK declares no INTERNET permission and has no external
model fallback. The separately pinned vision diagnostics still do not dispatch
phone actions.

## Required evidence

The combined source must pass the standard full host checks with JDK 17,
including the LFM3 impossible-floor regression, exact counted/generated-ID
checks, overflow-before-generation checks, warm repetition, and the production
parent lifecycle tests. Synthetic tokenizer/SDK doubles and synthetic Java
protocol peers are host contract tests; they do not establish model inference
or Android signal behavior.

A fresh Android build must bind its Java, resources, native sources and adapter
inputs to the generated DEX, base APK and PIE worker. Assembly must revalidate
those source hashes, every independently pinned runtime library, the actual
manifest/version, resource alignment, ELF dependencies and APK signature. Use
the existing signing key and compare the resulting certificate to the retained
v30 artifact. Build and assembly receipts are separate from source control;
no private phone evidence belongs in this source bundle.

Before adoption, verify the actual installed APK identity and signer, ordinary
App accelerator selection, real-model exact token IDs/count/hash, repeated warm
requests and an actual over-context rejection. Run the ordinary Hepta entry,
offline tool suite and independent final-state checks from this exact APK.
Stop/restart, cleanup and sustained runtime behavior need fresh device evidence.
Candidate build or static acceptance does not claim those gates passed.
