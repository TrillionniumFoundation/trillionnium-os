# Code19 stable-observation build and qualification

Code19 source commit is `fdb7eca8d3a434c515da547365fcc47bb2f510d3`.
Its complete 866-member source manifest is
`9817f2af3937a402b52176565233c763869495d203080deffd7e279f9f621b69`.

The observation caller already supplied an absolute deadline of at most ten
seconds, clipped to the existing task deadline. The inner stability gate
previously stopped collecting fresh stable evidence after two seconds. Code19
raises only that inner cap to ten seconds. It still takes the minimum with the
original caller deadline; retry/reset cannot extend either deadline.

Two equal complete frame identities still need at least 200 ms separation.
Missing-root handling, screenshot/post-save graph rechecks, the original
capture watchdog, cancellation, ownership and retirement remain unchanged.
A late result cannot become a new task's observation. This change does not
claim hard real-time Android callback scheduling or prove the precise cause
of an earlier navigation observation failure.

## Actual same-signer Android build

`LOCAL-PREPARATION.json` records the path-sanitized preparation receipt.
Mac actually compiled Java, DEX and the Android arm64 worker in 12.226 seconds.
Pocket4 assembled and checked the APK with the existing signer:

- Version: 19 / `0.19.0-local-stable-observation`.
- APK: 20,612,784 bytes; SHA256
  `e9eb1d119c265e12402975bece2db450bd999436e41e64d62cb64cf315668782`.
- Original signer:
  `202d00f853589c753069189086e0c76cb308d11745c33e70200985e4de3129d5`.
- No declared INTERNET permission; no new signing key.
- All 16 packaged native members are byte-identical to Code18, as recorded in
  `NATIVE-CLOSURE-COMPARISON.json`.

The controller, model profiles, defaults, action protocol and native code
remain identical to Code18. Explicit model configuration is not migrated.
The new explanatory document removes a private task identifier while keeping
the case ID and original receipt hashes; the owner source remains unchanged.

## Focused contracts and full exact-head CI

The focused host execution retained the old gate with its original contracts,
passed the new eight-contract gate suite, and confirmed that the new transition
test fails at the old two-second boundary. The report preserves that expected
negative-control exit. `FOCUSED-OBSERVATION-CONTRACTS.json` identifies the exact
code/test bytes and original report. That focused run preceded the final version
and manifest freeze; it is separate from the later complete Code19 CI.

[Run 42579979834](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42579979834)
completed successfully at the exact source commit. Both the macOS MNN producer
and Linux source/Android consumer succeeded. All 47 original host gates passed.
Real Android compilation, static acceptance, same-run/attempt runtime verification
and packaging with an ephemeral CI signer completed.

`CI-QUALIFIED.json` identifies the downloaded evidence artifacts and their
independently verified full sizes and SHA256 digests. All 119 host source inputs
were matched to the frozen Code19 source. `CI-HOST-CHECKS.json` retains the
actual receipt. CI's ephemeral signer is not the installed-device signer.

This run also exercised the bounded transport fallback with real official
bytes: the original GenieX release URL returned HTTP 504 twice; attempt three
used the fixed official asset API and verified the complete 98,545,327-byte
archive against the original SHA256
`248b49c83bc74238babc0d9ebf46f0c8b6d2e9b6de3ffb90c2a5a2042523831f`.
The original extractor and all payload pins remained unchanged.
`CI-RUNTIME-TRANSPORT.json` records all three attempts. Code18's successful
first original-URL attempt and both earlier failed Code17 runs remain separate.

The local preparation also preserves its platform boundary: 27 Java compile
and contract gates passed on the Mac JDK, while 152 Python tools tests and
4 private staging tests passed on Linux. The Mac run still encountered the
existing Linux-specific fixture. The later supported-runner full-suite pass
does not overwrite that original partial-platform record.

## Acceptance boundary

Build and host qualification do not establish model task success, ordinary
Start/Stop, background work, restart or recovery. Phone qualification must
bind the actual Code19 APK, explicit candidate/configuration, original plan,
complete task/native/action evidence and independent final UI.

Code17 and Code18 failures are retained separately. Neither the prompt-budget
correction nor the stability-window correction establishes that every tool
receipt and long history is sufficient for every model decision. No model
task is relabelled as passing because compilation, NPU inference or an isolated
screen observation succeeded. Raw phone/model logs, private task identifiers,
device identifiers, signing keys, models and APK binaries are excluded.

## Later retained phone boundary

Code19 was installed with the original signer and the explicit Gemma
NPU4096 configuration preserved. Another visible controller started the
identical frozen nine-case plan, but its host connection was interrupted.
The original suite retained **1 pass, 1 unknown and 7 not_run**. Recovery
records include a host reboot and two checks of restored network settings;
the second phone task subsequently ended naturally with known cleanup.
Neither observation fills in the interrupted suite or establishes full
Code19 phone acceptance.

Ordinary Start, sustained background work, Stop and a new task after restart
remain unverified. Phone control must be coordinated before any new suite
starts. [The dated qualification snapshot](../phone-local-20261109/README.md)
and [research revision v5](../code17-build-and-qualification/phone-regressions/RESEARCH.zh-CN.md)
preserve this boundary without publishing private task identifiers.
