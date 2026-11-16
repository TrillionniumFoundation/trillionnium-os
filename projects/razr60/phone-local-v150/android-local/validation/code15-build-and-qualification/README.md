# Code15 loader change and qualification boundary

Code15 (`0.15.0-local-mnn-loader`) changes only the MNN diagnostic child's
library search environment and its recorded policy, plus release metadata.
It uses `/system/lib64:/system_ext/lib64:/vendor/lib64`, preserving the fixed
worker's direct `$ORIGIN` RUNPATH for its pinned MNN and C++ dependencies. It
continues to remove preload/audit/GenieX/plugin/ADSP overrides. The mixed App
native-library directory is not added to that global search path.

The full frozen App source is unchanged from the tested candidate. Its source
manifest has 851 members; `BUILD-IDENTITY.json` records source, signed APK, DEX,
and all 16 native identities. All 39 host gates passed, followed by real Android
Java, DEX and arm64 compilation and same-signer assembly. All 16 packaged native
files match Code14 by complete size and SHA-256, including the freshly rebuilt
GenieX worker. The original model profiles, text planner, dispatch guards,
shared process ownership, cancellation and recovery contracts are unchanged.

## Ordinary-App OpenCL model-only result

A fresh normal-App run with the exact earlier private fixture and original
120,000 ms / 256-token limits completed with native exit 0 and EOS. Independent
retained-evidence qualification bound the live worker to its ordinary App
parent, App UID and untrusted_app SELinux domain, exact installed executable,
all 23 `/proc` arguments, request identity, complete model hashes and native
receipt. Full maps demonstrated the three pinned runtime files and OpenCL.
The observed environment was the declared system-first search path.

Thirty live samples preserved both processes' identity brackets. In 27 samples,
all three runtime libraries and OpenCL were mapped together. The execution
receipt recorded 117,568 GPU operator calls and 112 CPU helper calls, so this
is not an all-GPU claim. The native model operation took 36.362 seconds in this
observation. The final native and original Java contracts passed, two terminal
idle observations established cleanup, and the prior controller journals,
configuration and membership remained unchanged. No phone action was dispatched.

The original collector report remains unqualified: it incorrectly expected
`ps` to display a full executable path, while Android displayed only the
worker basename. A separate audit accepted only that observed argv[0]
representation (or the exact full path), with all other 22 displayed arguments
unchanged. Complete `/proc` argv and executable identity remained independently
mandatory. The audit did not rewrite the saved sample or old report, and no
third inference was run. The earlier attempt lacking live domain proof also
remains unqualified. Private screenshots, prompts, raw outputs and device
identifiers are not included here.

## Limits and retained results

MobiMind is still a model-only diagnostic endpoint. This result does not qualify
visual phone operation, the nine-goal controller suite, or MNN cancellation.
Neither the experimental visual controller, native-tools runner nor compact
history draft is merged. No INTERNET permission or external model fallback is
added. Code14's E4B offline four-goal result remains 3 pass / 1 fail; its
calculator-keypad failure and earlier negative evidence are not rewritten.
Code14's text-controller Stop/restart qualification is separate from MNN.

## CI

The new `mobimind-runtime-rebuild-v3` and `mobimind-ci-host-split-v3` helpers
are bound to this exact Code15 source. The prior Code14 helper versions and
actual CI results remain preserved. Fresh CI rebuilds the MNN runtime on macOS,
requires all three original full file hashes, binds the current source HEAD
and workflow attempt, and revalidates that closure on Linux before assembly.
The compiler qualifier and all runtime pins are unchanged. Code14's green CI
is not a Code15 result; the new exact-HEAD workflow supplies that evidence.
