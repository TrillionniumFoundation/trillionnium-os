# Code23: bounded action dispatch and experimental model registration

This isolated source derives from the complete frozen Code22 manifest
`3aa67e3a9e332fb0a8e0937d1ea652288d20e52fc909e9f951927bb8ff9190e1`.
It preserves Code22's history, recovery, all seven existing model profiles,
default configuration, and the three session contracts.

The controller binds each action's cancellation token to the original task
deadline and the lifetime of that individual wait. The first callback wins.
An action acknowledgement that arrives within the existing eight-second wait
is saved with its original accepted/dispatched/effect information before Stop
or an expired task prevents further work. An eight-second receipt timeout keeps
the existing CleanupUnknown/blocked behavior. This change neither invents a
receipt for a timed-out action nor resumes it after a late callback.

The new `qwen35-4b-q4_0` profile selects the exact Unsloth conversion at revision
`1a02dbed1cdfe73efc3fa519c54126befb4faf68`, file `Qwen3.5-4B-Q4_0.gguf`,
2,583,221,408 bytes, SHA256
`298fcb5fe7a77ccc79745ae24751560c5ac56874caff4bb39b1f2055bd72b8bb`.
It is a text-only experimental candidate, not an official Qwen-produced GGUF.
The six-GiB availability threshold is an admission policy, not measured peak
memory. The existing Code22 `lfm2.5-8b-a1b-q4_0` ID and seven-GiB policy are
unchanged; the parallel `lfm25-8b-a1b-q4_0` alias is not admitted.

No model is bundled, downloaded, selected as default, or qualified by this
registration. Native loading, exact-input tokenization, NPU behavior, output
quality, RAM, thermal behavior, and phone actions require separate real-device
qualification. Host checks and Android compilation alone do not prove them.
The SDK, compiler requirements, existing runtime pins, permissions, prompt,
grammar, thinking policy, and native-tools policy remain unchanged.

Version metadata: 23 / `0.23.0-local-deadline-moe-qwen`.

## r2: click eligibility projected from the existing execution policy

This revision narrowly incorporates PR121 at
`47be96088bb43d42af4ae107c849f97d56b1be4d`. It classifies the full observed direct
label/description before display truncation, retains the label as observation
data, and uses the same eligibility in prompt click flags, finite grammar, and
post-parse click validation. The existing fresh execution policy remains in
place. Code22 event history, recovery, and the same-state no-effect guard are
retained; the older PR121 controller is not substituted wholesale.

The original 18 synthetic policy contracts remain, plus one merged-guard case
using the actual pure same-state guard. The tests do not execute Android, prove
that this mismatch caused a particular phone failure, or remove the existing
bounded-descendant-text limitation. Deadline and Qwen registration behavior
from r1 are unchanged. r1 source manifest `f9697267…` remains a separate frozen
artifact; r2 must be selected by its own complete source manifest and archive.
