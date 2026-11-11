# Code40: prior model intention and accurate permission guidance

Candidate `40 / 0.40.0-local-progress-guidance` is based on frozen v39 commit
`5a68ef538ca8a9d76591dd6adb089b90b0ad97d4`.

## Confirmed permission-guidance defect

The installed phone has Magisk 31.1 (31100). Its release removes reactive `su`
prompts: a grant must already be configured through the Superuser page. The v39
probe correctly reported a clean failure (exit 13), but its progress message told
the owner to choose in an authorization prompt that would not appear.

Official references verified by the parent device investigation:

- <https://github.com/topjohnwu/Magisk/releases/tag/v31.1>
- <https://github.com/topjohnwu/Magisk/blob/master/docs/changes.md>

## UI behavior

The app explains the Superuser **+** workflow and shows the fixed Hepta package
and its actual ordinary UID so the owner can identify the application. A visible
**打开 Magisk 管理器** button resolves only the launcher for
`com.topjohnwu.magisk`. It performs normal owner navigation, with no command,
grant, task, preparation attempt or persistent permission-state update. The
button rechecks visibility and the existing idle conditions at click time.
If the manager is hidden, renamed or unavailable, the UI asks the owner to open
the actual manager manually. No package scanning or implicit alternative target
is added.

The existing preparation button is now **核验后台执行权限**. Its pending and failed
messages explain prior authorization rather than promising a reactive prompt.
A successful probe still verifies only that invocation; it does not establish a
permanent grant, working background display or successful application task.

## Preserved implementation

The fixed command remains `su -c /system/bin/id -u`, issued by the ordinary app
UID. Identity checks, process ownership, the Application-owned shared lease,
deadlines, cancellation, output validation, durable receipts, late-exit handling
and historical unknown recovery are unchanged. This candidate changes no Magisk
policy, model/runtime setting, system instruction, grammar, task permission,
broker, virtual display or external diagnostic entry.

## Bounded prior model output in the ordinary task prompt

The actual v37 Qwen step 3 selected digit 3 with a reason explaining that this
would finish entering 23. Step 4 received the complete executed action history
and the actual current value 23, but the earlier model reason was absent. It
selected Clear while calling that partial operand a conflict with the requested
expression. All 20 requests had valid native prompt/grammar binding, exact token
counts and complete EOS output. This is a continuity hypothesis to test, not a
proven explanation of all model failures.

`LastModelDecisionProjection` retains only the most recent actual dispatched
model intention within one running task. The controller updates it only after
saving the real action receipt and following observation, with accepted=true,
dispatched=true and stale=false. Its immutable object binds the task, model run,
source observation and step. Before projection it verifies the same task and the
last actual dispatched history row. Rejected, unexecuted, stale, read-only,
waiting and terminal proposals do not become a new intention. No state is
restored or replayed across tasks or process recreation.

The prompt field is placed after `events`, before `last_transition` and the final
current `screen`. It contains only `source=prior_model_output_not_observation`,
`step`, `action`, and `reason`. The reason is bounded to 96 Unicode code points;
an exceptional longer parsed reason is copied as a prefix with an explicit
`reason_truncated` flag. Existing native control grammar already caps reasons at
96. No historical node, package, observation ID, success claim or tool permission
is issued by this new field. Full source bindings remain in the object and
existing per-step model/action receipts.

OWNER, SYSTEM, current screen facts, recorded events, allowed targets, action
parser/grammar, authorization and dispatch checks are unchanged. The new field
remains inside escaped `UNTRUSTED_DATA` and is counted by the same Java/native
budget checks. It adds input tokens, so a small context can reach its existing
admission limit sooner. No reserve, truncation bypass or default-model change is
introduced. There is no Calculator-specific production branch or host-supplied
next action. No new model-only trigger/API was added.

## Local verification and limits

The existing actual permission worker tests passed 44 cases, and the actual
Application-owned permission session plus shared lease tests passed 12 cases.
These were supplemental Java 8 source/class-target checks using explicit Android
and process IO fixtures; no `su`, model, Android runtime or phone was used. The
strict Java 8 API release gate and Android compilation remain required on the
existing build hosts. No mirror test was added solely for the display strings.

The new pure projection regression passes 37 checks, including the hash-bound
actual v37 step-3 output and step-4 prompt. Existing ordinary controller/owner
wiring passes 33 cases, qualification-scope control passes 88, and IME submission
and owner grammar suites pass. A separate production prompt-builder check
confirms identical current grammar text/SHA and target sets, identical existing
frame content after removing the added field, unchanged OWNER, escaped model
markup and increased budget accounting. All six prompt-admission cases pass.
These are supplemental host checks; actual inference was not run locally.

An initial local broad pure compilation hit an unrelated existing
WarmProcessSession serial-lint warning in the stripped JDK. The targeted
supplemental check excludes that unused class. The unmodified strict full gate
still includes it and remains required on the existing complete JDK17 build
host. Initial new-test fixture mistakes (open field order and a mismatched
expected synthetic reason) were corrected without changing parser or production
authorization behavior; the later retained receipts show the corrected passes.

The independent saved-request A/B input fixture is outside this source tree.
Because v39 lacks an exact-grammar retained-slot diagnostic entry, no new
external entry was added. The parent will evaluate the ordinary v40 task against
the recorded v37 failure after full host and Android build gates. Host tests,
signing and installation cannot establish improved model decisions or phone task
completion.
