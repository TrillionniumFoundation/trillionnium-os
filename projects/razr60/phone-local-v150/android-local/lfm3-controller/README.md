# Hepta v57 candidate: scoped Web and asynchronous control

This candidate combines the existing action/Stop/session repair with the scoped
Web code that matches the freshly observed 216-input installed build. The source
refs are `0b9e0031d2e137d6823668946d48e8154b339787` and
`dd2cd48054c2c6f0b2597b7d9be05edd8ce6b34e`; their real common ancestor is
`42d3a0f447807659c0f78c8273edee01dd1b734f`.

The current complete code contains 117 Java sources and 219 production inputs.
Read [ACTION-EXECUTION-CONTRACT.md](ACTION-EXECUTION-CONTRACT.md) for ownership,
ordering, deadlines, recovery and qualification boundaries. Source membership is
bound by the regenerated SOURCE-MANIFEST.json. All current validation must use
this exact source; prior 112-source compilation, v56 results and earlier v57
fixture results do not qualify the integrated build.

Android version 57 / `0.57.0-off-main-action-stop-candidate` distinguishes the
candidate. Model/native/sampler pins are unchanged. Build, original-key signing,
installation and real phone acceptance remain separate gates. Existing historical
sections below retain their original source/version boundaries.

## Frozen v56 foundation: natural Web tasks and responsive observation

This standalone Android candidate forward-integrates the business v54 source
42d3a0f447807659c0f78c8273edee01dd1b734f with the v55 observation, cleanup and
launch repairs at b949261f8caaf821c7a4618d0bab09a718238802. Their common source
is 7dee83d838b2c76b3abe3a3e61d7837316f40853. VersionCode is 56,
0.56.0-natural-web-responsive-observation. Neither earlier APK represents
this merged candidate.

The current city/date confirmation and single native flight-query attempt,
native calendar hierarchy, public-product evidence/completion path, natural
owner constraints, automatic in-range background target selection and concise
UI remain. The process-wide observation worker, original deadlines, screenshot
event fences, unreleased-Web admission/recovery fence, late-Stop completion
revocation and unsupported task-reuse launch refusal are retained. Invalid
runtime configuration disables new inference while Stop and cleanup stay
available. Model/backend details remain in the diagnostic section.

Flight results still cannot satisfy the completion gate. Public-product query
completion has a source implementation requiring matching detail/price evidence
and accepted native model navigation; this does not establish phone qualification
or shopping-order completion. The helper contract remains code 5 / protocol v3.
The controller has no INTERNET permission and makes no external-model request.
Ordinary text control still does not send screenshots to the model.

Action-side synchronous graph/identity checks can still delay the main looper.
No model weights, sampler, native runtime pins or saved owner application range
are changed by this integration. Read the [current v56 contract](docs/INTEGRATED-V56.md)
and [build contract](PUBLIC-BUILD.md) for the source and separate Android/phone
gates. Historical failures and receipts remain bound to their original versions.
This source alone proves no Android build, signed APK, installed upgrade,
GPU/NPU inference, simultaneous main-screen use or completed phone task.

## v52 predecessor: remember explicit background UI choices

The v52 predecessor: versionCode 52 (`0.52.0-local-background-preferences`), based on
frozen v51 commit `ed98f11db804f191a65254c378b195b1fb5f13be`.

The normal Hepta launcher now remembers the user's explicit background-mode
choice, selected application range and initial application in private preferences.
Reopening the screen restores those UI choices without starting or resuming a
task. Each selected package is rechecked against its current installed UID,
current signing certificates and launcher availability. Missing applications or
changed identities remain visible as an invalid saved selection: background
Start stays unavailable until the user explicitly selects the range again.
The controller does not silently change to foreground mode or discard a missing
package. A new task still performs its original full installed-APK, OWNER,
authorization and display-lease checks; saved UI preferences grant no authority.

Production changes are limited to MainActivity, a new BackgroundUiPreferences
helper and version metadata. The pre-existing foreground scope host fixture adds
a throwing interface stub for the new background-choice check; no permission or
UI preference is simulated by that stub. This release note records the change. The launcher label remains **Hepta**, package
`org.trillionnium.hepta.local`, and accessibility label **Hepta 本地操作**. This is
an update of the same application, not an additional launcher package. Existing
Start, Stop, recovery, cleanup, Notes parsing/workflow, task completion, native
runtime and model profiles are unchanged. No new permission, network client,
WEB provider or helper integration is included in this v52 artifact.

The Notes recognizer retains v51's bounded, completely consumed patterns. It
accepts short unquoted forms such as “明天下午三点看牙记一下” and colon-prefixed
“帮我记一下：明天下午三点看牙”, as well as explicitly quoted bodies containing
commas. It does not yet accept arbitrary comma-separated natural instructions;
for example “帮我记一下，明天下午三点看牙，带检查资料” is outside the current
recognizer. Bodies remain exact single-line OWNER spans of at most 94 UTF-16
units, with no marker insertion or date rewriting. Broader natural-note parsing
and controlled WEB support belong to later candidates.

Host regression results, Android compilation, same-signer installation and real
cold-reopen/selection/Notes behavior each require their own actual receipts.
This source note does not claim those validation stages have passed.

## v51 predecessor: complete authorized note creation with an observed tool workflow

The v51 predecessor is versionCode 51 (`0.51.0-local-notes-workflow`), based on frozen
v50 commit `9ecf87f313ef08cfd2f963671a19eb2358cebbfe`.

For an already recognized new-note/save/list/reopen request, the actual
model-issued `notes.create` may now own a bounded save/readback workflow.
The fixed Intent and its once-only ledger still report only `draft_opened`.
After that parent request and its complete body are independently observed,
the controller may consume a single-use grant for at most two fresh-body Back
actions and one click on the unique complete-body list item. Every child uses
the live task, immutable OWNER permission, installed Notes UID/APK identity,
current observation, display/generation and the same existing action domain.
A Back acknowledgement is never proof of saving. An unexpected editor, missing
or duplicate list item, stale callback, cancellation or uncertain effect stops
the workflow without retry.

Child records are explicitly `actor_kind=tool_child`, `model_issued=false`
and bind the real parent model run, fixed-entry attempt and before/after frames.
They do not appear as additional model decisions. The completion gate has a
separate child-proof branch; the existing model-click proof branch remains.
A complete exact-body collision already visible in the parent-before editor
or list prevents this parent from establishing a newly created note. This is
a bounded UI evidence claim, not a proof that no hidden or offscreen old note
exists and not a database item-identity guarantee.

After the workflow proves save/list/same-item reopen and a stable complete
readback, the controller may publish `controller_verified_done` with
`completion_actor=controller/tool_workflow`. Original model success/partial
claims stay unchanged in the raw evidence. No model `done` is synthesized.
The original success authority, fresh installed identity, actual parent worker
receipt and known native/background cleanup must still pass before the
terminal result is accepted. The recovery code recognizes only this exact new
terminal name and retains its existing task/UID/cleanup checks.

A small natural-note recognizer also accepts fully consumed, unambiguous
requests such as “明天三点看牙记一下” and “新建笔记：牛奶”. Its body is one exact
UTF-16 span of immutable OWNER, without trimming, markers or date rewriting.
The current complete-list proof limits that body to fewer than 95 UTF-16 units.
Ambiguous multiple goals, reminders and explicit draft/no-save requests do not
receive workflow authority. Unknown tasks and requests lacking either Back or
click permission keep their existing behavior.

The background broker conditionally requests a fresh document task only when
two actual PackageManager reads agree on the same explicit component, UID,
enabled/exported state and standard/document-none launch modes, and the
existing fresh-task flags are present. Unsupported cases retain their original
flags. Outbound intent metadata is recorded separately; this change alone
does not claim framework-effective flags, owned task identity or Recent-task
cleanup. No remove-task API, process kill or global policy is introduced.

Permission state stays visible in the main screen. The existing background
permission explanation and two preparation buttons are in a user-controlled,
initially collapsed section; their original listeners and start/recovery
controls are unchanged.

Host tests use explicit Android and native IO fakes. The archived real v50
LFM3 parent create/body evidence remains its original partial task and contains
no fabricated child success. Full host API-release checks, Android compilation,
signed source binding and real phone acceptance require separate receipts.
Native libraries, model profiles, sampling and fixed-entry payload semantics
are unchanged. Calculator and WEB completion providers are not added here.

## v50 predecessor: bind success choices to current proof and expose collection limits

The v50 predecessor is versionCode 50 (`0.50.0-local-observation`), based on frozen
v49 commit `06fb07b957c63622628afae90ec52887523b0860`.

The controller now intersects the immutable OWNER permission for success with
its existing completion predicate for the current observed frame. The exact
native grammar offers `done.status=success` only when both predicates hold;
`partial` and `failure` remain available within the existing tool authority.
The prompt publishes the same `completion.allowed_done_statuses`, and the
controller checks the same frozen grammar predicate after parsing and again
before dispatch. A parsed raw model success claim remains in original evidence
even when rejected at this earlier gate. The final fresh observation, installed
identity, stable completion and cleanup checks still decide actual completion.
No navigation or action is selected or dispatched by this status filter.

The selected accessibility tree has independent bounds of 1,536 visited nodes,
128 retained useful nodes, and fewer than 6,144 retained UTF-16 text units. Every
new observation records actual visited/retained counts, pending queue entries,
direct child slots not queued at the traversal limit, useful rows rejected at
row/text limits, reason codes and elapsed collection time. These counters do
not estimate the unknown number of unvisited descendants or grant actions.
Legacy observations keep unknown counters. Per-node package and class facts
are archived, and collection timing does not enter visible tree identity.
Prompt `nodes_omitted` counts only dropped observed rows; a separately reported
truncated tree is not converted into one fictitious missing node. Native exact-token admission
and profile/context limits remain unchanged.

The original v49 Notes regression preserves both premature native success
claims and the partial three-step task. A separate original browser XML has
975 nodes and is explicitly a later independent snapshot, not either selected
model-bound frame. Host replay compares the exact old and new collection
methods on that topology with declared synthetic Android IO. XML does not
supply platform action lists or isVisibleToUser/isEditable facts; no actual
click, scroll, or query success can be inferred from that replay. Real phone
collection cost, prompt admission and useful page coverage require new traces.

Notes still requires this task's creation, complete body, unique original list
provenance, model click on the same item, reopened body and stable final proof.
Calculator's pure matcher remains outside completion; a WEB query dispatch is
also not result verification. No new Calculator or WEB completion provider,
model/profile/runtime/sampler change, or additional tool authority is included.
Original failed and partial tasks are not reclassified by host regressions.
Full host release gates, Android compilation/signing and phone acceptance are
recorded in separate receipts and cannot substitute for one another.

## v49 predecessor: constrain verified task inputs and preserve failed-action evidence

The v49 predecessor is versionCode 49 (`0.49.0-local-task-inputs`), based on frozen
v48 commit `68cb7d8df097519694c52bf766c3816b09f2d0ea`.

For the supported literal Notes contract, this task's proved creation and its
currently verified complete editor body now restrict the `leave_created_editor`
phase to `back`, `wait`, and `done`, intersected with existing owner authority.
Body, title and category clicks are unavailable in that phase. The existing
verified-list phase retains its matching-item `click`, `wait`, and `done` domain.
The model chooses each action; returning is never dispatched automatically and
does not establish saving. Real list provenance, a later model click on the same
item, reopened complete body and stable completion remain required.

A complete, bounded integer arithmetic request for Moto Calculator can now
establish a separate task input domain after the installed application identity
is bound. Its expression is parsed from the immutable owner request with full
consumption and bounded `BigInteger` arithmetic for addition, subtraction and
multiplication. Eligible clicks come from fresh, unique, observed noneditable
calculator buttons, with their actual resource IDs and labels. Editable result
fields, history, ambiguous buttons and direct text/submit input are excluded;
launcher choices intersect the already authorized Calculator target. No digit,
operator, expression, answer or button sequence is dispatched by the guard.
Prompt, grammar, postparse and service dispatch use the same frozen domain.

The Calculator expression/result matcher has pure host regressions but remains
outside the task completion gate. A current correct pair alone cannot prove
this task calculated it. Calculator and unknown WEB goals therefore retain
partial completion when task-bound effect evidence is unavailable. The real
background type failure in the regression archive still has no verified after
frame, and its exact-readback failure has not been reinterpreted as success.

After a dispatched action fails verification, the controller may collect one
read-only diagnostic observation under the same live task, authorization,
display and deadline. It records that observation separately, keeps the
original failed action and error, performs no retry, and adds no completion
proof. Existing cancellation and cleanup rules remain in force.

Original v48 Notes frames and actions reproduce the body/title click detour and
partial terminal result. Actual Java 8 host tests separately exercise the new
editor domain, authorization intersections, grammar, service refusals, native
Calculator button domains and failed-action diagnostics using explicit host IO
fixtures. Full host release checks, Android compilation/signing and phone
acceptance require their own receipts. Runtime, model/profile/sampler pins,
Notes completion rules and unknown-task tool authority remain unchanged.

## v48 predecessor: keep supported Notes tasks within their current goal

The v48 predecessor is versionCode 48 (`0.48.0-local-notes-domain`), based on frozen
v47 commit `30811a345cf836f6d48123bb9fdbdf6ca9793162`.

For the already supported literal new-note/save/list/reopen contract, launcher
choices are the intersection of existing authorization, qualification scope,
repeat/no-effect checks and Moto Notes. Unrelated `web.search` is excluded. Once
this task has its verified create/body/list evidence and a current unique saved
item, its tool filter is `click`, `wait`, `done`; only the actual matching item
retains click capability. A capability removed by another guard is not restored.
The model still chooses every action. No navigation, click or next step is
executed automatically, and partial/failure reporting remains available.

The same final node, open-package, fixed-tool and scroll domain is bound to the
prompt and grammar, checked after parsing, and checked again by the existing
service dispatch gate. Leaving the created editor retains its existing valid
navigation choices. Unknown and WEB contracts retain their existing domain and
prompt layout. All Notes completion/source/identity/same-item-reopen/stability
checks, authorization rules, native runtime, profiles and sampler are unchanged.

Supported Notes prompts now distinguish cumulative task evidence from the
current provider-verified surface. `current_surface`, the current unique list
item ID and current editor-body match come from this same observation. The
complete original event history remains, followed by the screen and adjacent
completion/task-phase facts. A body reached by back without the required model
click is still not verified same-item reopen; its current body is reported
truthfully without advancing completion.

The new regression fixture contains 88 exact archived v47 files, including all
20 original before/action/after frames and model prompts. It preserves the failed
phone task. Host replay checks the five real target-list frames, suppressed
capabilities, service refusal, generic-task behavior and full history. Original
completion cases continue to require real model-selected effects in explicit
host IO fixtures. Full release8 host checks, Android compilation/signing and
real phone acceptance have separate receipts; this document does not claim a
successful phone task. Calculator input and completion changes are deferred to
an independent candidate and are not included in this Notes-only release.

## v47 predecessor: recover observed note progress after app switching

The v47 predecessor is versionCode 47 (`0.47.0-local-note-recovery`), based on frozen
v46 commit `59432f43633fc710a4c8843d77803bcdbf613ec6`.

After this task's verified `notes.create` receipt and complete editor body, an
actual unique full-body Notes list item can establish the list stage even when
it appears after an app switch or a later observation. Navigation acceptance
alone proves nothing. The original source/parent binding, installed app identity,
task/display binding, model-selected same-item click, reopened complete body and
stable final completion checks remain required. No next action is scripted.

The prompt now asks for a short rationale about the current observation and
next action. Prior free-form reasons remain in original action/model receipts
and are not fed back into the next prompt. The last actual dispatch keeps its
structured step, action and target package; complete event/observation facts
remain available separately. General app-opening authority, catalogue ranking,
model/runtime/sampler pins and permissions are unchanged.

The original failed v46 trace is a regression fixture, not a successful phone
run. Full release8 host checks, Android build and phone qualification require
separate receipts. See [CODE47-NOTE-RECOVERY.md](CODE47-NOTE-RECOVERY.md).

## v46 predecessor: protect existing notes and verify observed sources

The v46 predecessor is versionCode 46 (`0.46.0-local-note-phases`), based on frozen
v45 commit `c0195c1d7708c76dcd18dbb31083f1b5c1c5123f`.

The supported literal new-note contract now narrows the ordinary controller's
node actions until this task has a model-bound `notes.create` receipt and actual
body observation. The same immutable domain is used by the prompt, grammar,
postparse check and final service dispatch. Its complete literal body is passed
once through the existing local entry; direct text replacement and submit are
not part of this supported workflow. Leaving the editor and reopening the same
list item still require model-selected tools and actual subsequent observations.
Unknown tasks retain their existing authorization and action rules.

Confirmed no-effect clicks and launches are retained in a bounded task-local
memory for their observed package, app tree and IME state. Returning to the same
state no longer erases those refusals. This does not invent progress or claim to
detect every cycle of state-changing actions.

Moto Notes list verification now accepts a complete, parent-bound accessibility
`note_summary` text source inside the actually clicked `note_item_content` card.
It does not split a composed label or infer ancestry from screen coordinates.
A manual list XML fixture establishes the observed topology, not agent success.
The reopened editor must still pass the original complete body checks.

LFM3 now uses native exact-token admission on the exact `input_ids` passed to the
SDK. Java byte counts are advisory for this profile; model/runtime/sampler pins,
context limits and the same-input-ID native budget guard are preserved.

Full release8 host checks, Android compilation, signing and phone acceptance
are separate build/run receipts. This source document does not claim those
stages passed. See [CODE46-NOTE-PHASES.md](CODE46-NOTE-PHASES.md).

## v45 predecessor: observed labels for text-only clicks

The v45 predecessor is versionCode 45 (`0.45.0-local-observed-clicks`), based on frozen
v44 commit `180a7ab55f5a479c14c202fdbe33a1a4734cecfd`.

The ordinary controller receives text observations without image input. It now
offers click only for targets whose current supplied label contains actual
visible text or symbols. Empty labels, invisible-only labels, structural IDs,
and collector-added punctuation cannot identify an icon's function. The final
click domain is checked independently after parsing and again before dispatch.
Observed nodes, labels, coordinates and metadata remain intact. Empty editable
fields retain type and observed query submit; scroll and system back retain
their existing rules. Calculator symbols and actual labeled list cards remain
eligible when their other existing gates permit them.

This change addresses a saved Notes failure where the model clicked unlabeled
node `n10` while reasoning about saving; that action did not establish a saved
note. It does not add a Notes success fixture or change completion evidence,
runtime/model configuration, background execution or permissions. See
[CODE45-OBSERVED-CLICKS.md](CODE45-OBSERVED-CLICKS.md) for the exact scope and tests.

## v44 predecessor: completion evidence for local tool tasks

The v44 predecessor is versionCode 44 (`0.44.0-local-completion-evidence`), based on
frozen v43 commit `c76be7243b70e2142c6c87733c292c6df0d88652`.

A model's success statement is now checked separately from tool authorization
and launch acceptance. A first claim without the required evidence leads to a
fresh observation and continued local reasoning; a second rejected claim ends
as partial. The supported Notes contract requires the model's exact note text,
visible editor, save/list transition and a model click on the same observed item
followed by reopened body evidence. Search requests and unsupported goals remain
partial when actual result proof is unavailable. No write is required merely to
complete a read-only task.

In v44 the v6 tool grammar, SYSTEM text, runtime/model/sampler, existing permissions,
background broker and one-shot dispatch ledgers are unchanged. Raw model claims
and verified completion are recorded independently. Strict host/Android gates
and real phone business acceptance are separate evidence; source status does not
claim they passed. See [CODE44-COMPLETION-EVIDENCE.md](CODE44-COMPLETION-EVIDENCE.md)
for the supported owner forms, exact Notes representation and remaining limits.

## v42 predecessor: observed state and control metadata repair

The v42 predecessor is versionCode 42 (`0.42.0-local-observation-repair`), based on frozen v41
commit `ebd495d93660f24a3229fe91fec25508c546fad4`.

This candidate refreshes sampled background accessibility nodes, classifies
same-target content changes as zero-dispatch stale observations, records actual
broker and ordinary-app display policy readback, and exposes bounded observed
resource/class properties for otherwise unlabeled controls. Node labels, action
authority, model/runtime settings and existing cleanup gates remain bound to the
original observed facts. Full strict host checks, Android compilation and v42
ordinary phone acceptance are pending. These source repairs do not establish
successful shopping, flight search or note creation. See
[CODE42-OBSERVATION-REPAIR.md](CODE42-OBSERVATION-REPAIR.md).

## v41 predecessor: background startup repair

Version 41 (`0.41.0-local-background-repair`) fixed socket setup order, handled
the narrowly defined empty organizer task shape and retained bounded broker
diagnostics. Version-specific documents preserve their original freeze-time
claims. Existing interrupted task journals must retain their original bytes;
only normal in-app cleanup and acknowledgement may restore task availability
after the required evidence is established. See
[CODE41-BACKGROUND-REPAIR.md](CODE41-BACKGROUND-REPAIR.md).

## v40 predecessor: bounded model continuity and permission guidance

The v40 predecessor is versionCode 40 (`0.40.0-local-progress-guidance`), based on frozen v39
commit `5a68ef538ca8a9d76591dd6adb089b90b0ad97d4`.

The owner UI explains Magisk 31.1's requirement to configure a grant in its
Superuser page before running a command. **打开 Magisk 管理器** opens only the normal
launcher for `com.topjohnwu.magisk`; hidden or renamed managers must be opened
manually. **核验后台执行权限** retains the existing fixed read-only probe and its
independent receipts. Opening the manager does not grant or verify permission.
See [CODE40-PROGRESS-GUIDANCE.md](CODE40-PROGRESS-GUIDANCE.md).

The ordinary controller now retains one bounded prior model intention after a
real accepted/dispatched step. It is explicitly marked as model output rather
than observation evidence and cannot supply tool authority or old target pairs.
This tests a continuity hypothesis from the actual Qwen failure; improved model
quality has not been established. System instructions, model selection, native
inference, action dispatch and permission preparation semantics remain unchanged.
Its Mac Android compilation passed with 172 compiler inputs. The complete host
gate stopped at an inherited app-label fixture error (one error among 267 Python
tests), so v40 was not signed or installed. Real-device acceptance remains
unestablished; these predecessor results do not qualify v41.

## v39 predecessor: owner UI preparation

The v39 predecessor is versionCode 39 (`0.39.0-local-background-setup`), based on frozen v38.

The normal UI now offers **启用后台执行权限**, a fixed read-only `su -c /system/bin/id -u`
probe under the ordinary application UID. It has independent receipts and shares
the existing process lease, so preparation cannot overlap tasks or model diagnostics.
See [CODE39-BACKGROUND-SETUP.md](CODE39-BACKGROUND-SETUP.md) for exact verification,
interruption behavior and the distinction between one successful probe and permanent
authorization. That historical implementation is retained; its old qualification
notes do not substitute for v40 build or device evidence.

## v38 predecessor: observed query-field submission

The v38 predecessor was versionCode 38 (`0.38.0-local-ime-submit`), based on v37.
It adds a strictly observed, query-labelled `ACTION_IME_ENTER` tool to the ordinary
local controller, with task authorization, full input/window/display binding,
durable pre-call attempt evidence and no automatic retry. Generic Enter, payment,
order and send labels do not qualify. The background broker, qualification scope
and configured model are unchanged. See [CODE38-IME-SUBMIT.md](CODE38-IME-SUBMIT.md)
for the compatibility boundary and host-versus-device qualification.

## Retained implementation history

### Code26: observed transitions and an explicit 9B candidate

The historical Code26 candidate is versionCode 26 (`0.26.0-local-observed-transitions`). It places the current screen after the complete recorded action history and adds the last step's actual before/after editable text, window title and IME observations. Those facts do not infer causality or task completion. An independently pinned Qwen3.5-9B Q4_0 text profile is available for qualification; it does not replace the configured or default model. Existing action permissions, freshness, recovery and local-only inference gates remain. See `docs/CODE26-QUALIFICATION.md` for the change and qualification boundary.

The prior exact Code24 source passed 70 host checks and Android compilation; Code24 was not installed for phone testing. Those artifacts remain separate from Code25 qualification.

The selected model is read from the existing app-private runtime configuration. Installation does not select or import a model. The APK has no INTERNET permission and does not fall back to an external model. The ordinary task controller remains text-based; the separate MobiMind and UI-Venus image diagnostics do not dispatch phone actions. A signed build or passing host tests does not establish production readiness.

## Retained implementation history

The current candidate is versionCode 20 (`0.20.0-local-stable-ui-venus-budget`). It combines the complete observed action domain and lossless recorded-history projection with the exact allowed open-package list and a stable-observation cap clipped to the original ten-second caller/task deadline. Fresh unconfigured LFM3 uses NPU / 8192 / four threads; existing explicit configuration is preserved. The separate UI-Venus Q4_0 first-frame diagnostic remains model-only and does not dispatch phone actions. See `docs/CODE20-QUALIFICATION.md`; older version-specific documents and host receipts are historical evidence.

## Private model-only diagnostic

Code20 / `0.20.0-local-stable-ui-venus-budget` retains a separate private UI-Venus
first-frame image diagnostic and a single Application-level recovery barrier
for the control, MobiMind and UI-Venus sessions. The new VLM output is retained
as raw text and never connected to the phone action dispatcher.
See [UI-VENUS-APP-PROBE.md](UI-VENUS-APP-PROBE.md) for the exact private request,
original-image/OWNER/template binding, budgets, model/runtime pins and limits.

Code16 observation stability, exact scroll domains and execution guards remain
unchanged. Recorded history now uses one lossless compact representation. The original sixteen GenieX/MNN native APK
members must remain byte-identical; one independently pinned UI-Venus App worker
is added. The existing private text configuration is not changed. The fresh LFM3
8192 default from the budget-continuation branch is preserved. The APK still declares no INTERNET permission.

Host contracts, Android compilation and a signed APK are separate from ordinary
App VLM execution, actual device mapping and semantic GUI task acceptance. The
original shell VLM probe is a different artifact. No runtime or phone task
qualification transfers automatically to this candidate.

The retained code14 controller exposes
bounded actual active-window metadata and node focus, binds them to exact
observation freshness, and removes a repeated click from the next candidate set
only when the existing repeat guard already rejects it. The protocol treats all
rounds as the same owner task and retains the ordered completion requirement.
See [CODE14-WINDOWS.md](docs/CODE14-WINDOWS.md) for exact changes and limits.

A separate explicit experimental Nemotron 3.5 Bolt E4B Q4_K_M text profile is
pinned to its official artifact. Initial qualification uses context 4096 and an
8 GiB available-RAM admission threshold, not a measured peak-memory guarantee.
No profile is selected automatically. Existing runtime configuration is not
rewritten by installation, and the source default remains LFM3.

The complete code13 GenieX and MobiMind runtime pins are preserved. The separate
MobiMind endpoint remains model-only; visual output does not dispatch actions.
Its ordinary-App GPU execution is not qualified by this source build.

## Existing local phone controller

Independent package `org.trillionnium.hepta.local`, label **Hepta**. It does not update or replace `org.trillionnium.hepta.localprobe`.

Code 9 exposes actual bounded descendant labels for otherwise blank clickable
parents and binds their sources to target/whole-window freshness. It rejects
explicitly labelled persistent destructive node clicks before dispatch and
includes the compatible reason-first host verifier. See `CODE9-TARGETS.md`.

Code 8 explicitly includes `done(status,summary)` in the tool menu, requires a
tool-name string for `action`, and explains that waiting is for loading rather
than completion. Existing grammar, owner task and dispatch gates are unchanged.
See `CODE8-PROTOCOL.md`.

Code 7 added separately observed input-method window visibility to progress and
freshness checks, while preserving repeated-action rejection when no actual
change is known. See `CODE7-IME.md`.

Code 6 added reason-first constrained decisions, action-specific observation
freshness, CPU SHA2 acceleration of the still-complete per-invocation model
integrity check, and private prompt/token diagnostics. See `CODE6-REASONING.md`.
Successful compilation and host checks do not establish phone task completion.

Code 5 exposes precise progress fields and removes an `open` candidate only when
the existing unchanged-screen repeat guard would already reject that exact action.
The dispatch-time guard remains active. See [CODE5-PROGRESS.md](CODE5-PROGRESS.md)
for the preserved transition semantics and host/phone validation boundary.

This candidate preserves the original default LFM3 profile and includes explicit,
SHA-pinned MiniCPM5, Spark, Gemma 4 and experimental Bolt profiles. New models require exact native
tokenization and same-input-ID budget proof. See [MODEL-PROFILES.md](MODEL-PROFILES.md)
for configuration, identity binding and remaining phone-validation gates.

This candidate reuses the ordinary Android Accessibility controller, Start/Stop UI, private one-use test trigger, app-wide session, strict JSON action parser, fresh-screen checks and owned native-process cleanup. It selects **LiquidAI LFM3-1.7B QAD Q4_0** with the pinned **GenieX 0.10.0 llama_cpp** runtime. Defaults are **Hexagon NPU**, context **8192**, four CPU support threads. It declares no INTERNET or other application permissions. It has no model URL, HTTP client, shell tool, external model endpoint or automatic CPU fallback.

The selected file is exactly `files/model/LFM3-1.7B-QAD-Q4_0.gguf`, 1,049,615,680 bytes, SHA-256 `43a7d09a0e9cba91b63eb7052488b9564569bddfd65754d2e426465e572a7452`. App-private ownership and a full first-use SHA verification bind the embedded tokenizer/template as well as the weights. The verification is reused only for the unchanged file in the same app process.

The text model receives the owner's instruction, a bounded application catalogue, Accessibility node text/bounds, visible readouts and the full compact recorded task history. A read-only `find_app` tool searches and pages the complete bounded installed launcher snapshot when the first prompt omits the target app. Screenshots stay on the phone for observation consistency and evidence; they are not sent to this text model. Only observed node clicks are accepted. An app with no usable Accessibility nodes may require a separately qualified vision model; this candidate does not pretend to see images.

Read `LOCAL-CONTROL.md` for the task contract, `PUBLIC-BUILD.md` for build commands and `TOKEN-BUDGET.md` for the model-specific conservative bound. `tools/phone_acceptance.py` performs independent final UI checks and binds app/native receipts; self-reported completion is never enough.

Host checks establish parser, policy, runtime configuration, Unicode/context, atomic publication and acceptance-driver behavior. They do not establish Android compilation, NPU/GPU access, phone control success, battery use or a full phone task suite. Those require fresh evidence from this exact package and APK.

Each control request uses an observation-specific GBNF action grammar and validates its actual native input hash. Diagnostics remain unconstrained text. Available-memory admission now prefers valid Linux MemAvailable, records both kernel and ActivityManager metrics before/after, retains the 3 GiB threshold and always honors Android lowMemory.

Revision 3 adds explicit package/normalized-label ranking and model-issued local app discovery. Search receipts distinguish an accepted read from a dispatched UI effect, and pagination advances only past entries actually shown after prompt budgeting. Opening an app still requires a package shown in the current prompt and a fresh launchability check. See `APP-DISCOVERY.md` for the schema, evidence and host/device validation boundary.

Process recreation reads persisted session ownership before admitting new work. Only a known clean terminal state can allow another task; unresolved/corrupt state blocks without replay. The native worker validates its expected parent and uses a parent-death signal. `SESSION-RECOVERY.md` explains the remaining Android-specific qualification.

This standalone candidate has no active Cargo/G1 adoption claim. `CONTROL-INTEGRATION.md` is its current interface, state, resource, evidence, migration and rollback contract. Historical source overlays and old test receipts are not part of this source closure.
