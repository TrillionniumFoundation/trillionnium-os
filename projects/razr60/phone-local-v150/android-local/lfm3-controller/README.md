# Hepta v48: recover the created note without relaxing completion

Current candidate: versionCode 48 (`0.48.0-local-notes-recovery`), based on frozen
v47 source `4b96f6d7513a336028a79367f33f38babe19a41b`.

A newly retained v46 LFM3 phone run created the requested note body, then spent
19 actions switching between Hepta and Moto Notes. The list contained the body,
but its unproven save transition left the phase without a permitted item click.
The run exhausted its 20-step budget. Native NPU inference completed normally;
the task did not complete.

This candidate restricts unrelated app opens after this task's created body has
been observed. A unique, provenance-bound matching list item can restore that
editor after a deviation. Recovery still requires model-selected tools and fresh
observations; it does not establish a save, a completed reopen chain or success.
The existing completion predicates continue to require the full original chain.
Unknown tasks retain their original tool rules.

The v47 strict host gate, Android compilation and original-signature assembly
passed on their exact source. Acquiring a new operator owner stopped at the busy
lock, so installation was not attempted. Those results do not qualify this
changed v48 source. New host, Android and actual phone results remain separate.

LFM3 now has a retained 20-request NPU execution baseline on this phone, but the
failed Notes workflow does not establish the best task model. See
[the model deployment review](docs/LOCAL-MODELS-20261110.md) for the measured
scope, model alternatives and MoE memory limits.

## v47 predecessor: responsive observations and checked task completion

The v47 predecessor is versionCode 47 (`0.47.0-local-observer-completion`), based on
v46 commit `59432f43633fc710a4c8843d77803bcdbf613ec6` and the observation worker
repair from `2dbb3b312748976b58b15a001ef1a02aef86e8bc`.

Blocking accessibility reads, bitmap work and evidence writes now use one
bounded observation worker. The main-thread owner can retire an expired request
while that work is blocked. Task, request and background-display identities
prevent a late result from becoming a new observation. A worker still doing
heavy work prevents admission of another task. This changes observation work;
it does not make all Android operations asynchronous.

The narrow Motorola calculator completion contract requires a fresh, local-model
action chain from the current input to the requested multiplication and its
observed result. The controller independently computes the expected product;
existing results, history rows and a model's success statement are insufficient.
Installed app identity and cleanup still gate completion. The existing Notes
create, save, list and reopen contract remains in place.

The selected phone profile remains the local LFM3-1.7B QAD Q4_0 NPU candidate,
8,192 context tokens and four helper threads. Model registration and code checks
do not qualify model quality or completed phone tasks. See
[the model deployment review](docs/LOCAL-MODELS-20261110.md) for current primary
sources, memory limits, alternatives and measured older failure timings.

Strict Java 8 host checks, Android compilation, signing, installation and actual
phone acceptance are separate results. This source record does not claim those
stages passed. See [OBSERVATION-WORKER.md](OBSERVATION-WORKER.md) and
[CALCULATOR-COMPLETION.md](CALCULATOR-COMPLETION.md) for implementation scope and
the supported completion evidence.

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
