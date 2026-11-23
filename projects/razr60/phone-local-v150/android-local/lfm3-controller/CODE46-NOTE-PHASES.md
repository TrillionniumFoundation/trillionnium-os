# v46: new-note action restrictions, source proof and LFM3 admission

Base source: `c0195c1d7708c76dcd18dbb31083f1b5c1c5123f` (v45).
Candidate manifest: versionCode 46, `0.46.0-local-note-phases`.

## Observed failure and independent evidence

The archived ordinary v45 Notes task
`883a2a7d9abd4a25aa44c7e5da21c5be` first replaced the body of an existing test
note containing a v43 marker and audio attachment. The replacement was actually
dispatched and its complete text was read back. Subsequent decisions clicked the
body, title and category in a two-state loop. The task never used `notes.create`,
`back` or `done`, and timed out without a verified new-note/save/reopen chain.
The dependent completion flags did not establish that no body was visible.

`tests/notes-task-phase/fixtures/v45-notes-trace.json` preserves original JSON
bytes and each original SHA-256 for selected steps. Its archive provenance is
`37c00e6f8624d6a8fbf652af85e99c7356f03870d2a5ccaf152169681fd065cd`.
This is a saved failure replay, not a new phone run.

The later manual public-launcher observation found two test notes in the list.
`manual-notes-list.xml` is the exact saved XML with SHA-256
`56b5f62e246a9945c1c4c0e9eea1273eb44152014d3d272cd8769776185cb7db`.
Each clickable `note_item_content` card had no own text/description, and its
noninteractive `contentRoot` contained `note_title`, `note_date` and
`note_summary`. The summary accessibility text was complete even though the
screen image visually clipped the line. Opening this list manually does not
retroactively complete the failed v45 task and is not model-bound save evidence.

## New-note domain

Only the already recognized, anchored literal Notes save/list/reopen contract
activates `NotesTaskPhaseGuard`. The service creates it from the same immutable
OWNER as `TaskAuthorization`; screen content, model reasons and model claims
cannot create or change the contract. Unsupported and read-only tasks do not
acquire a Notes workflow.

The phase projection intersects existing authorization, observed node
capabilities, text-only click eligibility and no-effect guards. It never grants
a tool or creates a target. The final immutable node domain is published only
after the prompt budget and grammar are constructed. Both controller checks
and every service authorization-before-dispatch check use that same task-bound
domain. Repair replaces its identity; lease retirement retires it. A legacy
service call without a published domain fails closed for the supported contract.
The phase lookup is inside the controller cleanup try/finally so service loss
before worker entry cannot strand the task.

Before a model-bound `notes.create` receipt and body observation, node clicks,
direct replacements and submit are unavailable. The supported workflow passes
its whole literal body once through `notes.create`; direct replacement/submit
remain unnecessary and unavailable throughout it. Both the emitted fixed-tool
grammar and dispatch guard require the exact immutable OWNER body. The existing
installed-target checks, ordinary permission checks, one-shot durable ledger
and no-retry-on-uncertain-dispatch behavior remain independent.

After the created body is observed, the model is told that its next goal is to
leave the editor and observe the list. `back` can first hide the IME, so a new
observation is necessary. No action is automatically selected or dispatched,
and accepted `back` is not a save proof. After the existing completion gate has
observed the list, only its unique proved item survives the click intersection.
Reopened-body and stable final `done` evidence are still required for success.

## Bounded remembered refusals

`SameStateNoEffectGuard` retains at most 20 confirmed no-effect action records
across observed states within one task. Records bind package, full app-tree
identity and known IME state. An unchanged accepted/dispatched/non-stale click
or open can add a record; a rejected, undispatched, changed or unknown-IME
outcome cannot. A new state has no invented refusal, but returning to a recorded
state retains its facts. Unknown current IME conservatively includes matching
tree refusals rather than claiming progress. Capacity failure never evicts an
old refusal. No static/shared task cache is introduced.

This addresses the observed forgetting of ineffective actions. It does not
claim that every cycle consisting solely of state-changing actions is detected.

## Complete accessible summary provenance

The existing own-text and nonderived-label list paths remain supported. A real
`derived` label cannot use the old full-label fallback, including when its only
text happens to be the title or date.

The additional Notes-specific path requires all of the following:

- The executable card is the observed `note_item_content` node, inside the
  already required all-notes pager, with no own text.
- The actual `ObservedChildText.collect` result is derived, untruncated and has
  complete bounded sources. It comes from actual noninteractive descendants;
  no display-coordinate ancestry is invented.
- The collector's captured root signature binds to the `NodeRef` app-tree
  signature carried by that same `PhoneObservation.Node`.
- Every source has a bounded canonical descendant path and valid identity/text
  hashes. There is exactly one `note_summary` source, its property is `text`,
  and its raw full-text SHA-256 equals the immutable complete body SHA-256.
- Exactly one executable list item matches the body.

`ObservedChildText.SOURCE` is now `visible_noninteractive_descendants.v2`.
Its fingerprint includes captured root identity, source resource IDs and source
completeness. The label formatting and its original visible-character spans
remain unchanged. When duplicate descendant strings are omitted by the existing
label deduplication, `sourcesComplete` is false; the provider conservatively
refuses them. Thus a body equal to a duplicated title/date may remain unverified
even when the app contains it. Historical/manual reconstructed results without
captured provenance do not receive synthetic signatures or complete-source
status.

Private observation JSON preserves `child_text_root_signature`,
`child_text_sources_complete`, `child_text_visited`, per-source `view_id`, and
`node_app_tree_sha256`. Completion records retain the selected summary source
path/hash and distinguish complete accessibility text from visual clipping and
persistent database bytes. Existing source and protocol binders must bind the
new raw observation bytes; they must not reinterpret old evidence as v2.

No app-private storage/provider access, new root permission or private Notes
API is introduced. Installed identity checks, editor exact-text/raw-hash rules,
the pinned 40-LF representation exception, display continuity, action/run/owner
binding, and ordered save/list/reopen completion transitions remain in force.
Delayed UI transitions still need actual qualifying controller observations;
a manual XML file cannot advance the live task state.

## LFM3 exact-token admission

The Java/C/Python LFM3 profile definitions now require exact native tokenization
instead of using a Java byte upper bound to reject complete task facts. The
existing formatted prompt is tokenized once, checked against the unchanged
context/generation reserve, and those same recorded little-endian `input_ids`
are passed to SDK generation. The host worker tests capture that actual call
argument and compare its bytes, count, hash and profile with the saved evidence.
Fake-SDK tests prove host wiring only; they are not real NPU/model acceptance.
Model hashes, context limits, templates, sampler pins and execution runtime are
not changed by this admission repair.

## Validation boundaries

The host suite includes the real saved failure replay, existing completion and
controller/service classes, old-editor grammar/postparse/dispatch rejection,
exact and altered create payloads, phase replacement/retirement, authorization
intersection, service loss before worker entry, unknown-task isolation and
cross-display refusal. The manual XML topology is passed through the production
collector and provider with explicit host Reader IO. Negative cases cover parent
borrowing, absent root proof, wrong text hash/property/resource ID, title/date
collisions, interactive/foreign subtrees, truncation and duplicate summaries or
items. Existing generic empty-edit/submit, scroll, text-only click and completion
tests remain separately exercised.

All new fixture bytes are included in the full host source-input inventory.
Strict release8 host, Android compilation, APK signing and device business tests
are separate receipts produced from the final committed source. Passing host
tests does not establish successful shopping, flight search, Notes persistence,
background operation or independence from the main display on the real phone.
