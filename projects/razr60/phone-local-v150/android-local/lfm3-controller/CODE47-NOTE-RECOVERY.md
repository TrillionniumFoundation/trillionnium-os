# v47: observed list recovery and bounded dispatch facts

Base source: `59432f43633fc710a4c8843d77803bcdbf613ec6` (v46).
Candidate manifest: versionCode 47, `0.47.0-local-note-recovery`.

## Reproduced product defect

Ordinary v46 Notes task `3ac1287814414567b655b42030d9911b` used the local
LFM3 model. Step 1 correctly dispatched the existing `notes.create` entry with
the immutable literal body and observed that body in the actual editor. Step 2
opened Hepta; step 3 opened Moto Notes and observed its real list. The current
`n11` executable card contained the complete requested accessibility summary,
and its original child-source fingerprint matched its observed parent binding.

The v46 completion gate required a direct `back` or `click` transition from
editor to list. The app-switch route did not satisfy that extra condition, so
`list_observed` remained false and the phase restriction removed every click.
The OWNER required returning to the list, not a particular navigation API.
The model continued switching apps, reached 20 steps, and failed with cleanup
known. No model click reopened the item; this task remains failed.

`tests/notes-task-phase/fixtures/v46-notes-recovery-trace.json` contains 15
selected original files, each with original byte count, SHA-256 and verbatim
UTF-8 contents. Fixture SHA-256:
`c253146ad4556d8448df87905f0529846b9fa80b489bdf59c94840afb137ad01`.
The original wrapper RESULT SHA-256 is
`dbbc2a2afe822e91fc585d7c033b72bbbff16f76c0396225d2d171a815ffddb3`.
The fixture preserves the original failed status and missing reopen evidence.

## Recovery rule

`TaskCompletionGate.observed` can record `post_create_observed_list` only after
this same task and immutable contract have a validated fixed-entry receipt and
an actual complete editor-body observation. Installed identity must remain
available and uninvalidated, and the observation must retain the original
display/background generation. The unchanged `NotesCompletionEvidence.list`
provider must find one unique executable full-body item in the actual Notes
list. Its original source, complete raw-text hash and parent signature checks
are unchanged. A marker substring, navigation acknowledgement, model reason or
completion claim cannot supply the missing evidence.

The additional proof records the actual list observation ID, earlier body
observation ID and full existing list-provider evidence. Its step is zero and
model run is null because it records an observation, not a new dispatched action.
The existing direct editor-to-list proof remains available. Every actual frame
used for a new controller prompt is observed by the completion gate, including
a reobservation following a stale or undispatched proposal. Existing after-action
observations continue through the same completion action path.

Recovery is not completion. The model must subsequently choose the current
proved item's exact node ID and projected label. Only an accepted, dispatched,
nonstale click followed by the full editor body proves reopen. A stable final
model `done` claim, installed-identity rechecks and cleanup gates are still
required. Reopening an editor by another route cannot substitute for this click.
The phase restriction only intersects existing current-frame tool eligibility;
it cannot add a missing or unauthorized node, replay `notes.create`, rewrite a
body or dispatch an automatic action. Unknown contracts keep their original
rules and do not acquire this Notes workflow.

## Reason feedback

The saved reasons repeatedly copied a prior phrase and filled all 96 allowed
Unicode characters. The earlier SYSTEM instruction required reciting the last
dispatched step before the next action, and `last_model_decision` fed the previous
free-form reason back into the next input. This created an avoidable repeated-text
anchor; it does not establish that changing it alone solves model planning.

SYSTEM now asks for one short current-observation-to-next-action rationale,
without reciting OWNER body or prior reasons. `LastModelDecisionProjection`
retains its original task/run/observation/outcome validation and projects only
source, step, action, target package and the fact that it was dispatched. It
does not project prior reasons, historical node/label pairs, tool grants or
completion claims. Original raw/model/action receipts retain their reasons.
OWNER, complete structured event history and current observations remain intact.

General self-app opening and app catalogue ranking are unchanged. The test
body's `Hepta` marker can cause the catalogue ranker to prioritize the Hepta app
label, making an irrelevant app switch more likely. This version must recover
from a real observed detour; it does not hide that case by changing the marker
or silently banning explicit user requests to open Hepta.

## Verification scope

The completion runner includes the saved failed prefix through the actual
observation bridge and completion/phase/prompt code, negative task/receipt/app
identity and source cases, same-item click/stability checks, grammar acceptance
and rejection, and a controller integration with explicit Android/model IO fakes.
Any hypothetical action after the recorded failed prefix is labeled synthetic;
it never becomes a fabricated phone receipt. The original fixture is checked
again for unchanged bytes.

Existing phase, source-provenance, text-only-click, authorization and exact-input
tests remain in the full host suite. Strict release8 tests, Android compilation,
signing and real phone task acceptance are separate gates. This source change
does not claim those stages passed, alter native/model profiles or establish
general shopping, flight-search, background or arbitrary-instruction success.
