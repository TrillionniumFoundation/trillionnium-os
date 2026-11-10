# Code38: observed query-field IME submission

Candidate versionCode 38, versionName `0.38.0-local-ime-submit`, based on v37
commit `60cfbd525875cd8e948a97187c836fd965694afc`. This change does not select a
model, alter runtime configuration, expand qualification scope or add a broker
command. It has not been installed or tested on a phone by its implementer.

## Behavior

The ordinary controller uses action schema `hepta.observed-action-gbnf.v5-ime-enter`.
It adds `submit(node_label,node_id)` only when the current immutable observation
contains a same-package enabled, visible, non-password, focused editable node with
an actual ACTION_IME_ENTER and an explicitly observed query action label.

After NFKC, trim and Locale.ROOT lowercase normalization, the exact label must be
one of `搜索`, `搜尋`, `查询`, `查詢`, `查找`, `search`, `query`, `find`. Raw labels
and their full hashes remain part of freshness. This is a deliberately narrow
compatibility subset. `Enter`, empty/null labels, `Go`, `Done`, `Next`, payment,
order, send and generic confirm labels are not automatically invoked. A standard
TextView may expose generic Enter even with search-style IME options; such an App
can remain unsupported unless it provides a usable observed query action or button.
Resource IDs, owner keywords, typed content and model explanations do not relabel
an unknown action as a search action.

Android ACTION_IME_ENTER invokes the target editor's configured action; it does
not prove that an App performed a search or saved anything. An App can define its
own handler. The boolean return is not independently verified business success.
The v38 allowlist prevents this tool from defaulting to visibly labelled commit
actions; it cannot establish arbitrary third-party handler semantics.

The model cannot supply keycodes, an arbitrary actionId, displayId, text, shell
commands or coordinates to submit. Its only parameters are the exact current
node label/ID pair. V3/V4 parser and grammar entry points remain closed to submit.
`type` remains ACTION_SET_TEXT without an implicit submit, including for newlines.
Type permission does not grant submit; the Owner parser has an explicit new parser
identity and separate submit aliases. V37 app-discovery domain behavior is retained.

## Execution and isolation

Actual capability, focus and complete observed input hash are bound to node and
graph freshness. Null text or ill-formed UTF-16 cannot gain a submit capability;
valid text is hashed as exact UTF-8, without truncation or normalization.
The existing visible-progress predicate is unchanged: capability
or focus changes alone cannot become business progress. The final prompt's
`screen.submit_actions`, actual grammar and controller validation use the same
capability subset; the service independently refreshes and checks the real node.

Before and after writing the attempt journal, the service verifies the current
task, authorization, scope, observation, node signature, application window and
display. It calls only `node.performAction(ACTION_IME_ENTER.getId())`, with no
model-controlled Bundle. Background actions pass the existing node-required
VirtualDisplay/window/package/generation gate. Root broker protocol and IME_HIDE
policy are unchanged; no global Enter, keyboard gesture or foreground fallback
exists.

## Attempt and result evidence

Each task binds a fresh `SubmitAttemptGuard`. The conservative attempt key is the
task instance plus package and SHA-256 of the complete observed editable text.
At most 20 attempts can be retained. A consumed key remains consumed across waits,
fresh observations, focus/bounds changes, false API returns and unknown outcomes.
Entries are never evicted. This intentionally also blocks a legitimate repeat of
the same text in another field of the same App/task; stable field-specific rearming
is outside this change. A new user-started task is not an automatic replay.

Consumption precedes an fsynced `ime-submit-NN-attempt.json` in the task evidence
directory. The journal has schema `hepta.ime-submit-attempt.v1`, stage
`consumed_before_call`, task/model/observation/node/window/display/background and
complete input/action-label hashes. It does not falsely claim the platform call
has already occurred. If recording fails, no action is called and the key stays
consumed. After a durable journal the target is checked again; a late change can
produce a consumed but `not_dispatched` result.

Immediately before entering performAction the in-memory result becomes unknown.
The callback's `ime_submit` has schema `hepta.ime-submit-result.v1`, a consumed
attempt identity, `dispatch_attempted`, nullable `api_accepted`, and one of
`not_dispatched`, `accepted`, `refused`, `unknown`. Returning false after an actual
call is still an attempt. Throwing after entry is possibly dispatched and never
reported as a clean no-effect failure. Cancellation/retirement wrappers preserve
the original submit proof. Unknown/refused outcomes stop the current controller
path without automatic retry.

`result.json.submit_attempts` retains the complete task ledger independently of
normal step callbacks. A durable pending journal survives the dangerous interval
where performAction might have happened but the callback has not returned. Startup
does not replay it. `goal_independently_verified` remains false; search results or
saved content require separate actual-App acceptance.

## Verification

`tests/ime-submit/run_host_tests.py` runs the real pure classes, emits actual GBNF
for an independent recognizer, and executes the extracted production service plus
full controller with explicit Android/package/inference IO fixtures. It covers
query-only labels, independent Owner permission, legacy schema rejection, full-text
and label freshness, durable pre-call consumption, false/unknown/late callback
results, repeat exclusion across wait, exact window/display checks and normal
type/submit/wait control flow. The fixture's display metadata is not a real Android
VirtualDisplay or main-screen isolation test.

The default full host gate keeps `--release 8 -Xlint:all -Werror` and includes this
suite. The development executor only provides supplemental source/class-target-8
validation on a stripped newer JDK; Java 8 API qualification, Android compilation,
real native inference and real foreground/background App effects remain distinct.

Python acceptance checks v5 against the exact native-hashed prompt, not mutable
receipt schema alone. A successful submit effect must match the same observation's
node capability/full-text hash, current window/display/background generation and
the durable attempt journal. Duplicate attempt IDs or same-package/input consumption
cannot be counted as independent successful effects.

Official API background: https://developer.android.com/reference/android/view/accessibility/AccessibilityNodeInfo.AccessibilityAction#ACTION_IME_ENTER
