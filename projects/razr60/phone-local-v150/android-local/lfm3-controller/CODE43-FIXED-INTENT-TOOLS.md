# Code43: two fixed local tools chosen by the phone model

VersionCode **43**, versionName **0.43.0-local-fixed-intent-tools**. The source
baseline is frozen v42 commit `3c4894ad4c7958c94741b0e7e6709380d6ac8ff7`.
This is a new ordinary-controller vertical slice. Full Java 8 release gates,
Android compilation and actual phone task qualification are pending at source
freeze. Passing host fixtures does not establish note persistence or useful
search results.

## Why this changes the task path

Earlier ordinary model tasks spent many local inference rounds navigating Notes
without reaching a usable text editor. Actual installed resolver evidence shows
that Moto Notes declares a public plain-text SEND entry at
`com.motorola.stylus/com.motorola.stylus.note.text.TextNoteActivity`. No installed
CREATE_NOTE resolver was found. The installed browser resolves WEB_SEARCH at
`com.zui.browser/com.lenovo.browser.BrowserActivity`. This change uses those
specific public Intent contracts, with independent runtime eligibility checks.
It does not invent a provider, database insertion API or automatic save API.

The unmodified natural-language OWNER reaches the existing local model request.
The model chooses one structured tool and its content under a new explicit
`hepta.observed-action-gbnf.v6-fixed-intents` grammar. There is no host-side
selection of the action or extraction of the note body/search query from OWNER.
Existing native prompt, system, grammar, raw output and worker/task receipt
validation remains in place. The controller parses that exact raw output and
binds the latest actual model run, including a format-repair run, to dispatch.

| Model tool | Only model content field | Fixed Android request | Requested next observation |
|---|---|---|---|
| `notes.create` | `text` | Explicit Moto TextNoteActivity; ACTION_SEND; `text/plain`; EXTRA_TEXT | `draft_opened` |
| `web.search` | `query` | Explicit installed browser activity; ACTION_WEB_SEARCH; SearchManager.QUERY | `search_opened` |

Both actions also require the current observation ID and the exact supplied
`app_label`/`package` pair. The model cannot specify a component, action string,
MIME type, URI, flags, title, extras map or recipient. Each payload retains its
original Unicode and whitespace, must contain non-whitespace content, cannot
contain NUL or unpaired UTF-16 surrogates, and is bounded by 1,024 Unicode scalars
and 4,096 UTF-8 bytes. The existing generation/context admission limits still
apply; those size bounds do not promise generation of an arbitrarily long note.

## Authority and fixed dispatch

The two tools participate in the existing OWNER tool allow/deny policy. An
explicit `find_app`-before-`open` prerequisite cannot be bypassed by a semantic
tool. Prior v3/v4/v5 parser and grammar entry points do not acquire new actions.
The old restricted qualification-scope mode does not publish or dispatch these
new tools; its package/UID/source-file policy is unchanged.

For an ordinary task, trusted code inspects the compiled component through
PackageManager before advertising a capability and rechecks it before dispatch.
The exact activity and application package, target UID, enabled/exported state,
declared public action/MIME filter and any activity permission are checked.
Only ordinary installed user-0 app identities are supported. A package update
or label/UID/permission identity change between the supplied frame and call
refuses dispatch. Model text never supplies those eligibility facts.

Foreground uses the ordinary application's Android startActivity. Background
uses the existing authenticated socket, immutable selected package allowlist,
session generation, virtual display, TTL and cleanup protocol. The broker checks
activity permissions for its configured **ordinary app owner UID**, independently
of its own privileged identity. It reconstructs the same fixed Intent and passes
the actual MIME type as `resolvedType` to the framework. It checks that the target
package has no task on another display before and immediately at dispatch; there
is no main-display fallback or task relocation. Existing display flags, IME
policy, independent ordinary-app readback and release checks remain.

The narrow wire extension has exactly nine fields for the two new operations:
the existing version/request/generation/deadline/op fields plus package,
target_uid, payload and attempt_id. Existing operations retain their exact old
field sets. Unknown, duplicate or arbitrary Intent fields are rejected.

## One attempt, durable evidence, honest outcomes

Each tool is available at most once in one owner task. Before an Android or broker
call, the task-owned ledger consumes the capability and writes/fsyncs a new private
`fixed-intent-NN-attempt.json`. NN is the attempt ordinal, not the step number.
The journal binds task/model run/observation, source package/window/display,
background generation, complete payload hash and actual installed target identity.
If the journal fails, no call occurs and the same running task cannot re-arm it.

The ledger enters `unknown` immediately before the effect boundary. Only an
accepted ordinary Android return or fully checked broker reply yields
`launch_accepted`. Exceptions, cancellation after a possible effect, timeout and
lost/mismatched replies never cause an automatic retry. The broker additionally
consumes each fixed operation once per session. Existing request-ID replay
protection, task/process leases and background recovery barriers remain.

`step-NN-action.json.fixed_intent` and terminal `fixed_intent_attempts` preserve
the attempt and result. The executed native action envelope and original payload
remain in the existing model/action records. A late callback retains a possible
dispatch but cannot borrow a replacement task's authority.

`draft_opened` and `search_opened` are **requested observation labels**.
`launch_accepted` is not proof that the editor consumed the text, the note was
saved, or search results were found. Both `goal_independently_verified` and
`saved_or_search_results_verified` are false in these dispatch receipts. Later
ordinary model UI actions must inspect the editor/results. No automatic save,
order, payment or booking adapter is included.

## Required phone acceptance

Use a new versioned acceptance run; preserve all earlier v41/v42 results.

For notes, require the original native request/grammar/raw-output binding and
exact model `notes.create` payload; the matching durable attempt and actual target
identity; a subsequent observed editor containing that complete text; real save
and list navigation; then reopening the resulting note with the same unique
marker and complete body. Absence of a separate `type` action is expected for
this path. A launch, text echo, model `done(success)` or a pre-existing note is
insufficient.

For flight/product lookup, `web.search` only initiates a query. Actual result
content must be observed and reported with its source and query context. Opening
a browser is insufficient, and this code does not claim inventory, current fares,
availability, an order or a booking. The model remains local; a browser may use
its own normal network access to retrieve the requested public information.

## Validation boundary

Focused host tests execute the real parser/grammar, complete controller, extracted
actual service dispatch, shared Android adapter and real BackgroundSession with
explicit Android/model IO fakes. They check natural Chinese OWNER propagation,
model-selected exact payload and repair-run binding, fixed Intent fields, ordinary
UID permission denial, changing target UID, durable-write failure, cancellation,
unknown calls, no retry, public-filter eligibility, strict wire fields and reply
binding. Independent GBNF recognition covers allowed payloads and rejected
component/URI/extra/label/observation changes. These tests do not perform native
inference, invoke Android or prove real saved content.

The existing 92 host records retain their names and relative order; two focused
records are added. Native/model/sampler sources, runtime pins, existing signing
key, external-model behavior and the original phone acceptance helpers remain
unchanged. Separate v6 acceptance must validate the new schema explicitly rather
than relabel it as v5 or overwrite an old false result.
