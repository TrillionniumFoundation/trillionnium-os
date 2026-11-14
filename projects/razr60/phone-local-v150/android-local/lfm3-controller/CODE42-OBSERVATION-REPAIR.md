# Code42: observed state and unlabeled control metadata

Candidate `42 / 0.42.0-local-observation-repair` is based on v41 commit
`ebd495d93660f24a3229fe91fec25508c546fad4`. It merges three independently reviewed
local overlays. Complete strict host checks, Android compilation, installation
and ordinary v42 task acceptance remain pending at this source freeze.

## Recorded failures motivating the changes

In v41 task `4061f26e5821434c8bdc483a0a99cc7d`, a background Calculator session
created display 6 and dispatched two Nano/NPU actions. After the multiplication
click, the same observation's screenshot showed `17×`, while its accessibility
tree still exposed input text `17`. The next model request was a whole-field
replacement with `29`. No third action was dispatched: the refreshed node differed
from the cached signature, and the client incorrectly reported a permanent
qualification-scope failure instead of a stale observation. The task failed;
its original result and cleanup evidence are preserved.

The same run's display-policy acceptance remained false. All 102 active system
samples printed `FLAG_TRUSTED` but omitted the two own-focus flag names from the
display's text description. The broker had read numeric `Display.getFlags()`
value 6272 and checked the required flags and hidden-IME policy. A missing printed
name is not independent evidence of a missing bit. The old acceptance result is
not retrospectively changed.

In v41 Moto Notes task `ca52dec778e44c63a8939e5c9f8c62aa`, the step-four observation
contained an unlabeled clickable `n5` with resource ID
`com.motorola.stylus:id/fab`. The actual prompt reduced it to an empty label,
bounds and `c`; both compact nodes and text metadata omitted the resource ID.
The model chose a different visible entry, and the task eventually failed without
typing or saving. The saved observation and actual prompt are pinned in
`tests/observation-hints/PROVENANCE.json`. They identify lost input evidence;
they do not prove how a future model will interpret the resource ID.

## Fresh background observations and typed stale outcomes

The background root is refreshed before metadata is sampled, and each visited
descendant is refreshed before its body is read. Noninteractive child text used
as a control label is also refreshed. A failed refresh or disappearing subtree
does not publish a partial old frame. Existing traversal bounds, stability
checks, screenshot checks and fixed observation deadlines remain in place.

Immediately before an effect, a content change inside the same validated node,
package, window and display produces `accepted=false`, `dispatched=false`,
`stale=true`. The existing controller obtains a new observation and calls the
model again, with the original two-retry limit. It never substitutes the refreshed
node into an old action and executes it. Invalid target pairs, changed authority,
foreign packages/windows/displays and retired leases remain terminal failures.

An already consumed submit attempt is not rearmed by this path. Its inner error
handler retains consumption and actual dispatch evidence, with `stale=false`.
The existing `type` contract remains a complete field replacement, without an
implicit Enter action. Foreground sampling is unchanged by this background fix.

## Structured display policy evidence

The broker reports actual framework flags, the runtime `android.view.Display`
constant values, required/forbidden masks and actual `getDisplayImePolicy` value.
These values are generation/display/time bound. The existing creation flags and
policy checks are retained and checked against a shared numeric contract.

The ordinary app independently uses public `Display` getters to verify the same
display ID, name, validity and flags. Its receipt binds the task, generation,
application UID/PID, boot and authenticated broker request ID. A failed read clears
old proof; an actual flags mismatch is retained for diagnosis and rejects action
admission. Only the broker reads the hidden IME policy and constant values: this
is not a claim of two-UID independent IME verification.

The separate r9 device verifier must retain independent system display identity,
focus, target isolation and cleanup samples while consuming the new strict numeric
evidence. No textual omission is simply promoted to a pass, and no old r7/r8 result
is rewritten.

## Unlabeled control structure in the model input

`screen.unlabeled_controls` contains raw observed `view_id` and `class_name`
properties only for empty-label nodes that are in the final shown node set and
still have a post-policy action. The sidecar has an explicit observed-data source,
at most 16 entries, and 96-UTF-16-unit property prefixes with safe ellipses and
truncation/omission indicators. It does not turn a resource ID into a name, purpose
or permission. The original `node_label`, `node_id`, target-map signature and tool
grammar are unchanged.

Metadata is escaped within `UNTRUSTED_DATA`. The short system explanation and all
added JSON bytes enter the existing full prompt budget and native admission path.
The regression reconstructs the recorded step-four screen through the actual
prompt builder. Missing recorded class names stay empty. For that fixture, two
structural hints add 273 UTF-8 bytes to the otherwise identical prompt data; the
system explanation is budgeted separately by the same existing estimator.

## Local validation and remaining gates

The background freshness overlay passes 119 actual-class cases, including the
original 88 and 31 added snapshot/dispatch/controller cases. Isolated regressions
that disable root refreshing or restore stale-to-scope wrapping fail as expected.
The display overlay passes 66 client, 57 protocol and 17 extracted snapshot cases.
The observation-hints regression passes 75 assertions over recorded evidence,
bounded metadata, prompt budgets, exact target identity and malicious/unauthorized
variants. Existing prompt admission, owner and IME tests also pass in supplemental
local compilation. An independent reviewer found no blocking source issue.

These use explicit host Android/model IO fixtures and the available Java syntax
and class-target checks. They are not an Android runtime, native model or phone
business test. The unified strict plan preserves all 92 existing top-level gate
names and order and 172 Android compiler inputs. Only a subsequent complete build
and ordinary device task can establish v42 runtime behavior.

The model defaults, native inference, GPU/NPU configuration, root command surface,
owner restrictions, payment policy and recovery/journal protocols are not expanded.
No task-specific success oracle or hardcoded Calculator/Moto action is introduced.
