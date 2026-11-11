# v44 completion evidence

Version 44 (0.44.0-local-completion-evidence) is based on frozen v43 commit
c76be7243b70e2142c6c87733c292c6df0d88652.

## Problem and implemented boundary

The v43 controller treated an authorized, stable done(status=success) as a
completed task. A first-step statement without a search and a statement that a
visible Notes draft had not been saved could both reach that terminal state.
Tool permission and launch acceptance do not establish the owner's goal.

TaskCompletionGate is a separate, non-dispatching verifier. The existing v6
action codec, generated grammar, SYSTEM text, tool authorization, once-only
ledgers, native runtime, sampler, model choice and background broker are unchanged.
It cannot grant an action, select a component, change OWNER, or repeat an intent.

The exact OWNER text and existing TaskAuthorization bind an immutable completion
contract. The local model still chooses every tool and creates the action's text.
No controller-generated note body is sent in place of a native answer.
The completion object is included in the ordinary prompt and its full budget;
it does not erase or replace task_authorization.

## Supported Notes contract

The conservative recognizer accepts a single literal note followed by explicit
save, return-to-list and same-note-reopen instructions. The documented form is:

> 打开 Moto 笔记（com.motorola.stylus），新建一条笔记，正文完整写入以下一行：<literal one-line body> 保存这条新笔记，然后回到笔记列表，重新打开它并停留在正文完整可见的页面。不要修改或删除已有笔记，不分享或发送。

The prefix may omit opening Moto Notes and its package suffix; optional 请,
一条/一个, 笔记/备忘录, documented comma/colon punctuation and the final
no-modification/no-sharing clause are recognized. A second form uses
正文为：“<literal one-line body>” before the same save/list/reopen sequence.
Unconsumed clauses, negated forms, multiple goals and unsupported forms remain
unverified. This is a bounded goal recognizer.

A positive observation chain requires all of the following:

- An ordinary installed Notes package identity, full base/split APK hashes,
  version and UID captured read-only with the existing installed-file verifier.
- One actually dispatched and accepted native-model notes.create whose exact
  payload equals the immutable owner's body. Its durable consumed attempt,
  task/run/before-observation, source package/window, display/generation,
  installed target and all ordinary-caller eligibility fields must match.
- A new visible Notes editor body after that request, with complete input-text
  hash and actual observed editor context.
- A dispatched back or click from the matching editor to an actual Notes list.
  The list must have the observed list title/pager, no editable editor or empty
  list notice, and one enabled clickable item whose complete text/label equals
  the expected body.
- A subsequent dispatched model click bound to that same current list node ID
  and projected label, followed by the full body visible in the editor.
- A stable final done observation, unchanged app installation, valid terminal
  native receipt and known model/background cleanup.

Current list matching does not infer descendant ancestry from bounds. A combined
date/title/body label, truncation, duplicate visible candidates or absence of a
complete body item remains missing evidence. Real childText sources could support
a future exact descendant proof after actual app fixtures are collected; v44
does not introduce that untested relaxation. The successful list/reopen test
fixture is synthetic, so host passes do not establish phone Notes usability.

The pinned Moto Notes base APK may present the body with exactly 40 trailing LF
characters. Only this one captured APK SHA permits that visible form; other
padding, split sets or unverified identities are refused. Raw observation text,
its full hash, raw_exact=false and trailing-LF count remain separately reported.
No trimming rewrites the original data. Persistent storage bytes and a new
database-record identity are explicitly not verified by this UI observation chain.

## Success claims and bounded continuation

Every valid model success claim remains in raw model evidence and
model_reported_success. It is not automatically a business verdict.

On the first unverified success claim the controller records a completion check
with structured missing reasons, performs a new observation, and invokes the
same local model again. The original task, scope, tool ledgers and native worker
remain bound. Nothing is automatically dispatched or replayed.

A second rejected success ends the task as partial. The existing 20-step,
480-second task limit and cancellation/cleanup rules remain unchanged.
Explicit model partial/failure can exit immediately. A late installed-app
identity change or invalid native cleanup receipt removes verified completion
without erasing the original model statement.

The prompt exposes only the relevant method stages: Notes stages for the
recognized Notes goal; web_query_dispatched for explicit web.search goals;
neither for unknown read-only goals. Unknown goals do not gain a write requirement.

## Search and unsupported goals

web.search can prove only its exact bounded query dispatch. No flight/product
result provider is added here, so opening a search remains partial, even if the
model calls it success. Other goals without a complete supported verifier also
remain unverified/partial. Existing read-only tools remain available under their
original OWNER authorization; no effect count is a universal success rule.

Results and durable sessions record completion_verified, completion_evidence
and raw model claims separately. goal_independently_verified follows the
supported observation-chain verdict, with the provider's stated limits retained
in completion_evidence. Model summary text is preserved as model_done_summary;
the ordinary completion message comes from the verifier.

## Validation and recovery provenance

The exact v43 baseline contains 480 source files. Its sorted inventory SHA256 is
d4a3a7796a518dfe6291177a80d81a225741c0a958a4d3ded544dfb25bde875a.

A cloud workspace interruption occurred during local checks. The baseline was
recovered from its exact Git objects and reproduced the same full inventory.
The reviewed completion/controller/provider identity is verified after recovery;
old test records lost with that transient workspace are not regenerated.

New tests exercise actual production classes with explicit Android/native I/O
fakes, including first-done continuation, full note observation sequence,
draft-only refusal, wrong item, cross-domain binding, exact attempt receipts,
read-only zero-effect goals, cancellation, post-close APK change and invalid
native close receipt. Six pinned historical Notes files cover the real 40-LF
editor representation and historical absence of list/reopen proof.

The main host plan retains all original 94 gate names and order and adds
notes-completion-evidence and task-completion, both requiring Java 8 API release.
All six observation fixtures are included in the host-input hash inventory.
Strict host execution, actual Android compilation/signing and phone acceptance
are separate receipts; this document makes no phone-pass claim.
