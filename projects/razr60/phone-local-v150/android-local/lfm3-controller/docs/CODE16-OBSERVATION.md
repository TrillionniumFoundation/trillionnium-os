# Code16 bounded observations and exact tool capabilities

This candidate contains the reviewed Code15 controller merge r2 and release
metadata only. No model or runtime profile is selected automatically. Existing
private configuration is preserved by an ordinary same-signer package update.

## Observation stability

A new observation requires two complete observed window/graph/truncation states
that agree at least 200 milliseconds apart. A fixed two-second settle budget is
inside the existing observation and task deadlines. A typed transient missing
active root can be retried inside that same budget; permission and other errors
are not converted into success. Cancellation is checked while waiting. The
same capture owner/token governs callbacks, and the complete graph is checked
again after PNG encoding, filesystem publication and hashing. Two equal samples
do not prove that the screen was continuously static between them.

All existing execution-time freshness and locked-device checks remain active.
This does not ignore unrelated clock changes during a long model invocation or
remove whole-graph target protection. Stable observation is not evidence that
a model correctly understood the page or completed the requested goal.

## Tool semantics and recent evidence

The tool description explains that type replaces a complete text field through
ACTION_SET_TEXT, emits no keyboard keys or submission, and that matching text
readback does not prove business-level acceptance. The owner instruction's
method requirements still govern the task. Clickable does not mean a keyboard
key. These statements do not choose an action or supply a task answer.

The recent-history projection retains the same last-six selection and order,
original owner, applicable observed false/null/empty values, rejections and
read-only app-discovery query/offset. It omits inapplicable default fields.
It does not reconstruct or invent missing prior evidence. The original
heuristic prompt budget and exact native token guard remain unchanged.

## Scroll capabilities

Each exported node has one immutable observation of its actual action list.
Only observed forward, backward, up, down, left and right actions grant those
specific directions. Unknown action lists and known empty lists grant none;
isScrollable alone does not grant an action. Raw observations retain the
unknown-versus-empty distinction. The compact prompt map lists only nonempty
confirmed sets, and GBNF binds each node label, original ID and actual direction.
The parser and existing dispatcher independently enforce that binding; the
dispatcher still checks the current node's real action before performing it.
No direction is translated into another and no gesture fallback is introduced.

The scroll capability fingerprint participates in target and snapshot freshness,
while the existing app-tree and IME progress semantics remain unchanged. Old
phone records without action lists cannot establish which directions were
supported. New on-device evidence is required.

## Preserved scope and qualification

No INTERNET or WAKE_LOCK permission is added. The 480-second task budget,
20-step limit, native deadlines, stop/session recovery rules, models, all native
sources and compiled runtime pins are unchanged. Native tool-call, thinking,
visual control and wake-lock experiments are not merged. The separate MNN
endpoint remains model-only and uses the unchanged Code15 loader.

Host contracts and a real signed Android build are distinct from phone
acceptance. A fresh final candidate must be verified for task effects, scrolling,
stop/restart, background behavior and disconnected-network operation. Existing
failures and earlier candidate evidence remain separate.
