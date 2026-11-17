# Compact action output contract

The generated action grammar permits zero or one ordinary ASCII space at each formatting boundary and a reason of 1–24 Unicode scalar values.
The controller prompt uses the same bound and requests one short observation that supports the next action.
Reason remains before action. Node label remains before its paired node ID, and application label remains before package.
Every emitted action still requires a complete JSON object.

This is an output format restriction, with one general prompt clarification: native_app.phase=home_search describes a query entry; suggested terms in that entry are not evidence that the user's query was entered or results were obtained.
native_app.result_ready=false still means the result condition is unmet.
The prompt does not supply a product answer or select a tool on the model's behalf.

## Unchanged authority and payloads

OWNER, task authorization, observed package/observation/label-node pairs, fixed intents, completion choices, freshness, ownership and background-display checks are unchanged.
No field, tool, coordinate fallback, partial JSON recovery, automatic replay or output-token increase is added.
ActionDecision's existing parser and historical reason projection remain unchanged so original stored decisions remain readable.
The generation-complete gate remains required before the existing parse and dispatch path.

The 1–24 bound concerns reason only.
type text, exact Notes body, fixed-tool payload, queries and done summary retain their existing respective limits.
Whitespace inside strings remains content and is not stripped or normalized.
A 1024-character body or summary is not promised to fit within 256 output tokens.
The change does not make wrong page reasoning correct, guarantee completion, or establish a token or latency saving.

## Tests and evidence scope

The Java host test emits actual production GBNF for both existing test scopes and an explicitly authored synthetic query-entry scope.
The independent test recognizer accepts compact complete choices and checks whitespace and Unicode/escape bounds, unchanged label-node pairs, absent success authority, and incomplete JSON rejection.
The real ActionDecision parser separately receives complete and truncated synthetic strings.
Existing parser, owner, fixed-intent, Notes payload, completion and budget regressions remain required.

These are host checks, not a native SDK grammar or phone model test.
Any later model comparison must use the same prompt/domain and current background ownership, retain complete native and application receipts, and report actual output tokens and elapsed time.
Original failed phone outputs are private host evidence; they are not repaired or added to these public fixtures.
