# Code10: exact label-first target pairs

Version `10` / `0.10.0-local-labels` changes the node-action protocol to
`hepta.observed-action-gbnf.v3-label-first`. A node click, type or scroll first
emits `node_label`, copying the exact visible label supplied in the current
prompt, then its original `node_id`. GBNF enumerates each complete pair. The
parser, controller policy and service all reject an unmatched pair; none use
the model's reason to choose, repair or substitute a target.

One immutable `ObservedTargetLabels` map is built from the same bounded prompt
projection. It preserves the existing 36 UTF-16-unit display limit, without
splitting a surrogate pair, and binds the observation, package, IDs and labels
with a length-prefixed UTF-8 SHA256 contract. Empty and duplicate labels still
retain explicit IDs. The service receives that original map and executes only
the original `currentGraph.refs.get(action.nodeId)` after the existing complete
window, signature, freshness, cancellation and persistent-destruction checks.
No lookup from a generated label to a different live node is performed.

The model receipt records the small pair contract. The host verifier admits the
new schema only when it can recompute the contract from the exact native input
prompt, verify that prompt's native/App SHA, and check the raw output pair and
field order. Existing v1/v2 grammar validation is preserved for earlier
evidence; historical results are not relabelled.

Native sources, model profiles, sampling, inference, full-file SHA checks,
repeat-guard semantics and the code9 persistent-action policy are unchanged.
The receipt addition does not alter native invocation. This version contains
no MNN engine or visual-model integration.

The targeted host qualification includes actual generated-grammar recognition,
Java parser/policy contracts and tampered prompt/receipt rejection. Host tests
and a real Android rebuild do not establish that the model now selects the
correct target. Code9's descendant-label correction did not itself prove
calculator reliability. Device acceptance must still demonstrate real key
presses, application goals, cancellation/recovery and offline execution with
the frozen final APK, model and driver identities.
