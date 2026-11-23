# Ctrip form observation pairing

This narrow fallback addresses a completed full native screenshot-pair read whose
whole graph differs because a disjoint recommendation branch changes. It applies
only to an already-observed managed-profile Ctrip single-flight form with the
compiled version and base APK identity. It does not stabilize the first sample,
extend an observation deadline, retry an action, or complete a flight query.

The Service compares the two complete raw native censuses through
`NativeActionSnapshotCheck.Node/Snapshot`. Those immutable value constructors
require the exact field sets, actual visited count, every parent and child slot,
known hidden IME, complete window census, and zero omissions. Retained UI rows
and bounded diagnostics cannot act as a complete census.

`NativeCtripFormObservation` checks the complete envelope and profile identity;
the complete form subtree and all containing ancestors; route, literal displayed
date, passengers, trip type, economy selection, query/date references and bounds;
and roles across the entire tree. Every added, removed, or changed node must fall
inside one dynamically derived, fixed region disjoint from the protected form.
Unknown input/IME/scroll metadata, an overlapping region, a protected change,
or any unclassified difference rejects the fallback. No numeric tree path is an
allowlist.

The ending target/unknown event counters are frozen immediately after the second
complete read, before diagnostics, snapshot construction, or comparison. Known
target events during that read are admissible only when the complete pair passes.
A subsequent event cannot be included by refreshing this counter. Unknown events
remain a veto. The original post-persistence fresh-window and publication event
fences still run.

Published evidence uses `pre_encoding_form_pair_history`, includes the complete
classification and start/end event watermarks, and explicitly claims neither
whole-tree equality nor simultaneous pixels and accessibility values. The actual
first graph and screenshot are retained; no graph, selected node, capture age,
model run, query history, or action is fabricated. All later action checks,
including the final fresh selected-node ancestry chain, are unchanged. This
fallback does not repair a descendant becoming invalid during an action's fresh
complete traversal.

## Host checks

Run `run_host.py --source SOURCE --output NEW_OUTPUT --java-home JDK17 --json-jar JSON_JAR`.

- `run_pure_host.py` compiles the actual comparator and complete value types.
  `FormPairHostTest` uses clearly synthetic complete censuses and the unchanged
  existing action-test builder. It covers protected fields and identities,
  full difference classification, overlays, unknown metadata, omissions and
  parent/child closure. It constructs no action Intent.
- `run_observer_host.py` executes the production observer and read-only adapters
  with explicit host Android/clock/window/pixel ports. It separately exercises
  the event fence, capture/publication ownership and rejected evidence disposal.

These are host protocol tests. They do not claim Android execution, local model
inference, successful flight results, or absence of future final-action staleness.
The existing observation-pipeline template gains only an explicit fail-only
port for the new optional helper; its legacy cases retain their original scope.
