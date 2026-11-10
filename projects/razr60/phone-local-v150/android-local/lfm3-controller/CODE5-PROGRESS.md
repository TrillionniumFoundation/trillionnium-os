# Code 5 progress and existing repeat guard

This candidate starts from frozen code 4. It changes progress-field semantics and
the visibility of an already rejected repeated `open` action. It does not supply
the planner with an app-specific navigation policy or choose a replacement action.

## Observed progress

`recent.window_changed` exposes the existing before/after observation-tree
comparison. It does not prove a navigation goal was reached. The old
`target_foreground_confirmed` field is named `exact_package_match`: it only compares
the requested launch package with the observed package string. A false value does
not establish launch failure. `dispatched` remains a separate fact. No relation
between different package names is inferred.

## One unchanged dispatch predicate

`RepeatActionGuard` preserves the code 4 action identity exactly: action, package,
node id, coordinates, direction, typed text, discovery query and offset. Observation
id and explanation do not change effect identity. An action is rejected only if
its key equals the preceding effect key and the current tree equals the recorded
unchanged after-tree. The controller still checks this predicate before dispatch.

The recorded state is updated at the same point as code 4, after an accepted
action and a fresh after-observation. A stale/rejected request does not update it.

| Transition | Preserved behavior |
|---|---|
| First open | No repeat restriction |
| Open changes the observation tree | No new cooldown or repeat restriction |
| Open leaves the tree unchanged | Same open on the same tree is rejected |
| Current tree differs from that unchanged tree | That repeat condition does not match |
| Read-only `find_app` | Prior repeat state is retained |
| `wait` | Prior repeat state is cleared, as in code 4 |
| `home`, `back`, click, type or scroll | Prior key is replaced by that action's key |
| Ordered open → home → open | Second open remains available |

## Candidate and policy agreement

When the predicate already rejects an `open`, its target is removed from the same
package set supplied to both `DecisionGrammar` and `ActionPolicy`. The original
current-package exclusion remains independent. Non-open actions retain their
existing dispatch guard; this change does not preselect back, home or a node.

The displayed `apps` catalogue and pagination counts stay intact. The prompt adds
one `blocked_action` with the action, package, stable reason code and readable
reason. Thus catalogue membership alone does not imply that a blocked launch is
available in this decision. Formatting repair receives the same filtered set and
the same reason. The block does not disappear when recent history is projected
out: it comes from the controller guard, not model-visible history inference.

## Verification scope

The native receipt additionally records `phase_timing` from CLOCK_MONOTONIC for
model hashing, vocabulary loading, model creation, template/token admission,
generation, destruction and deinitialization. Each stage distinguishes not
started, ended and valid elapsed time. A timing boundary is not a successful SDK
result. Timing failures do not change inference or cleanup decisions; every
request still performs its full model verification and normal teardown.

Host contracts exercise the real parser, guard, policy and generated GBNF. They
cover exact target filtering, changed-tree admission, discovery preservation,
wait reset, non-open effect identity and ordered open → home → open. The independent
GBNF recognizer checks that the emitted grammar excludes the blocked launch while
retaining other supplied launches and navigation choices.

These checks do not establish Android compilation, inference quality or phone
task success. Code 4 comparison results remain code 4 results. Code 5 requires a
fresh Android build and separate phone validation of this exact APK.
