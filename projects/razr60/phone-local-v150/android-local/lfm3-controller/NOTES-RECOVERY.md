# Literal Notes task recovery

This change belongs to the standalone Android local project. It does not change
Cargo modules, native inference, the model configuration, or the completion
provider. No new repository module ID is invented for this project.

## Failure addressed

The retained v46 Notes task established a model-bound `notes.create` receipt and
observed the requested body in the editor. Its next model choices opened Hepta
and reopened Moto Notes. The matching saved-list card was then visible, but that
history had not established the required editor-to-list transition. The phase
guard offered no recovery click, while unrelated `open` choices remained
available. The task exhausted its 20-step limit without completion.

The correction is an execution restriction and an evidence-bound recovery
option. The model still selects every action. The host does not perform a repair,
retry an intent, write text, or mark a note saved because it appears in a list.

## Action-domain behavior

The existing exact literal Notes contract is the only supported workflow here.
`NotesTaskPhaseGuard` reads the unchanged `TaskCompletionGate.NotesPhase` facts.

| Observed state | Offered recovery behavior |
| --- | --- |
| This task has no proved create or no observed owned body | No recovery click |
| Owned body was observed and the active package is Notes | Empty `open` package set |
| Owned body was observed and the active package is another app | Intersect the existing permitted catalog with Notes only |
| Valid task domain; owned body; list transition still unproved; exactly one current list item satisfies the existing body/provenance provider | Only that current card may be clicked to recover the editor |
| Missing, ambiguous, incomplete, stale, or foreign-domain item evidence | No recovery click |
| Unknown owner contract | Existing action domains remain unchanged |

Recovery never adds a node or package removed by catalog, authorization, scope,
budget, repeat, or no-effect filtering. Historical owned-body facts may continue
to narrow `open` after identity invalidation, but invalid identity never grants
a recovery click. The final immutable `Domain` owns the exact offered open set,
as well as the existing node/fixed-action sets. Prompt, grammar, postparse check,
and service-owned final dispatch use that same published domain. Replacement
and task retirement invalidate older domain instances.

## Completion stays unchanged

`TaskCompletionGate.java` and `NotesCompletionEvidence.java` are unchanged. A
list-to-editor recovery click does not establish `listObserved` or `reopened`.
After recovery, the existing editor-to-list transition and a click on the same
observed matching list item are still required, followed by current full-body
verification and the existing controller terminal/cleanup checks.

The composed parent card keeps its original label, child source hashes, root
signature, completeness flags, and parent node signature. A summary leaf does
not become clickable. Existing note protection, exact owner text, installed
identity, display/generation checks, and unknown-goal handling are retained.

## Host verification and provenance

`tests/completion/run_host_tests.py` retains its original six stages and appends
`notes-recovery`. That stage runs `NotesRecoveryHostTest` plus the independent
GBNF recognizer against grammars emitted by the actual controller prompt path.

The default lane is explicitly **synthetic**. It covers the failed-prefix shape,
restricted opens, one-card recovery, unchanged completion transitions, missing
preconditions, wrong task/run/observation receipt identities, foreign display
and generation, installed-identity invalidation, domain replacement/retirement,
immutable final open sets, unknown goals, and the actual service dispatch path.
Forged opens produce zero Android IO effects; the permitted recovery click
produces exactly one synthetic Android IO effect.

An optional **external_actual_trace** lane reads the original failed task's
owner, installed identity, three before/after/action pairs, and terminal result.
The 12 input hashes are pinned in
`tests/notes-task-phase/fixtures/v46-notes-recovery-pins.json`. Raw histories and
other existing private notes are not copied into this repository. The lane
receipt records every input SHA and actual historical model run ID.

The external reader preserves the recorded card and leaf capabilities. For
the complete direct-child topology present in this particular recording, it
matches each source to its exact raw leaf by resource ID, text hash, and
independent source/node-signature binding. It then runs the production
`ObservedChildText.collect()` and `LocalTaskController.completionFrame()` bridge,
checking the recorded complete parent binding. It does not infer ancestry from
coordinates, flatten the composed label, or set Gate state with reflection.

The historical `open Hepta` is rejected by the new domain. The old accepted
open/open prefix is replayed only to exercise the stranded-list recovery state.
All recovery continuation actions and observations are explicit host IO fakes.
Passing either lane is not fresh native inference, a new phone task success, or
a persistent database-byte verification.

Run the default host lane:

```sh
python3 tests/completion/run_host_tests.py --source "$TASK_SOURCE" --output "$TASK_OUTPUT"
```

To include the retained original input directory:

```sh
python3 tests/completion/run_host_tests.py --source "$TASK_SOURCE" --output "$TASK_OUTPUT" --notes-recovery-trace "$TASK_TRACE"
```

`TASK_TRACE` must be the original `evidence/task` directory. The runner refuses
hash mismatches and verifies the external inputs are unchanged after the replay.
Use an unused output directory. `--release8` requests a compiler with Java 8 API
release support; the default reports Java 8 syntax/target checks only.

## Compatibility, resources, and rollback

There is no stored-data or native IPC migration. The added phase is task-local;
the existing phase evidence schema gains one restriction flag. The private Java
`Projection.bind` call now includes the final open set. No public Android tool
schema or fixed-intent contract changes.

The change adds bounded set intersections/copies during prompt construction. It
adds no executor, worker, model allocation, inference backend, or automatic UI
operation. A stranded-list recovery requires one additional model-selected
click before the normal completion sequence; the existing task step limit stays
in force.

Rollback restores the previous guard/controller and their matching host tests,
using the project's existing signed-build/version procedure. Notes data must
remain intact. An in-flight task should end through the normal cancellation and
cleanup path before replacing the build; its action domain must not be reused.
