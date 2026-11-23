# Code18: current controls and bounded factual history

Code17 could admit a prompt after retaining a long dispatched history but dropping most current controls. Because the finite action grammar uses the final projected node set, a dropped control also disappeared from the model's valid choices. The executor still dispatched the exact model decision; this change repairs the information and choices supplied to the model.

## Factual sequence format

Raw controller evidence is preserved separately. Only history rows whose recorded `dispatched` value is the boolean `true` are included. Read-only discovery, rejected actions and unknown dispatches are not converted to effects.

`dispatched_sequence_schema` is `hepta.dispatched-sequence.v2`. Each row follows `dispatched_sequence_columns`:

| Index | Column | Meaning |
|---:|---|---|
| 0 | `step` | Original recorded step |
| 1 | `action` | Original tool action |
| 2 | `target_package` | Index into `dispatched_sequence_packages` |
| 3 | `before_package` | Index of the recorded before-observation package |
| 4 | `after_package` | Index of the recorded after-observation package |
| 5 | `details` | Recorded label, direction and bounded type text, when present |

The dictionary removes repeated package strings without substituting a requested target for an observed outcome. An absent base column has a null placeholder and its index in `details.absent_columns`. An explicitly recorded null package remains a dictionary value. Empty strings, false values and absent details remain distinct. Type-text excerpts retain the existing Unicode-safe bound and explicit truncation flag.

When history must shrink, only a suffix is retained; row order and original step numbers are preserved. `dispatched_sequence_omitted` counts omitted confirmed effects. `history_omitted` separately counts omitted detailed recent rows. These facts do not certify task progress or success.

## Budget selection

The controller caps the serialized history projection at 1,024 UTF-8 bytes, including its schema, dictionary, recent rows and omission counts. It first removes detailed recent rows and then the oldest compact effects to satisfy this additional sizing bound.

For the complete prompt, the existing `ConservativeTokenBudget` and native authorization remain unchanged. If the prompt does not fit, the controller removes detailed history, surplus ranked app candidates above four, optional noninteractive text metadata, old compact effects, and remaining surplus app candidates before trimming current nodes. Current editable fields and actual enabled action capabilities are sorted before optional labels. Editable metadata is always selected from the final projected node IDs.

This does not promise that every large screen fits every context. Every omission remains explicit, and an instruction that cannot fit still fails closed. The byte cap does not replace native token checking or increase context, generation, task-duration or repair limits.

## Exact open choices

`open_allowed_packages` is the same package set supplied to the finite grammar after the existing repeat guard and existing current-package and `android` exclusions. The app catalogue remains observation data and can include the current app; it is no longer described as the exact list of valid open targets.

This is a prompt clarification. Action JSON schema, node-label binding, permission checks, observation freshness, executor dispatch, native model interfaces and offline operation are unchanged. The executor never converts a reason into a different action.

## Verification and evidence limits

The existing recent-projection contracts remain intact. `CompactSequenceHostTest` adds ordered navigation, actual-versus-requested package outcomes, confirmed-dispatch filtering, suffix omissions, absence/null/empty-value preservation, Unicode excerpts, repeated-package compaction and immutable output checks.

A separate host replay uses retained observations and histories with the production prompt code. A frame is an exact regression fixture only after its old prompt and grammar are reproduced byte for byte. Reproduced long-calculator frames verify available current controls, editable ID membership, unchanged native budgeting and complete retained factual sequences.

Old `PhoneObservation.Node.json()` evidence omits each node's package and class, although production nodes carry both. A launcher can contain widgets from other packages. Filling every recorded node with the root package is therefore not an exact reconstruction. Such frames retain an unresolved-baseline result; neither resource IDs nor expected grammar choices are used to invent missing node packages. Other fully reproduced frames and focused contracts can test navigation history, but cannot retroactively qualify those unresolved frames.

Host projection checks do not substitute for real Android compilation or the unchanged phone acceptance suites. Model output quality, app-specific behavior and ordinary-entry/lifecycle qualification remain separate measured results.
