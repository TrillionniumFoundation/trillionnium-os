# Code14 active-window and repeated-click candidate

This independent candidate derives from the frozen code13 manifest
`e48ddbd38cffe0ed3218606d47b0bcd126827d081cb5647c50bebb8c56f445a2`.
The root manifest identifies the complete code14 source. Android compilation
and packaging have separate receipts. No phone task improvement is established
by the source or host contracts.

## Active-window evidence

The projection now includes the bounds of the observed active root, its actual
class, and—only when `root.getWindow()` matches its window ID and the selected
default display—the API window bounds, type, and title. Missing metadata remains
null with `metadata_status: unknown`; an unavailable title is not replaced with
the application label. The `active_root_only` scope says what was traversed.
It does not classify a window as a menu, dialog, home page, or completed goal.

The public Android API describes the window title as a `Window` title or its
`WindowManager.LayoutParams` title, and allows null. It is not a guarantee of the
visible page title. Bounds are screen coordinates. References:

- https://developer.android.com/reference/android/view/accessibility/AccessibilityWindowInfo#getTitle()
- https://developer.android.com/reference/android/view/accessibility/AccessibilityWindowInfo#getBoundsInScreen(android.graphics.Rect)
- https://developer.android.com/reference/android/view/accessibility/AccessibilityNodeInfo#getWindow()

Title and root-class strings are untrusted data, bounded to 96 and 128 UTF-16
units respectively with explicit truncation. Full-source hashes bind exact
freshness even when only a prefix is displayed. Metadata changes invalidate the
existing complete-snapshot checks. The app-tree/IME progress predicate remains
separate, so known/unknown metadata transitions do not reset the repeat guard.
No other window root or input-method content is traversed for this metadata.
The prompt uses a compact form of these same facts, further limiting title/class
text to 16/32 UTF-16 units and marking any truncation. This reserves space for
actual controls and input/readout text. Full status, window/display identity and
the 96/128-unit records remain in the private observation; all source hashes
still bind exact freshness.

The system instruction explains this limited scope and forbids inferring a page
or completion from package/application/window-title identity alone. It adds no
task-specific keywords, second model, automatic navigation, or success override.
The owner instruction is explicitly the same task across all rounds. Progress
must follow dispatched actions and subsequent observations; previously completed
steps are not new requests when the owner text appears in the next round.

## Existing rejected clicks become unavailable before generation

`blockedClickNodeId` exposes only a node click that the unchanged existing
`rejects` predicate already rejects in the current state. The node stays visible
in the prompt with its original label and ID, but loses the `c` capability for
that turn; the emitted grammar receives the same reduced click set. Other node
capabilities, targets, actions, parser checks, live target binding, and the
dispatch-time repeat guard are unchanged. The fact that the preceding click was
dispatched without confirmed visible progress is reported as `blocked_action`.
The already-observed node focus is also projected as `f`; it is not an action
capability and cannot authorize a click or input. The protocol explains that an
already-focused editable target can receive the requested text without another
focus click. The ID/focus pairs from the same collected nodes are separately
bound into the complete snapshot digest, so a focus change invalidates exact
freshness without resetting the app-tree/IME progress guard. Actual type
eligibility and live target checks are unchanged.

Actual app-tree/known IME changes restore the original candidate. Unknown IME
state cannot manufacture progress; a read-only catalogue query cannot clear the
preceding blocked click. The existing wait/reset semantics remain intact.

These changes address two observed classes of failure without weakening any
core-suite expectation. They do not establish that a model will navigate
correctly, distinguish calculator history from current input, or complete all
nine original goals. The source's model-only diagnostic is unchanged.

## Explicit experimental Bolt candidate

The closed Java/native/Python artifact lists add only the fixed text artifact
`nemotron-3.5-bolt-e4b-q4_k_m` from
`nvidia/NVIDIA-Nemotron-3.5-Bolt-E4B-4GB` at revision
`1db54d5b12533ff1bcaa8e42cf4c667988a1f1be`:

- File: `Nemotron-3.5-Bolt-E4B-Q4_K_M.gguf`
- Size: 6,180,446,208 bytes, retained as a 64-bit integer end to end
- SHA-256: `c8af2b8aea10a690a1d9491db744a9446660173cb38fc489612b556615a69612`
- Expected architecture: `gemma4`; exact native input-ID tokenization required
- Available-RAM admission: 8 GiB; this is an engineering qualification threshold,
  not a measured peak, RSS estimate, or success claim
- First device qualification is limited to context 4096. The existing E4B
  admission remains 7 GiB, source default remains LFM3, and no persisted device
  profile is changed by this candidate.

The model card's license is `openmdw-1.1` (OpenMDW 1.1), not the base model's
license inferred from its name. Official metadata is public and ungated:
https://huggingface.co/nvidia/NVIDIA-Nemotron-3.5-Bolt-E4B-4GB/tree/1db54d5b12533ff1bcaa8e42cf4c667988a1f1be
and https://openmdw.ai/license/1-1/ .
Bounded official GGUF ranges confirm architecture and tokenizer `gemma4`,
42 blocks, and a 20,161-byte embedded template with SHA-256
`35b7d0641b6fb4ee41c3bc623e85bdb7d583c40f6ae9f24514ae58a9d57119f3`.
The actual template defaults `enable_thinking` and `conversational_mode` to false;
no new native-tools mode is enabled. This header observation is not a whole-file
download, inference or accelerator qualification. Whole-file SHA verification,
memory admission, backend loading/offload and device task quality remain
separate gates. See `provenance/bolt-e4b-header-qualification.json`.

## Bounded projection check

The revised SYSTEM is 2,329 UTF-8 bytes, compared with 2,862 in code13. Host
projection checks reused retained calculator and search inputs byte for byte,
then applied this candidate's capability/focus facts and bounded metadata.
Code13 had not collected the new window metadata, so unknown and maximal JSON
escaping envelopes were used explicitly as sizing scenarios, not observations.

| Retained input | Metadata envelope | Old shown / omitted | New shown / omitted | New estimated input / total |
|---|---|---:|---:|---:|
| Calculator | Unknown API values | 25 / 0 | 25 / 0 | 3,147 / 3,659 |
| Calculator | Maximum bounded escaped text | 25 / 0 | 25 / 0 | 3,336 / 3,848 |
| Search | Unknown API values | 15 / 12 | 20 / 7 | 3,574 / 4,086 |
| Search | Maximum bounded escaped text | 15 / 12 | 11 / 16 | 3,567 / 4,079 |

All calculator controls, equals and current readout remained present in both
envelopes; the focused editable search input remained present in both. The
existing node-selection order, history format and 4,096-token context were not
changed. Total estimates include 256 generation and 256 reserve tokens. These
are the existing Java sizing heuristic, not exact tokenizer counts; the actual
native formatted-input count remains the admission gate.
