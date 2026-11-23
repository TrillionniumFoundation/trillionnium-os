# Observed descendant labels for anonymous clickable containers

This source change preserves the existing active-window selector, screenshot/observation pairing, node IDs, action schema, package/window checks, freshness checks and original parent ACTION_CLICK dispatch. It does not translate text into a different target or add an app-specific route.

## Observation

ObservedChildText runs against the actual AccessibilityNodeInfo subtree through a read-only adapter. Only an otherwise unlabeled, visible, in-scope clickable root exposing ACTION_CLICK is eligible. Editable/input-type or password roots are rejected before requesting their text. For descendants, invisible/out-of-scope, input/password and nested interactive nodes are whole-subtree boundaries. Nested interaction includes clickable/long-clickable, checkable and scrollable flags and the corresponding click, text and scroll actions. Focus alone is not treated as a separate control.

Each root can acquire at most 16 descendant references, traverse at most four levels, and contribute at most three distinct text/description parts within 96 UTF-16 code units. A UTF-16 surrogate pair is never split. Truncation is explicit. An unavailable child or metadata exception discards partial label assertions. Every acquired descendant reference is released; the caller retains the root. Parent/child package, window and intersecting screen bounds must agree. A successful label is supporting screen evidence, not proof that every possible descendant was visited or that the node is safe to activate.

PhoneObservation records child_text independently of text/description, along with a versioned source, relative child paths, original source text SHA256 and source node signatures. Own text and description keep priority. Prompt projection, node ranking and actual action history use the same final fallback. Input text remains available only through the pre-existing explicit node observation; this change never copies an input body's text into an ancestor label.

The input boundary is conservative: isEditable or a nonzero inputType prevents descendant text collection. Android permits a custom noneditable TextView to have a nonzero raw inputType, so such a label can be omitted. No actual Apps-label inputType measurement is available from the retained fixture; this is a documented limitation, not a claimed cause. It must be resolved from real metadata if encountered, not by assuming every noneditable text node is safe to read as an ancestor label.

## Freshness

The original parent node signature is retained and combined with a fingerprint of the label, traversal status/truncation and sources. The resulting signature is appended to the same Graph digest as before. At dispatch, the parent is refreshed and the same bounded descendant traversal is repeated before comparing the target signature. A changed derived label or source therefore invalidates the old target and whole-graph identity. No text is used to substitute a different node or action.

## Focused contracts

ObservedChildTextHostTest executes the real traversal, display fallback and binding helper. It covers the Settings-style Apps container, the observed empty popup parent with the non-clickable `清除历史记录` child, search input exclusion, a separate static search label, nested interaction and password boundaries, visibility/scope boundaries, own-label precedence, description provenance, duplicate parts, depth/node/text limits, reference cleanup, unavailable children, source identity changes and label-only freshness/progress changes.

The first full host run is host-evidence/code9-r1/HOST-CHECKS.json: 31 checks passed, including 130 assertions in the new test. This is host validation; Android compilation and actual phone behavior remain separate gates. A final host run is required after integrating the separate persistent-action policy and version/driver changes.

## Safety boundary

The prior live Apps test activated an anonymous parent whose actual descendant label was `清除历史记录`. Labels repair the observation gap but do not establish authority to erase persistent state. Code9 separately adds a reviewed, fail-closed policy for clearly persistent destructive node clicks. That policy is supplied by the other source owner and must run after live node/package/window/password/freshness checks and before ACTION_CLICK. The current text controller still rejects coordinate clicks, and this change does not claim a general visual-action safety policy or support destructive automation.
