# Code9: observed targets and a narrow persistent-action gate

This candidate is versionCode 9 / 0.9.0-local-targets. It is based on the frozen code8 source whose manifest SHA256 is `8fd07b409a471927bc94577adb36da39e2256f0e347be35a967b869a0fd33c70`. Model profiles, native inference, tokenizer/budget checks, grammar schema, owner instructions, same-window checks and original node permissions remain unchanged.

The code8 app-management qualification exposed two problems. A clickable parent had no own label, while its actual non-clickable descendant supplied the intended label; the model did not receive that association. A later anonymous popup control was activated even though its real child label described clearing stored history. Testing stopped after that unintended persistent change. Code9 is a correction candidate, not a claim that those problems or all phone goals have already passed real-device validation.

## Actual descendant labels and freshness

`ObservedChildText` derives a bounded fallback only from a target's own visible, non-interactive descendant subtree. Own text/content description retain priority. `PhoneObservation` keeps derived text, provenance, source paths/hashes and truncation separate from original labels. Prompt projection, ranking and action history use the same fallback. The original parent identity and the derived-label/source fingerprint both participate in target and whole-graph signatures. A label or source change makes an old click stale; text never redirects a click to another node. See `docs/CODE9-OBSERVED-CHILD-LABELS.md` for traversal limits and input/password boundaries.

## Explicit persistent destruction is unsupported

Immediately before a node's ACTION_CLICK, after the existing live refresh, target signature, visibility, enabled, password, package, window and cancellation checks, `PersistentActionPolicy` inspects the real direct text, description and newly re-derived descendant label. Clearly labelled combinations such as clearing history/data/cache or deleting files/accounts are rejected, as are explicit uninstall/factory-reset controls. Rejection produces `accepted=false`, `dispatched=false` and a specific guard reason. This build does not attempt to infer destructive authorization from a free-form owner phrase, model reason, package name or resource ID. It does not support automated persistent destructive operations, even if a model asks for one.

Only actual `isEditable()` grants the input-focus exemption; a nonzero raw inputType does not. Input-field contents are not interpreted as button commands. Bare `清除` / `删除`, C/AC and current-input editing remain **unclassified** and retain their existing behavior: the real calculator uses bare descriptions without C/AC text, and a word alone does not prove persistence. Those cases are not declared universally safe. The policy is a narrow visible-label gate, not a complete detector of every persistent side effect, every language, misleading UI semantics or coordinate/visual actions. The current text controller still rejects coordinate clicks.

The pure Java policy has 73 contract assertions, including the observed empty popup parent, descendant-only destructive labels, safe-looking own text that must not hide a destructive description, genuine input-focus text, ordinary navigation and the actual calculator's bare descriptions. The descendant-label helper has 130 assertions. Host qualification does not establish Android compilation or real device behavior.

## Compatible independent verification

The host acceptance verifier now recognizes exactly the existing GBNF v1 and reason-first v2 schema values. Both grammar SHA bindings and the corresponding uniquely observed package remain mandatory. The copied `phone_acceptance.py` and its tests are byte-identical to the separately reviewed compatibility-r1 bundle; no old evidence is rewritten. Use a newly frozen core-suite-v2 plan for the exact code9 APK/profile.

The next real-device qualification must demonstrate the actual Apps target label/provenance and fresh dispatch, an actual rejection of the persistent-history control without changing history, and independent final UI/cleanup checks. Calculator and broader phone-goal capability remain separate tests; improved labels do not establish that the model maps every number or button correctly.
