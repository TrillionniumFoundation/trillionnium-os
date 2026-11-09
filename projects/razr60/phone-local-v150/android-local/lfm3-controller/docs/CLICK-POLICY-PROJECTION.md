# Project the existing click policy into model capabilities

## Problem and change

The executor already rejects some persistent or destructive commands using
`PersistentActionPolicy`. Previously, a prohibited control could still be
presented to the model as clickable and included in the observation-bound click
grammar. The model could therefore select a syntactically valid observed target
that the executor would subsequently refuse.

This source derivative classifies observed controls with that existing policy
before direct text and content descriptions are shortened for display. The
classification is recorded in `PhoneObservation`. The controller retains the
observed label as data, omits click capability for prohibited targets, and adds
`screen.unavailable_clicks` with the reason. The emitted grammar uses the same
click set. A post-parse check also verifies membership in that observation's
allowed click domain; a valid label/ID pair alone does not authorize a click.
The executor still checks the fresh Android node immediately before clicking.

This does not introduce new prohibited-word rules or infer task completion.
Editable-field focus and type retain the existing policy exception. Independent
scroll capability and navigation, application discovery, open, wait, and done
remain available where their existing contracts allow them. Disabled, password,
foreign-package, repeat, freshness, and actual Android action checks still apply.
Observation retention continues to use the original observed action domain, so
withholding click capability does not silently erase a control's visible text.

## Public regression coverage

`tests/click-policy-projection/` contains 18 synthetic host tests and is included
in `tools/run_host_checks.py`. It compiles the actual pure policy, grammar, label,
scroll, descendant-text, retention, action-parser, and action-policy classes.
Source-extracted capture, projection, click-domain, and post-parse statements use
narrow Android/JSON scaffolds; fragment ranges and hashes are recorded. An
independent GBNF recognizer checks the production-generated grammar.

Cases include long direct labels and descriptions, bounded child text, same-label
editable and noneditable controls, password getter avoidance, Unicode
normalization, empty labels, all-clicks-blocked observations, immutable click
sets, and preservation of independent nonclick actions. The public tests use no
saved UI, task, model output, phone identifier, private baseline checkout, model,
network, or device.

Run the integrated checks from the source root with a new output directory:

```sh
python3 tools/run_host_checks.py --out /tmp/hepta-host-checks-new
```

## Qualification and remaining limits

Host checks do not execute the complete Android controller, its sorting/budget
loop, accessibility effects, or native model-constrained generation. Synthetic
repeat state is empty; the existing repeat-filter wiring is checked separately.
The descendant-text collector remains bounded in length, depth, and count. The
suite explicitly records that prohibited wording beyond the collected boundary
can remain unclassified; this patch does not claim to solve that limitation.

The original installed code20 full9 result remains **3 passed / 6 failed**.
Those historical device results and Android build receipts do not qualify this
changed source. The current click-policy source candidate is **not installed**,
and **new phone acceptance tests have not run**. Final Android compilation and
fresh device acceptance are separate required evidence. Host-only evidence does
not establish improved task success, local-model planning quality, or production
readiness.

The integrated host run completed 57 named checks successfully, including all
18 new click-policy regression tests. Its public summary and relative source
input hashes are retained in
[`PUBLIC-HOST-CHECKS.json`](../host-evidence/click-policy-projection-r1/PUBLIC-HOST-CHECKS.json).
That summary explicitly records Android and phone testing as not performed by
the host run.
