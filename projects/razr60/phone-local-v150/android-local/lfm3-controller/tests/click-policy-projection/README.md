# Click policy projection regression tests

This public suite contains only synthetic data. It requires Python 3 and an existing JDK 11+; it installs nothing and uses no network, phone, model, saved task, or baseline checkout.

Place these three files in `tests/click-policy-projection/`. From the application source root, run:

```sh
python3 tests/click-policy-projection/run.py \
  --source . \
  --out /tmp/hepta-click-policy-test
```

`--out` must name a new directory. Results include `result.json`, `regressions.log`, source hashes, generated Java fragments, prompt-node projections, and production-generated GBNF. The runner exits nonzero on compilation or regression failure. Python bytecode writes are disabled for imported source modules.

## What is exercised

The suite compiles actual pure Java `PersistentActionPolicy`, `DecisionGrammar`, `ObservedTargetLabels`, `ObservedScrollActions`, `ObservedChildText`, `PromptActionDomain`, `ActionDecision`, and `ActionPolicy`.

It also extracts the actual capture, node projection, grammar-domain, and post-parse validation statements from `HeptaAccessibilityService.java` and `LocalTaskController.java`. Narrow node and JSON scaffolds replace Android types. No independent copy of the policy or domain algorithm is substituted. Source ranges, fragment hashes, and scaffold type substitutions are saved in the output manifest. Extraction fails explicitly if the expected source shape changes.

The existing independent `tests/action-grammar/gbnf_recognizer.py` recognizes the actual generated GBNF. Cases cover:

- Full direct text and description classification before observation/model-label truncation.
- Password getter avoidance, verified with getters that throw when read.
- Editable-field focus/type exemption; a nonzero input type does not exempt a noneditable control.
- Descendant text, same-label editable/noneditable controls, bare clear/delete, cancellation, empty labels, and Unicode normalization.
- Retaining observed text while excluding its click capability and recording the reason.
- Prompt `c` flags matching the emitted grammar's click set, including disabled, password, and foreign-package nodes.
- Preserving independent scroll capabilities and back/home/discovery/open/wait/done alternatives.
- Immutable click sets, null/unknown-ID denial, and post-parse checks on syntactically valid exact label/ID pairs.
- Keeping the executor's fresh-node policy check before the Android click call.

## Scope and limits

These are host regression tests. They do not execute the complete Android controller, its sorting/budget loop, Android accessibility effects, or native constrained generation. Repeat state is empty in these fixtures; the existing repeat-filter wiring is checked statically. Android compilation and real-device acceptance remain separate checks.

The bounded descendant-label collector already limits text to 96 units and a bounded number/depth of children. A test records that wording beyond that boundary is not classified. This change projects the existing executor policy; it does not add unbounded descendant classification. `click_policy_allowed` also remains one gate among enabled state, package binding, password exclusion, repeat handling, freshness, and actual Android action availability.

## Optional host-check integration

The existing `tools/run_host_checks.py` can invoke the suite as an additional named check, using its own fresh output directory:

```python
run("click-policy-projection", [
    sys.executable,
    ROOT / "tests/click-policy-projection/run.py",
    "--source", ROOT,
    "--out", out / "click-policy-projection",
])
```

No private evidence replay is part of this public suite.
# Code23 r2 integration note

This copy keeps the original PR121 eighteen scenarios and adds one integration
scenario for Code22's same-state no-effect guard. The bridge compiles the actual
pure guard and the exact production domain-subtraction statement, checks an
empty snapshot and a confirmed unchanged click, and keeps that node absent from
prompt capability, grammar, and post-parse acceptance. There are nineteen tests
in this merged gate. The full Android controller and live phone are still not
executed by this synthetic harness.

