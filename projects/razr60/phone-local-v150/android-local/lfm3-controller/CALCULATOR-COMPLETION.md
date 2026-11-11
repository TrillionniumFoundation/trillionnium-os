# Current Moto Calculator completion contract

This provider is an independent observation check added to the existing task
completion gate. It does not dispatch tools, change OWNER, write an answer to
an application, choose a model, or change authorization.

## Supported goal

Only the complete immutable owner form below is recognized, with each operand
an ASCII nonnegative integer of at most nine digits and no leading zero except
`0` itself:

> 打开计算器，在当前主输入区计算 31 乘以 47，确认当前结果框显示计算结果后结束任务。

The same finite form also covers the prepared `17 乘以 29` driver. Unknown
clauses, negation, quotations, other operators and additional goals remain
unverified. `BigInteger` computes the expected product from these exact owner
operands; the answer is not included in the model prompt. This is not a general
arithmetic parser or a proof of the calculator engine implementation.

## Required current evidence

The application is exactly `com.motorola.cn.calculator`. Ordinary
PackageManager and full installed APK hashes are captured at task start and the
existing installation checks continue during actions and after native cleanup.
The two distinct, unique current fields are:

- `com.motorola.cn.calculator:id/formula`
- `com.motorola.cn.calculator:id/formula_or_result`

They must come from a complete, nontruncated accessibility graph in one observed
application window, have valid bounds, remain enabled and editable and not be
password nodes, and have full input-text digests equal to their raw strings.
The current formula must match the owner expression (`*` is accepted as the
explicit ASCII spelling of `×`) and the current result must equal the canonical
integer product. Formatted numbers, partial strings, approximations and history
`item_formula`/`item_result` fields are not accepted as current result evidence.

## Model action origin

A preexisting correct result and a model `done` claim cannot verify a task.
There are only two supported evidence paths:

1. An actual accepted, dispatched, nonstale model `type` writes the complete
   owner expression into the unique primary `formula_or_result` input. The before
   primary field was different and the before current pair was not already
   correct. The immediate after observation must read back the complete
   expression in that same primary resource. A subsequent actual observed equal
   click must replace that expression with the correct current formula/result
   pair. Type alone can never mark calculation produced, including when its
   after observation already shows a correct numeric pair. The separate
   `formula` field is never an accepted type target: editing it could otherwise
   combine a new formula with an old result. Directly typing the numeric answer
   is not an expression entry.
2. Actual observed model key clicks build every expression prefix from an empty
   or zero primary input; a final observed equal click changes that expression
   into the correct current formula/result pair. Every key binds the actual
   source node ID and complete label and must account for exactly the next input
   character. The keys use observed UI semantics, not fabricated resource-ID
   allowlists. Editable fields, history `item_*` nodes, derived labels, arbitrary
   coordinates and unrelated click targets cannot contribute a key. Existing
   partial expressions do not count as a newly entered prefix chain. An initial
   zero operand that causes no visible first-key transition is conservatively
   unsupported by the key route; the full-expression type route can cover it.

Both paths require distinct before/after observation IDs, the same application
window, display and background generation, monotonic model steps and nonreused
model run IDs. The production Controller/Accessibility layer owns actual time
freshness and dispatch; host frames alone do not establish those facts. Final
`done` must pass the existing stable final observation check. Installed identity,
native cleanup and display cleanup checks continue to gate the terminal verified
bit. Changing the current result/window retires the retained calculation proof.

## Source basis and limits

The resource IDs above were reported in the read-only archived observations
summarized at `/workspace/scratch/007f1dd9aa90/evidence/calculator-result-view-id/reference.json`.
Its two archived host references were:

- `/home/alex/hepta-local-6cc233-20261110-r1/foreground-nanbeige-resume-r1/evidence/task/step-05-after.json`,
  reported SHA-256 `df1978596e1d84e77b488a21459f1d7ef96636027ec0968b5ff14ae2fe9ff21c`,
  with current `23×19` / `437` and a separate historical `37+58` / `95`.
- `/home/alex/hepta-local-6cc233-20261110-r1/foreground-qwen35-4b-npu8192-fresh-r1/evidence/task/step-01-before.json`,
  reported SHA-256 `e43e983ecf8c2144e2aae2593264938b208882d9539f4503a5094af15038a052`,
  with blank current formula / `0` and a separate historical `23×19` / `437`.

That reference explicitly records `original_bytes_locally_saved=false`. The
provider's host fixtures are therefore synthetic cases informed by that summary,
not a replay of retained original phone JSON. Neither old foreground observations
nor host tests qualify a new background phone run. Exact per-key resource IDs
were unavailable; the key path assumes the frozen calculator's enabled,
noneditable, nonhistory single-key labels carry their conventional semantics,
and additionally verifies every resulting primary-field transition.

The longest 9-digit-by-9-digit key sequence plus equals and done exceeds the
Controller's existing 20-step task budget. Large operands may require the type
route; this change does not raise the global budget. The two prepared phone
examples need five expression keys, equals and done once already in the app.

The current source does not support arbitrary calculators, screenshots without
accessible nodes, decimal/scientific/locale formatting, copied historical
answers, or operations outside this exact multiplication goal.

## Tests

`tests/completion/run_host_tests.py` keeps the existing five completion stages
and appends `calculator-completion`. The added stage runs the actual pure
provider and completion gate plus the actual Controller and production dispatch
code with explicitly synthetic Android/model IO. It covers valid typed/key
chains, the two prepared owner goals, mathematical and provenance negatives,
preexisting answers combined with formula-only edits, direct result pairs after
type without expression readback, missing/invalid equals actions, history rows,
stale/replayed actions, domain changes,
installed APK changes after cleanup and invalid native cleanup receipts. The
actual Controller host also blocks inside final installed-identity verification,
issues Stop from the host thread, then releases verification: known cleanup must
publish cancelled with completion false, while unresolved cleanup remains blocked.
The Android PackageManager getter hook is an explicit IO fake; the verification
and Controller finalization logic are unchanged production classes under test.

A local Java runtime without the Java 8 release symbols can run the existing
syntax/target development mode. Only a successful `--release8` run on a complete
JDK qualifies the Java 8 API gate. Neither form is Android compilation or phone
acceptance.
