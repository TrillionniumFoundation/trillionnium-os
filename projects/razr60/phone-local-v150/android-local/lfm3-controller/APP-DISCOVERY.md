# Local app discovery, revision 3

The previous controller supplied at most six apps to each model decision and
had no way to retrieve omitted apps. Its initial ranking matched only a full
launcher label, so an explicit package ID or a Chinese request against an
English label could leave the desired installed app unrepresentable in the
constrained `open` grammar. The source also cut the catalogue at 40 entries or
2,000 characters before prompt budgeting.

`AppCatalogueRanker` now captures an immutable snapshot of up to 4,096 installed,
enabled, exported launcher packages. Exact package mentions receive first
priority, followed by normalized full-label matches, then stable package order.
Matching uses Unicode NFKC, lowercasing with `Locale.ROOT`, and whitespace
normalization. It normalizes only matching copies; the owner's instruction and
the real package ID are preserved. Labels are untrusted data and are bounded for
storage/display. A larger catalogue fails explicitly instead of silently hiding
entries.

## Model tool contract

```json
{"action":"find_app","observation_id":"0123456789abcdef0123456789abcdef","package":"com.example.launcher","query":"calculator","offset":0}
```

`observation_id` and `package` must equal the current real observation. The
example identifiers above must never be used as live evidence. Required search
fields are:

| Field | Meaning and bound |
| --- | --- |
| `query` | 0..64 Unicode scalar values, no NUL. A nonempty value searches only observed package IDs and labels; empty/normalized-whitespace query browses the snapshot. |
| `offset` | Canonical integer 0..4095, indexing the deterministic result list. Start changed queries at zero. |
| `reason` | Optional existing common field, at most 256 Unicode scalar values. |

No other search fields are accepted. The parser, per-observation GBNF and
current-package policy all enforce this schema. GBNF rule names use `find-app`
because grammar identifiers differ from the JSON action string `find_app`.

The service runs this tool through the existing task lease, cancellation, lock
and fresh-observation checks. It performs only a pure lookup against the
task-owned snapshot. It dispatches no Activity Intent, accessibility action,
gesture, shell command, network call or app launch. It returns at most six apps.
Newly installed apps enter a new task's snapshot; a later `open` always rechecks
that a supplied package is still installed and launchable.

The next prompt contains the results in `apps` and this metadata in `app_search`:

```json
{"query":"calculator","offset":0,"matches":1,"total_apps":59,"next_offset":null}
```

Prompt budgeting can display fewer than six results. `next_offset` therefore
advances only past entries actually supplied to the model. A non-null value can
be copied into another `find_app` call with the same query. A null value means
this result list is exhausted. A search with no matches returns an empty list;
it never fabricates a package or silently substitutes an app. Matching is
lexical, not automatic translation: the local model can try another name or
package fragment, or browse by empty query.

Only the packages actually displayed in the next prompt are admitted to its
`open` grammar and policy. A returned-but-budget-omitted package still cannot be
opened. Search does not itself complete a requested app operation. The task's
existing 20-step, total-time and repair bounds remain in effect; unchanged-screen
repeat protection is retained across a read-only search.

## Evidence

The controller records:

- `initial-app-catalogue.json`: the first page, snapshot SHA, local source and
  `model_issued:false`.
- `step-XX-model-Y.json`: the real local model run ID and exact raw decision.
- `step-XX-action.json`: the accepted or rejected search, with `model_run_id`,
  `model_issued:true`, `read_only:true`, `effect:"launcher_catalogue_read"` and
  `dispatched:false`. A stale or cancelled search is not accepted.
- `step-XX-find-app.json`: for each accepted lookup, the same model run ID,
  task/observation/owner binding, source `installed_launcher_snapshot`, query,
  offset, snapshot SHA, matching/total counts, and returned installed entries.
- `step-XX-budget-Y.json`: snapshot SHA and the actual prompt's search/pagination
  metadata, alongside the existing context and grammar SHA bindings.

The service takes a new observation after the search, exactly as it does after
other decisions. Evidence stays in the app-private task directory. A search
receipt is evidence of a local read, not a dispatched UI operation or completed
user goal. Phone acceptance must still verify subsequent real actions and final
visible predicates.

## Verification boundary

Host tests compile the production parser, policy, ranker and grammar for Java 8
with compiler warnings treated as errors. They exercise package/label ranking,
Unicode and whitespace normalization, deterministic immutable snapshots,
retrieval beyond the old 40-entry limit, pagination after budget truncation,
query bounds, missing apps, and the strict transition from an omitted package
to a supplied package permitted by a later `open`. The independent Python GBNF
recognizer checks the actual generated pre-discovery and post-discovery grammars.

Those tests use synthetic launcher fixtures and model-output strings. They do
not execute an Android model, launch an Android app, prove native GBNF support,
or qualify NPU/GPU acceleration. Android compilation and genuine device runs
remain separate gates. A real-device discovery case must show an initially
omitted installed target, a model-issued accepted `find_app`, its private lookup
receipt, a later dispatched `open`, and an independently verified final app/UI.
