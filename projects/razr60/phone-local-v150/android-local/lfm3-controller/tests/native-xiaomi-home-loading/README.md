# Native Xiaomi home loading and window freshness

This gate replays the complete ordinary-task observation `21a9070fc21d43c9837397f63ea48a8f` from task `358b396a60d54bf783c90f42b3cac4e4`. Its 11 retained nodes contain the selected home navigation, the five bottom tabs and the message icon. The saved production page originally classified it as `unrecognized_native_page`.

The provider recognizes this complete, installed-version-bound navigation shell as a readiness state. It grants no click, type, Back, purchase, query or result authority. The real `NativeAppSession` allows at most two model-issued wait proposals and a 15,000 ms span between observed frame timestamps. This is an **observed loading budget**, not a 15-second wall-clock execution guarantee. The existing task deadline, action deadline, cancellation and Stop checks remain independent. Neither a new window ID nor a temporary ready page resets the wait count or observed start time. An exhausted loading domain permits only a failure report; no loading transition is accepted as query or product-price evidence.

The special grammar entry accepts only the current complete, unexhausted loading domain and produces a real wait-only GBNF root. Ordinary task-tool filters continue to require terminal reporting. Unknown pages, ready pages, exhausted loading domains and an original mask that removes wait cannot use this entry.

The bridge cases compile the production `scopeBeforeDispatch`, `backgroundBeforeDispatch`, `requireBackgroundNodeWindow`, stale exception, action checks and node-refresh bodies verbatim. They exercise the actual outer scope catch. A replacement application window in the same active owned background display and explicit package produces a stale, undispatched proposal without permanently refusing scope. Fresh observation and another model decision are still required. Missing roots or window metadata, foreign packages/displays, main-display use, non-application windows, inconsistent IDs, invisible windows, retired/replaced leases, Stop and action deadlines remain rejected. Same-window node checks remain in place.

## Run

Use a complete JDK 17 and the existing pinned `json-20240303.jar`:

```sh
python3 -B tests/native-xiaomi-home-loading/run_host.py \
  --source /absolute/component \
  --output /absolute/fresh-output \
  --java-home /absolute/jdk17 \
  --json-jar /absolute/json-20240303.jar
```

Optional `--previous-source /absolute/r12/component` accepts only the pinned original R12 provider and service hashes. It separately recompiles them and reproduces both the unsupported saved page and the old terminal scope refusal on an otherwise owned same-package window replacement.

`RESULT.json` preserves actual stage exit codes, original stdout/stderr identities, full source/tool input identities before and after, generated Java identities, extraction evidence and the two component case records. `CASES.json` aggregates unique case names without rewriting their results. The GitHub Android workflow invokes this gate and uploads its entire output directory even when a required gate fails.

## Evidence boundaries

The three JSON fixtures are byte-for-byte saved phone records, pinned in `fixtures/PROVENANCE.json`. The generated DTO copies their fields and checks raw-frame, owner, collector-counter and page linkage. The actual production parser, Session, Domain, grammar and completion gate are compiled.

Later ready/changed pages, task identities, installed-app verifiers, model callbacks, action receipts, Android roots/windows and the worker clock are explicit host fixtures. These tests execute no phone operation, model inference, SDK, Android dispatch, shopping query or purchase. A host pass is not phone acceptance. The original phone failure remains unchanged.

Existing Xiaomi parser, image-modal, native provider, action integration and action-worker suites are retained separately.
