# Hepta core phone suite r2

This independent suite preserves the frozen r1 source/results and does not modify
Hepta. Freeze, validate and evaluate are offline. Only an explicit run contacts
the phone. Original nonce, owner, native-output, accelerator, cleanup and final
UI gates remain mandatory. A correct screen never upgrades a failed, unfinished
or unverified base task to pass.

## Goal semantics

The plan schema is `hepta.phone-core-suite.v2`. Each plan pins both core evaluator
files and the complete base-driver closure. Only the reviewed nine case
definitions are accepted. V1 plans are rejected; freeze a new plan and use a new
run directory.

Natural-language “open Settings” does not require an `open` tool call. A native-
bound launcher click, or back from a restored child page, qualifies when its
after-observation actually reaches Settings and the independent final UI matches
the goal. `action.package` remains the before-window package for a click;
arrival uses `after.package`. At least one real bound dispatched effect is
required, so a pre-existing screen or model success claim alone cannot pass.

| Case | Required evidence |
|---|---|
| Settings home | Bound effect reaches Settings; final focus, title and search entry match. |
| Apps management | Bound effect reaches Settings; both exact final Apps-page markers are present. Restoring that page is valid. |
| Calculator keypad | Fresh clear then exactly 2, 3, multiply, 1, 9, equals; no type shortcut; visible expression and final 437. |
| Chinese search | Exact model type into the observed field, exact after-readback, final query and distinct non-input result. |
| Search return | Initial model-bound fixture must be Settings search. System back or an observed return-button click reaches Settings; final home markers match. Missing start fixture is unverified with precondition_missing=true. |
| Settings → home → Settings | Strict actual arrival order. The desktop package is resolved read-only before submission. Final Settings home still required. |
| Settings → calculator → Settings | Strict target visits. Launcher detours are allowed; extra/wrong/repeated target visits and calculator input are rejected. |
| Settings scroll | Forward/down scroll on a model-provided scrollable node changes visible nonnumeric content; same foreground geometry and final Settings focus. |
| Find calculator | Explicit native-bound find_app query and catalogue result, followed by actual open of the returned target using matching search metadata. No calculator input. |

Settings' known search component counts as a visit to that app, not as its home
page. Final home predicates remain exact. State visits come from real cross-state
before/after observations; an Intent or home call alone earns no destination
credit. Wrong target visits cannot hide before a later matching subsequence.
The progress hint window_changed is not used to pass a case.

The conditional return case does not invent setup navigation when the previous
case left another screen. Its first model-bound observation establishes whether
the search fixture exists. A missing fixture is explicitly inapplicable, never
a model failure or pass. No automatic replay is performed.

## Freeze a new candidate plan

Use the real APK/version/model profile/config and the frozen app tools directory:

    python3 core_phone_suite.py freeze --drivers /absolute/frozen-source/tools --candidate /absolute/candidate.json --suite-id code8-home-r2 --case core-settings-home-01 --output /absolute/new-plan.json
    python3 core_phone_suite.py validate /absolute/new-plan.json

Omit --case for all nine, or repeat it for an explicit subset. Each exact owner,
goal, tool requirement and goal_visits sequence is part of the reviewed contract;
edited relaxed cases fail validation. Freeze/validate do not contact a phone.

## Root operator execution

    python3 core_phone_suite.py run /absolute/new-plan.json --adb /absolute/adb --adb-host 127.0.0.1 --adb-port 5061 --serial ZY22LS7WZT --output /absolute/new-run-directory

Existing-server, exact installed APK/config, idle-session and cleanup checks
remain active. Each case is submitted once. Unknown submission or cleanup stops
the remaining cases. Setup-home remains a test precondition, never a model action.

Only the ordered-home case adds read-only `am get-current-user` and
`cmd package resolve-activity --brief --user <id> -a android.intent.action.MAIN -c android.intent.category.HOME`.
The parser accepts the normal brief priority header and requires exactly one
component. Missing/ambiguous HOME resolution stops before model submission.
The raw output/hash, command, user, case and APK are retained in
home-environment.json. No launcher package is guessed.

Evaluate reads a v2 run offline and writes a separate reevaluation report. It
enforces the frozen core hashes and original base verdict; it does not rewrite
the r1 plan or promote an unfinished task.

## Host qualification

    HEPTA_CORE_TEST_DRIVERS=/absolute/frozen-source/tools python3 -m unittest -v test_core_assertions

35 synthetic regressions pass: launcher clicks, restored search, observed return
button, real visit order, wrong HOME/order, exact keypad/Chinese/find-app binding,
no-input navigation, missing start fixture, no-effect rejection and no upgrade of
an unfinished task. These are host regressions, not phone inference results.
