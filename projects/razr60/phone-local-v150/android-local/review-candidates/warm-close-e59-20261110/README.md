# Warm task close: limited Stop fix for review

This capsule retains a small controller patch and synthetic regression tests for an unpublished task-scoped model worker candidate. It is not an app source tree, build artifact, deployment input, or phone qualification. Publishing this capsule does not adopt the warm candidate.

## Problem and intended behavior

After a model-issued `done(success)`, the controller can wait inside `inference.endTask()` for its retained worker to exit. The real Stop method can accept cancellation during that wait. The observed controller did not reread cancellation after close: a valid terminal could preserve `model_reported_done`, while an invalid terminal changed it to `failed`.

The patch rereads cancellation after close. If action and model cleanup are known, an accepted Stop becomes `cancelled`. Unresolved process exit or an already unknown action outcome remains blocked. A known exit with invalid terminal proof becomes `failed` for full or partial completion, without pretending physical cleanup is unknown. A final blocked state clears the exposed success flag. No action is replayed or undone.

The baseline regression reproduces `Stop during invalid close: expected cancelled, got failed`. The patched exact production fragments pass 13 terminal cases. The existing recovery Application fixture passes 18 cases and 74 assertions with its already corrected extraction boundary. These results were first obtained as supplemental Java21 checks and are now independently recorded on Pocket4's complete OpenJDK 17.0.21.0.3 with the original Java8 target and warning gates.

## Exact applicability and already satisfied work

`BASELINE.json` separates the Git commit used to publish this capsule from the unpublished warm source to which its patch applies. The observed Code29 manifest declares a Code27 parent that could not be found through the connected GitHub repository. There is no verified published warm commit in this capsule.

Before applying, compare the target controller's SHA256 with `controller_patch.before_sha256`. Refuse a mismatch and review the current diff. Do not overwrite the complete controller with an earlier copy. `controller-stop.patch` contains only that controller hunk; it does not include any other warm implementation.

The original five-file review patch remains retained outside this capsule, unchanged. Its recovery extraction hunk is **already satisfied in the observed Code29 candidate**. The required fixture SHA is recorded in `recovery_fixture.required_current_sha256`. This capsule does not republish or rewrite that fixture. If a different target does not have those exact prerequisite bytes, reconcile the prerequisite separately before running the recovery regression.

## Copy into a separate warm source checkout

These tests extract exact production members and therefore must run from a complete, matching warm controller source tree. They cannot run against this capsule alone or against the older source at the capsule's publication parent.

1. Create a separate checkout or copy of the matching warm source. Keep the active shared candidate untouched.
2. Verify the controller and already satisfied fixture hashes in `BASELINE.json`.
3. Apply `controller-stop.patch` from the controller source root.
4. Copy the following three files from this capsule to the same relative paths under that source root. Their original bytes and SHA256 are retained in `BASELINE.json`.

- `tests/warm-finalization/prepare_fixture.py`
- `tests/warm-finalization/WarmFinalizationHostTest.java`
- `tools/test_warm_finalization.py`

With the target host's existing complete JDK, run from that warm source root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 tools/test_warm_finalization.py
PYTHONDONTWRITEBYTECODE=1 python3 tools/test_recovery_application.py
```

The test entry points retain `--release 8 -Xlint:all -Werror`. `HEPTA_TEST_JAVA` and `HEPTA_TEST_JAVAC` may select the actual installed executables. No JDK download or relaxed compiler gate is part of this capsule.

## Evidence and qualification limits

The retained local behavior checks used the existing Java21 compiler module with `-Xlint:all -Werror`. They compile the exact production Stop, `endTask` handling, terminal decision block and cleanup contract in an explicit host fixture. A latch holds close in progress while the test invokes the real extracted Stop method. Android listeners, model IO and filesystem result publication are fixtures. The fixture extraction identities are bound in the retained original evidence.

The initial Java8 attempt could not run in the local runtime because `ct.sym` is absent. The first Pocket4 host-check request returned an MCP timeout, followed by channel Internal errors. That original request remains **UNKNOWN and unreconciled**; the later results below come from a separate, explicitly identified host run. The unchanged WarmProcessSession compilation had also encountered a Java21 serial warning under `-Werror`; that historical result is retained without suppressing the warning.

A later isolated Pocket4 run used the existing complete OpenJDK 17.0.21.0.3. The original `--release 8 -Xlint:all -Werror` checks were preserved:

| Host check | Recorded outcome |
| --- | --- |
| Baseline terminal regression | Expected exit 1; reproduced Stop during invalid close being reported as `failed` instead of `cancelled` |
| Patched terminal regression | Exit 0; 13 cases passed |
| Existing recovery regression | Exit 0; 18 cases and 74 assertions passed |
| Unchanged WarmProcessSession strict compilation | Exit 0 with the original Java8 target and warning gates |
| Combined runner's supplementary behavior launch | Exit 1: the runner named a nonexistent packaged test class |
| Separate corrected behavior launch | Exit 0 using the actual main class `WarmProcessSessionHostTest`; real subprocess lifecycle with a synthetic model peer |

The original combined result keeps `all_expected_outcomes: false`. The corrected invocation is a separate result and does not overwrite that failure or turn the earlier timed-out request into success. The original combined-result SHA256 is `370fd28160a715aea489447fb11c398863429087d5562ccd129ab29fcf4c5e01`; the separate correction SHA256 is `89ec2191336dd292dd0d22f7b68ac2035fb599ef330d3e99a46c503df613ba80`. Retained local transfer copies add one trailing LF; removing only that LF reproduces each original hash. `VALIDATION.json` records both identities and concise path-normalized outcomes.

This establishes the scoped host regressions and strict compilation, not a complete Android or phone gate. No Android build, inference, GPU/NPU execution or phone task was performed by these host checks. The three included logs remain the byte-exact earlier Java21 synthetic host outputs; the later Pocket4 results are summarized separately. This capsule contains no real phone logs, prompt histories, app captures, device identifiers, model weights, credentials or full warm source.

## Independent review and remaining race

Independent source review supports this limited change: cancellation accepted during `endTask` is reclassified after known cleanup, unknown effects remain blocked, and invalid receipt proof is not confused with unknown process exit. This is not a formal non-author GitHub approval or approval of the full warm lifecycle.

**The final `cancelled.get()` and result publication are still not atomic.** A Stop can arrive in the remaining tail window after that check. The 13 cases cover Stop while close is in progress; they do not close or test the later publication race. Android scheduling, disk faults after the close decision, actual model reset behavior and phone effects remain outside this capsule's evidence.

The patch is an unadopted D3 lifecycle proposal with D5 evidence statements. It changes no task/session schema, model profile, resource budget, prompt, action domain or external-model boundary. The publication introduces no executable app overlay. Actual integration requires the matching warm base, repeating the original host gates on the integrated revision, Android build gates, and separate device ownership/acceptance. Rollback is removal of this unapplied review capsule, or reversal of the controller hunk in its exact reviewed source; it does not restore or replay phone tasks.
