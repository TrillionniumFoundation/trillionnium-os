# v55 forward integration contract

This standalone Android component remains outside the active Cargo/G1 delivery
graph. Affected boundaries are MOD-ANDROID and MOD-EVIDENCE; changes are D3
(observation/concurrency/lifecycle integration) and D5 (complete source identity
and scoped tests). No active product profile or semantic principal changes.

## Inputs and preserved behavior

| Input | Exact upstream identity | Retained behavior |
| --- | --- | --- |
| v53 | `7dee83d838b2c76b3abe3a3e61d7837316f40853` | Official-page helper evidence, Web journal/recovery, Notes parsing, native owned-worker cancellation, model and runtime configuration |
| PR #145 | `78c464e27133c07d7b74392d18773581e6f182ae` | Empty split paths with null split names remain a valid base-only APK identity |
| PR #144 | `7079f2eb499368c302aac00ca38099239a89519e` | Process-wide observation worker, event/display publication fences, late-Stop completion revocation, explicit configuration-error UI and strict v6 fixed-intent verifier |

The common source ancestor is v52 commit
`9414df636f5a20e3b5a5ee7582af9d81beb17aac`. Original component Git tree identities
are retained by the integration evidence. The version is 55; old v54 assembly
and acceptance pins remain evidence for their original subject only.

## Ordering and resources

The single observation IO worker and its process-wide busy flag are retained
from v54. An actual pending read blocks new service admission even after service
replacement. The v53 durable Web-session gate is independently required. A
clean observer does not erase a pending Web journal, and a released Web session
does not turn a still-running observation into completed IO. Recovery checks
all three observer, background-display and Web-session states together.

The production observer fixture covers these conjunctions, late callback
retirement, absolute deadlines and display event isolation. Android graph,
screenshot, looper and Web journal state are explicit host IO fakes. The actual
admission/recovery and observer methods are extracted unchanged for execution.
The existing cancellation suite also runs a real host child process; it is not
a proprietary SDK, DSP or Android execution test.

One observer, one task model worker and the existing bounded budgets remain.
No additional model process, weight cache, context budget, network fallback or
background application authority is introduced. Scheduling improvement is
unmeasured on Android. Synchronous action-validation graph/identity calls remain
on the main looper and may still block Stop; this integration makes no worst-case
response-time guarantee.

Background launch also now refuses target launch/document modes outside the
existing standard/NONE fresh-task policy. Root-task top/base/name metadata can
omit a buried activity, so absence in that snapshot is insufficient authority
to use a framework task-reuse mode. The broker retains the policy observation
before refusal and refuses before changing Intent flags or dispatching launch.
Supported fresh-task launches keep their original behavior. This narrows app
compatibility; it does not establish complete isolation when target activities
later launch other apps or when the user concurrently opens the same app.

## Build, compatibility and deployment

The complete source manifest is regenerated for the actual integrated member
set. `tools/verify_source.py` remains unchanged. Run its exact membership/hash
check and the complete `tools/run_host_checks.py` with a complete JDK supporting
`--release 8 -Xlint:all -Werror`; supplemental source/target flags are insufficient.
Historical reports are not qualification of this new tree.

Runtime configuration, task/session schemas and package identity retain v53's
behavior. The v53 native cancellation implementation is preserved byte for byte;
the old v54 APK's native-worker pin must not overwrite it. The v53 Web helper
signature permission is preserved. No INTERNET permission is added.

An actual Android build and original-signer assembly are required for this new
source. The existing v51-to-v54 one-shot installer is intentionally unchanged
and cannot install v55. A v55 installer must first bind the freshly observed
installed APK/configuration/UID, the actual v55 assembly and the normal original
operation lease. Do not change old pins to make it accept this candidate.
Preserve weights, journals, configuration and unknown outcomes. No uninstall,
data clear, lock bypass, permission change or automatic action replay is part of
this source integration. A rollback requires a compatible same-signer/version
plan and independently reconciled task state.

## Remaining acceptance and claim limits

Same-version phone evidence must cover ordinary Start/Stop, Notes save/list/
same-item readback, local accelerator placement, full native cleanup, Web helper
cleanup, cold reopening, interrupted observation, display loss and real concurrent
main-screen typing/scrolling/app switching. Main-screen-idle Notes evidence does
not establish concurrent noninterference.

The normal controller remains text based. Its separate visual probes are not
connected to action dispatch. TaskCompletionGate can independently verify the
supported Notes workflow; official-page navigation/field evidence is not a
flight-result completion provider. Shopping and flight results remain open.
Host tests, source closure and an eventual APK build cannot close those gaps.
