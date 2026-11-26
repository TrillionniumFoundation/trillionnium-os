# Bounded public-profile cleanup after a returned owned leaf removal

This focused regression compiles the actual owner/custody classes, the complete
changed broker close/worker methods, and the two actual guarded organizer effect
methods. Android service responses, retained Binder wrappers, clocks and waits
are explicit host I/O ports. It does not run on the phone or qualify a device.

## Evidence and scope

The fixed original Xiaomi task is 277631ac4db44fb5a7ca0e130e22fdb3.
Its broker recorded cleanup start 1039659911, task-read deadline 1039661311,
last public-history sample 1039661294 and TASK_RETIRE /
PROFILE_LEAF_RETIRE_NOT_CONFIRMED at 1039661319. The model's success claim was
verified, but the original overall business result and cleanup remained failed
and unknown. This test preserves those files.

The archive does not contain every intermediate global census or the exact
leaf Binder return time. A synthetic mixed global/recents transition uses the
measured 1383/1400/1408 offsets. It reproduces the old refusal without claiming
that this is the uniquely established real-device interleaving. The baseline
is compiled from the exact f4 production sources, not a copy of its algorithm.

## Candidate boundary

Only a public-profile live owner and the original authenticated close can create
the in-memory cleanup phase. The first leaf effect must enter and return
normally within the unchanged 1400 ms boundary. A late/throwing first effect
does not activate continuation and is never retried.

The activated phase has one fixed deadline: min(cleanup start + 3000 ms,
original request deadline - 150 ms). The application's original 3500 ms close
request remains unchanged. Every subsequent root deletion or display release
requires a new complete identity/absence sample, less than 1500 ms old and still
within the fixed phase budget. The guarded organizer overloads check this again
after package/wrapper preparation, immediately before the actual Binder call.

Unknown custody is monotone. New/replaced roots, changed UID/cookie, children,
a moved leaf, changed installation, changed protected public recents, stale
samples, failed effects and quarantine all refuse further cleanup. A returned
leaf or root effect is never replayed. Normal close can also clean resources
after business cancellation; it does not clear cancellation, reopen action
admission or convert that business result to success.

## Actual coverage

The runner executes, in order:

1. Exact f4 owner baseline with the synthetic measured-boundary projection:
   expected exit 3, elapsed 1408 ms, one leaf call and zero root calls.
2. Current production extraction with 35 focused cases / 337 assertions.
3. Current owner without the optional phase: the same old expected refusal.
4. The unchanged private-profile host suite: 47 cases / 449 assertions.
5. The unchanged public-history sampling suite: 9 cases / 55 assertions,
   three full history reads and its original 1400 ms budget.

Focused cases cover the second close wait after the first 1500 ms wait expires,
root/UID/cookie/display changes, same-package main-screen changes as audit only,
full history/installation changes, final adapter freshness checks, once-only
effects, quarantine before/during/after cleanup, late callbacks and cancellation.
All actual extracted method bodies are preserved verbatim and enumerated in the
report. Top-level fixture types are emitted as separate Java files so strict
javac warnings remain enabled.

## Invocation

Run run_host.py with explicit --source, --baseline-source, --java-home,
--json-jar, --actual-task and a new external --output directory. Baseline
production, actual original archives, JSON dependency and the synthetic complete
recents fixture have fixed SHA-256 pins. Reports retain exact argv, every compiler
input before and after, extracted method identities and all stdout/stderr.

The first preparation run exposed only javac's auxiliary-class file-placement
warning, and the next run caught an incorrect expected refusal label in one
new test. Both failed reports are retained. Production was unchanged between
those preparation runs and the final green run. Final device replay remains
necessary; host success alone does not establish that the real 277 leaf call
returned within the original deadline.
