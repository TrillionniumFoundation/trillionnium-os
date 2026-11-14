# Session recovery and native process lifetime

This candidate preserves uncertainty after an application process restart. It does not resume an old instruction, recreate its controller, replay its actions, or treat the disappearance of a process as proof that the phone task succeeded.

## Startup decisions

When a new application-owned `LocalTaskSession` is created, it checks the independent `control-session.interrupted.json` latch, `control-session.json`, and any AtomicFile `.bak` or `.new` sidecars. Activity recreation within the same application process continues to use the existing session object.

| Observed persisted state | Current behavior |
| --- | --- |
| Any interruption latch, including an empty, malformed, or unreadable one | Block new tasks regardless of what the base record says. Do not automatically clear the latch. |
| No latch, session record, or sidecars | Start with a fresh session. A new task still needs an explicit request. |
| Valid, known-clean terminal record with no latch or sidecars | Permit a new task; retain available prior identifiers for display without resuming the old task. |
| `pending`, `running`, `blocked`, `interrupted`, an unknown status, or unresolved activity/cleanup flags | Block new tasks and show an interruption message. |
| Unreadable, empty, malformed, oversized, wrongly owned, or otherwise invalid record | Block new tasks; do not reinterpret the error as an absent record. |
| Any `.bak` or `.new` sidecar | Treat the interrupted write as unresolved, even if the base record appears clean. |

The known terminal statuses are `not_started`, `cancelled_before_start`, `model_reported_done`, `partial`, `failed`, and `cancelled`. Admission also requires `pending=false`, `running=false`, `blocked=false`, and `cleanup_known=true`, together with valid schema, field types, application UID, timestamp, origin, and instruction/task bindings. A consumed debug request also requires its nonce binding. A terminal name alone is insufficient. In particular, `model_reported_done` does not independently verify the user's goal.

The reader bounds records to 64 KiB, requires valid UTF-8 containing one JSON object, and checks for a direct, single-link, application-owned regular file with mode `0600`.

## Preserving an interruption

For an unresolved session, the in-memory state becomes blocked, with no pending start or restored result. Before archiving or mutating the old AtomicFile, recovery exclusively creates the independent latch with mode `0600`, writes its interruption metadata, and requests synchronization of both the file and its containing directory. Failure at this stage leaves the base record and sidecars untouched; a partially created latch is retained and also blocks subsequent starts.

After that barrier succeeds, readable original records are preserved under the application-private `session-recovery` directory with content hashes before publishing an interruption record. The new base record uses:

```text
status = interrupted
pending = false
running = false
blocked = true
cleanup_known = false
automatic_resume = false
```

Its recovery metadata records the reason, available previous status/hash, and preserved records. It explicitly leaves `native_cleanup_independently_observed=false`. If preservation or publication fails, the independent latch remains. Thus, an old clean base record cannot authorize a new task merely because a failed AtomicFile write removed a sidecar. An existing latch is never rewritten or automatically removed. Existing interruptions do not generate a new archive on every launch.

An observer must check latch presence as well as the base record: after a failed publication, the application can correctly be blocked while `control-session.json` still contains an older clean result. The synchronization calls are part of the implementation; Android crash durability still requires device qualification.

For new work, the `pending` reservation must be written successfully before the controller is queued. Failure at that point prevents the task from starting. A later persistence failure blocks new tasks; it does not by itself prove that an existing worker exited. Normal completion can permit subsequent work only when the controller supplies a known-clean result and the session update succeeds.

## Native parent-death guard

`LocalModelEngine` supplies the application's `Process.myPid()` as the adapter's leading `--expected-parent-pid` argument. Before its first explicit SDK or plugin call, the adapter:

1. Rejects missing, malformed, or duplicate parent arguments.
2. Checks that its current parent PID matches the expected application PID.
3. Sets `PR_SET_PDEATHSIG` to `SIGKILL`.
4. Checks the parent again and verifies the configured signal.

The checks surrounding signal setup prevent continuing under a substituted parent if the application exits before the guard is armed. The adapter then removes its own argument before invoking the frozen upstream worker. The help-only invocation prints usage without starting inference. The model and context contract remain unchanged.

This mechanism limits the lifetime of this runner. It is not an acknowledgement that a phone action finished, does not undo prior effects, and does not establish cleanup of arbitrary descendants or runners launched by older builds. Startup recovery does not scan for or kill processes using stale recorded PIDs. The application receipt distinguishes a requested guard from cleanup proof.

## Operator reconciliation

An interrupted or corrupt session remains blocked pending explicit operator reconciliation. This build has no automatic reset, retry, replay, or implemented operator-unblock command. Restarting the application or pressing Stop does not convert an unresolved prior session into a clean terminal result.

The operator must preserve the latch and available private evidence, identify the interrupted task and any actions already dispatched, establish the actual status of its owned execution, and inspect the resulting phone/app state. A guard request, missing receipt, model completion statement, or assumed PID identity cannot substitute for those observations. Any eventual state repair requires a separately reviewed, explicit maintenance action based on that evidence. Clearing the latch or records merely to remove the blocked state loses the basis for reconciliation and is not a supported recovery procedure.

## Verification boundary

`SessionRecoveryHostTest` exercises the pure Java admission decisions, including incomplete records, conflicting flags, invalid identities, known-clean terminal states, latch precedence over clean/corrupt/missing base records, and the no-resume policy. These are decision tests, not disk-crash fixtures. `parent_death_contract.c` uses a Linux subreaper and bounded waits to verify wrong-parent refusal, refusal after the parent exits before setup, and observed `SIGKILL` termination after an armed worker's parent exits.

These host tests do not qualify Android file persistence, actual Android process restarts, process launch behavior, device-specific signal handling, accessibility side effects, or full phone task acceptance. Those require fresh tests of the exact built APK on the target device, preserving unknown outcomes without replaying the interrupted instruction.
