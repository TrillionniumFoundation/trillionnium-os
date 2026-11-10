# Rejected-action observation journal

Affected producer: `org.trillionnium.hepta.local.LocalTaskController`.
This additive evidence change retains the existing task, action and observation
JSON shapes. It does not change model inputs, action permissions, native
inference, stale thresholds, Stop handling, task deadlines or dispatch behavior.

For an observation-ID mismatch, the controller records the original model
decision and run ID with `accepted=false`, `dispatched=false`, `stale=true`.
It preserves the mismatched ID; the record is evidence of rejection, not a valid
fresh action. The record also survives a subsequent consecutive-stale refusal.

For both this mismatch and an existing stale/non-dispatched action outcome,
`step-XX-after.json` is written only after `awaitObservation` returns the real
fresh observation. The existing transition and `continue` follow that write.
A failed observation, Stop, deadline or exhausted stale allowance never produces
a synthetic after record. Existing record-publication failures propagate; they
cannot continue to another model request or action through these branches.

Each recovered rejected step adds at most one bounded observation JSON write;
the mismatch branch also adds one rejected-action JSON write. The existing
observation and task limits remain. There is no extra observation, inference,
action, automatic replay or copied-before-as-after path.

The host fixture extracts both production branch bodies unchanged. It exercises
fresh observation identity, retained wrong action ID, native run association,
await failure/Stop/deadline, stale exhaustion, record-publication failure and
unaffected non-rejected branches. Android observation, JSON rendering and file
publication are explicit deterministic boundaries; these tests establish no
Android build, physical phone behavior, performance measurement or business
task qualification.

The existing full host runner discovers `tools/test_stale_observation_journal.py`.
Its original Java release and warning flags remain. Reverting this isolated
producer change restores the earlier missing-record behavior; historical task
directories and scores must never be backfilled. Consumers must retain the
distinction between a bound rejected proposal and an accepted fresh action.
