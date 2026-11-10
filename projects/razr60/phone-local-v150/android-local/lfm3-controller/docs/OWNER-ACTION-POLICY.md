# Original-owner action restrictions

VersionCode 35 adds an immutable per-task action policy to the existing local
controller and Accessibility service. The only policy input is the original
instruction accepted for that task. Screen text, model reasons, model output,
recorded history and application content cannot grant action permission.

## Responsibility and limits

`OwnerActionPolicy` compiles a deliberately finite subset of explicit action
restrictions. It can remove action types from the existing domain. It cannot
grant a permission rejected by qualification scope, target labels, freshness,
protected-screen checks, task ownership, cancellation or the existing effect
guards. It does not select a model, change sampling, alter native execution,
write runtime configuration, add a tool or require a new confirmation screen.

The policy is not an interpreter for arbitrary natural language. Goal identity,
business effects, order, page semantics and conditional stopping remain outside
its proof. `done` remains a model claim that needs independent goal acceptance.
Preventing a forbidden action establishes permission enforcement, not successful
completion or model understanding.

## Supported input contract

The finite action vocabulary is `find_app`, `open`, `click`, `type`, `scroll`,
`back`, `home`, `wait` and `done`, with explicit aliases in the Java source.
Complete standalone clauses such as `不点击、不输入。` remove those types.
An explicit complete list such as `只查找、打开和结束。` intersects the domain
with `find_app`, `open` and `done`. Multiple restrictions intersect; none can
restore a removed type.

Input is bounded to the controller's accepted task instruction. The compiler
binds the exact original UTF-8 SHA256 before normalization. It uses NFKC and a
small fixed syntax, masks quoted data while retaining an opaque object token,
and never strips a double negation into a positive restriction.

Recognizable action restrictions outside that complete syntax refuse task
admission as `unsupported_owner_action_constraint`. This includes object-scoped
restrictions such as `不点击删除按钮`, conditional restrictions such as
`进入目标页后，不点击`, and conditional exclusive lists. The compiler does not
promote a restriction on one object or phase into a restriction on the whole
task. Quoted text such as `输入“不点击”到搜索框` is data. Unmatched quotes are
unsupported. The exact recognized vocabulary and conditions are finite; phrases
outside them are recorded as uncompiled fragments rather than certified as
fully enforced instructions.

## State and effect boundary

The controller compiles once from its original task ID and instruction before
model admission or observation. It saves `owner-action-policy.json` and binds
the policy to the service's current task lease exactly once. Unsupported input
ends through the existing cleanup path without starting inference or dispatch.

After a decision parses, the controller checks its action type before the
existing structural and label validator. `OwnerActionPolicy.Violation` is a
distinct exception, outside the format-repair exception path. A forbidden
decision records one refusal with `accepted=false`, `dispatched=false`,
`stale=false`, the violation code, policy identity, model run and raw-output
hash. It is not retried as malformed JSON or stale observation.

The service captures both the qualification-scope object and the immutable
owner-policy object when work is queued. It checks the captured policy and
task identity again at the effect boundary, including the asynchronous
coordinate-click callback. A replacement lease cannot be borrowed even if a
synthetic caller reuses a task-ID string. Deferred callbacks keep the captured
old policy in their receipt. Cancellation or retirement cannot erase an effect
that was already dispatched; its `dispatched=true` fact remains.

A permission refusal yields a failed task with a specific owner-constraint
reason. Stop/cancellation and unknown-cleanup priorities retain their existing
meaning. Unknown native or gesture cleanup remains blocked. The patch does not
replay an action or automatically start a replacement task.

## Evidence and interfaces

Policy evidence has schema `hepta.owner-action-policy.v1`, the task ID, original
instruction SHA256, policy SHA256, allowed and denied action types, compiled
rules, unsupported constraints and uncompiled fragments. It explicitly states
that complete instruction semantics and goal/effect/order/condition verification
are false. Task and action evidence add the policy and refusal code; existing
scope, raw-model and cleanup evidence remains available.

The changed boundaries are MOD-ANDROID and MOD-EVIDENCE. The change classes are
D1 implementation, D2 additive receipt fields, D3 captured task-lease/callback
lifetime, D4 restriction of execution authority, and D5 evidence and tests.
No cross-task policy store or runtime-config migration is introduced.

## Verification and promotion

Run `python3 -B tools/run_host_checks.py --out <new-private-output>` with the
existing complete JDK and C compiler. The host gate retains the full previous
suite and invokes `tests/owner-action-policy/run_host_tests.py --release8`.
The qualification-scope fixture now binds an explicit synthetic owner lease.
Owner tests compile the actual full controller and policy, and exact service
lease/dispatch/coordinate-callback bodies. Only Android/model/IO endpoints are
synthetic. Tests cover forbidden actions before label repair, direct service
bypass attempts, actual scope and label intersections, lease retirement,
already-dispatched effects, unknown cleanup and unsupported language ranges.

Public fixtures are synthetic and contain no phone serial, private screen dump,
task directory or signing material. Host contract passes do not establish an
Android build, accelerator execution or phone acceptance. Build promotion must
bind the exact Git source inventory, actual compiler inputs, generated identity
asset and signed APK. Phone acceptance still needs the exact installed APK,
current model/backend/configuration and independent final-state evidence.

Keep the prior signed APK and evidence for rollback. Restoring an older build
removes this new permission gate and is not a successful test of it. Use the
existing reviewed version/signer strategy; do not uninstall, erase task/model
data, migrate an existing task policy silently, or replay unresolved work.
