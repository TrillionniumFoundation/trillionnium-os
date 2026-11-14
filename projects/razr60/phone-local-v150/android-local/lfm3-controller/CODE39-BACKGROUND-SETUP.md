# Code39: ordinary owner UI preparation for background execution

Candidate `39 / 0.39.0-local-background-setup` is based on the frozen v38 source
at commit `45b45a7eb3312ca58e798cbd3b1a8c7b3ea5c0d4` (tree
`700b6bb1c479b07c6b665e5484b4e9a90a1893c7`). Its implementer did not access the
phone, run su, change Magisk policy or commit code. Android compilation and actual
Magisk/phone acceptance are separate gates.

## Owner flow and exact effect

The ordinary MainActivity adds **启用后台执行权限**. Only its visible, focused
owner-button callback invokes the Application preparation entry; no Intent,
private debug nonce, controller tool or model output can supply a preparation
command. The ordinary constructor launches exactly:

```text
argv[0] = su
argv[1] = -c
argv[2] = /system/bin/id -u
```

The parent must be the installed Hepta ordinary application UID, with matching
current and ApplicationInfo UID and the exact Hepta package. No shell UID,
run-as impersonation, root parent or model-provided argument is accepted.
The child command reads its effective UID; it creates no display, starts no
broker/task/model and does not modify the root manager's policy database.
The root manager handles its normal authorization UI.

Only full stdout exactly `0` or `0\n`, natural complete stdout/stderr within the
size bounds, observed exit code zero, no cancellation/timeout/termination, and
durably published terminal evidence produce `permission_verified=true`.
This says that this one identity probe succeeded. It is not a claim of permanent
authorization, background display isolation or a successful App task. A one-time
grant or later revocation can still cause another authorization request.

The main model-information line no longer displays changing available-RAM values.
It keeps the model/backend, local-model status and accessibility status. Memory
admission and diagnostic checks are unchanged.

## Ownership, deadlines and interruption

BackgroundPermissionSession is owned by the Application. It reserves the existing
LocalModelEngine.ExternalRunLease before queueing its worker. A second click,
ordinary task, native/model diagnostic or recovery borrow cannot share that slot.
An additional permission-preparation guard covers direct controller entry and the
BackgroundSession broker-spawn boundary, which precedes model inference.
Background cleanup/recovery use the narrow preparation guard, so an unrelated
existing recovery barrier is not mistaken for a running preparation.

The authorization wait is bounded to 60 seconds, followed by bounded termination
and output collection. Only the exact owned Process is signalled. Stop uses the
same lease cancellation. Activity recreation/rebinding neither launches a new
probe nor changes process ownership.

Two facts remain distinct:

- `cleanup_known` concerns the owned Process being unstarted or actually observed
  to exit, with the terminal receipt published before release.
- `permission_verified` concerns the strict successful identity-probe result.
  Cancellation, timeout, incomplete output or a late exit cannot establish it.

If the exact Process has not been observed to exit, the same-instance lease is
retained. A passive observer may later waitFor that same Process, write a separate
`late-exit.json`, keep `permission_verified=false`, and release only its own slot.
It does not re-execute the probe, start work or infer the root manager's final
authorization policy. Output collection is bounded; closing an unfinished owned
stream is never reclassified as natural EOF.

After an Application process restart, a structurally valid historical pending or
unknown identity probe is recorded as interrupted/unknown. It is not resumed or
called clean, and historical success never restores a current “ready” state.
A new explicit owner click may launch a new read-only identity probe after
archiving the old marker's exact bytes. This is appropriate because a late `id`
command cannot create a display or operate an App. There is no new phone-reboot or
unlock workflow. Existing task, display-lease, scope and recovery barriers remain
unchanged and independently constrain the new owner entry.

## Evidence and storage

Private evidence lives in `background-permission-runs/<request_id>/`:

- `request.json`: ordinary UID/package, fixed argv, deadline and source.
- `result.json`: observed process exit, complete/overflow/read-failure fields,
  bounded stdout/stderr sizes and hashes, authorization verification and cleanup.
- `late-exit.json`, when needed: actual late waitFor receipt, preserving unknown
  authorization and the previous result hash.
- `previous-interrupted-record.json`, when needed: exact historical marker bytes.

`background-permission-session.json` points to the terminal receipt by filename
and SHA-256. Writes use the existing exclusive/no-follow private file helper,
file fsync, atomic marker replacement and directory fsync. A terminal-publication
failure does not release the lease or display a successful authorization state.
Malformed identity records, unresolved sidecars or storage latches remain explicit
storage failures; none can confer permission.

## Verification scope

The bounded worker tests execute the actual pure production class. Session tests
execute full BackgroundPermissionSession and MobiMindPrivateFiles with exact
production ExternalRunLease/RunHandle extraction. Application tests execute the
full production Application and exact Engine external/recovery methods. Android,
Magisk, child-process effects and filesystem authorization are explicit host
fixtures; these tests are not real phone or Android-runtime evidence.

The normal full host gate adds both permission worker and permission session
suites while retaining `--release 8 -Xlint:all -Werror`. The development executor's
stripped JDK cannot satisfy that API gate; supplemental source/class-target-8
results must not be described as full release qualification.

The root broker implementation/protocol, qualification scope, runtime/model
configuration, native code and visual-model/tool integration are unchanged.
BackgroundSession retains its existing lease/timeout semantics; preparing a grant
before a background task reduces the first-prompt setup problem but does not
guarantee persistent root authorization or successful background App operation.
