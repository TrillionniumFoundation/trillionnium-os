# Android integration audit overlay

This directory records the Android repo-manifest inputs and the uncommitted
Trillionnium integration files that were present in the canonical
`lineage-fogos` checkout when the audit snapshot was published.

The Android checkout is a repo-manifest workspace with 1,172 independent Git
projects; it is not flattened into this repository. The complete source
baseline is reproducible from the pinned manifest files under
`../docs/audit/android-manifest/`. The `working-tree/` subtree contains the
current Trillionnium dirty overlay (modified and untracked source files),
with generated `__pycache__` files excluded. `PROJECT_STATUS.tsv` records each
overlay path, its project HEAD, worktree status, and content SHA-256.

This overlay is evidence for external audit and is not an approval gate. It
does not claim that a live Android build, device effect, or OTA has passed.

The `packages/modules/adb/daemon/restart_service.cpp` overlay is based on Android
project commit `318bdb11c42125779a6fc4338da7c2885d277624` and the original file
SHA-256 `6749e17acfe019a39a15208f15775a2cf09ad1fdd39d667d691bffe0a6d36817`.
Its missing Binder-service branch returns an explicit failure message to the
ADB caller. It grants no root authority and does not qualify the owner-open
privileged ingress. Before applying this full-file overlay during qualification,
mechanically verify the baseline SHA-256; a changed baseline requires review.
Use an isolated source view rather than overwriting a dirty original checkout.

The supported GitHub-hosted package to local self-hosted-device workflow is
documented in [`GITHUB_DEVICE_CI.md`](GITHUB_DEVICE_CI.md).


The owner-open client codec exposes `OwnerOpenFrame.RecoveryPlan` for the
Host-advertised `scoped_cursor_v1` recovery extension. Pass decoded Host objects
and the accepted turn digest, send `nextInspection()` through
`OwnerOpenClient.inspectRecovery`, consume each returned page and call
`observeInspection` with that decoded response. Continue until `isComplete()`,
then explicitly call `resumeRecovery` with the next flow-control sequence.
A failed or uncertain inspection leaves recovery incomplete; no effect is
redispatched. `job_runtime_event` and `job_journal_record` are separate domains,
and every job request retains all five parent identifiers plus `job_id`.
[The transport contract](../docs/modules/MOD-TRANSPORT.md) defines negotiation,
unknown/retention handling and rolling compatibility. Host JVM and Rust tests
establish source behavior; installed ingress, APK and physical recovery remain
separate qualifications.


The Shell exposes a **Recover output** action for a current delivery gap. It
reads each saved page, verifies the cursor domain and full scope, displays the
bounded observations, and only then sends the explicit resume acknowledgement.
An ended turn is inspected without reopening its flow window. Unknown scopes,
retention gaps and changed stream state remain visibly incomplete. The view and
pending display buffer each retain at most 65536 UTF-16 characters; one pending
UI update coalesces ordinary output. The operation/frame callback queue holds at
most 16 entries and disconnects on saturation. Socket generations, accepted
turn scopes and Activity teardown fence stale callbacks. JVM stub tests cover
these source state transitions and bounds; they do not qualify Android
rendering, installation, target memory consumption or physical reconnect.
