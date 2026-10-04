# Android integration audit overlay

This directory retains Android repo-manifest capture inputs and Trillionnium
integration source. Start current development and qualification from
[the G1 entrypoint](../docs/START_HERE.md).

The [capture metadata](manifest/CAPTURE.txt) describes the 2026-08-27
`lineage-fogos` observation. Its [resolved project manifest](manifest/manifests/trillionnium-fogos.xml)
records 1,172 exact Git revisions; the project contents are not flattened into
this repository. The `working-tree/` subtree contains integration overlays;
`PROJECT_STATUS.tsv` retains the captured path, project HEAD, worktree status
and content SHA-256. These capture records do not establish the current
checkout, overlay byte equality, private-fork state or Android build inputs.

The [current owner source gate](../tools/owner_source_provenance.py) selects
`owner-open-whole-control-v4`: 1,170 measured projects comprising 38 exact
private projects, 1,131 original projects and one control project. Its current
resolved manifest, complete content inventories, before/after vectors and
private-fork receipts must bind the same candidate; the older 1,172-project
capture cannot substitute for them. The two Motorola non-Git vendor trees and
generated-source checks remain additional inputs. Follow the existing
[owner Android contract](../docs/modules/MOD-ANDROID.md) and
[target-files binding consumer](../tools/verify_owner_target_files_binding.py)
for their separate contracts.

Neither a retained manifest nor a control-repository source archive proves a
complete current Android checkout or built image. Installed-target, device,
fault, signing and release evidence remain separate qualification gates.

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
