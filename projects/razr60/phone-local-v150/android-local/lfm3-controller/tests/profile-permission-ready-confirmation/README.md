# Permission exit during final ready confirmation

This host gate executes the production `ProfileOwnedTask.confirmInitializationReady` and `ProfilePermissionTransient` classes. It reuses the existing extractor for the complete `ProfileTaskPlatform.requireSamePermissionPair` implementation. Android framework rows, Binder objects, time, the dump boundary, and the history I/O port are explicitly synthetic. No phone is contacted, no Android adapter is compiled here, and these results do not establish that a device task succeeded.

## Scope and assertions

The new API is called only by the second read in the broker's `prepare_done` branch, after the existing initialization-state and physical-fence checks. Its retry is limited to one complete replacement observation using the caller's original request/lease deadline.

The authored fixture retains the same root/leaf Binder, task IDs, display, users, full UID, parent, cookies, intent, base, real activity and original activity. Both task presentations change from the verified permission controller with two activities to the target App with one activity. It preserves the failure shape without including private task identifiers, timestamps, paths, screenshots, or copied device originals.

The 114 named cases cover:

- Stable target and stable permission outcomes, an empty unclaimed target, and the exact transition at either pair-read boundary.
- Refusal of changes to every stable identity field, cookie addition/removal/replacement, invalid activity count, foreign or missing top, hidden/stopped state, and a partial root-only or leaf-only transition.
- Mandatory prior leaf ownership and root cookie; the legacy cookie-exit state exception does not enter this API.
- A second complete graph read with every after-pair field pinned, fresh global and recent-task checks, unchanged retained ownership, and no third read when the replacement changes.
- Cancellation and installed-target checks before/after the gap and at completion; the original deadline accounts for read and pause time without renewal.
- Unchanged strict ordinary `observe`, business-window and permission-window behavior. A later business-window request must perform its own fresh observation.

Every changed-pair path returns no permission proof and performs no task or display mutation. The public recent-history fixture delegates row parsing and basic target checks to the existing production recents policy; it is an explicit synthetic port, not a replacement implementation of Android public-history collection.

The runner also executes the unchanged prior gate (16 permission cases and 29 state-settle cases), checks its exact file hashes, verifies original method hashes, and verifies the exact ready-confirmation call change after independently reversing the separately reviewed Notes after-release read call. Result receipts include source hashes before/after, compile and execution outputs, extraction hashes, named cases, and assertion totals.

## Run

```sh
python3 -B tests/profile-permission-ready-confirmation/run_host.py \
  --source /absolute/source \
  --java-home /absolute/jdk17 \
  --output /absolute/new-output-outside-source
```

The output directory must not exist. A nonzero process result or any missing/failed result contract is a failure. Test outputs remain outside the source tree. The existing synthetic activities fixture is consumed unchanged; no private replay input is accepted by this new runner.
