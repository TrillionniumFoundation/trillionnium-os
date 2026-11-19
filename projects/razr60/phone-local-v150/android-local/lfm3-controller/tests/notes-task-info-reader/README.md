# Notes TaskInfo reader host regression

Run the complete production reflection adapters with the committed synthetic task census:

```sh
python3 -B tests/notes-task-info-reader/run_host.py --source /absolute/source --output /absolute/output --java-home /absolute/jdk --json-jar /absolute/json-20240303.jar
```

The output must be a new directory outside the source. The runner pins JSON jar SHA-256 `3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed` and both reviewed production adapters. It compiles with Java 8 API restrictions, executes 71 reader cases with 220 assertions, and retains the original private profile broker suite of 47 cases with 449 assertions.

The default input is `synthetic-notes-census.json`, 18,714 bytes, SHA-256 `8b44610ab210e5882d5de0cb61583992ccb626ed021b63af277f47407c3af201`. It contains three ordered samples derived from an observed ordinary root/leaf shape, with explicit synthetic identities and Binder relations. It is not a replay of phone bytes. Host Android ports, Binder tokens, and the clock are synthetic; no phone is contacted and no Android hardware qualification is claimed. `input_mode` is `synthetic_derived_fixture`, `archived_capture_replayed` is false, and `actual_capture_sha256` is null.

An optional `--actual-census /absolute/capture` mode accepts only the separately archived, complete 44,577-byte capture with SHA-256 `e0c6a2c1eee8d0d490df7ffd381149ffa443ab4c756bd4fdc41f960ef115db9c`. That mode rehydrates captured task values through host fixtures and is still not a live device run. The capture is not bundled in this repository.

The production fix retains the generic null refusal. Notes reads a complete root/leaf census before and after the organizer root snapshot, requires the same exact task and Binder identity, validates the ordinary root is its sole leaf, and keeps installation, user, UID, component, display, cookie, time, and physical-fence checks. A global null response, absent or inconsistent child arrays, nested or foreign task, changed identity, or incomplete census remains a refusal. `RootTaskInfo.visible` and `TaskInfo.isVisible` retain their distinct meanings. This fix does not retire an existing quarantined broker or rewrite an old failed task result.

The canonical runner owns registration of the default synthetic gate and checks the v2 provenance, exact fixture, unchanged inputs, the original case/assertion totals, and four actual successful compile/run stages. The README is documentation; it introduces no additional runtime authority or test threshold.

Android 16 empty-activity compatibility adds a separate 14-case / 59-assertion
receipt without changing the original 71 cases / 220 assertions. A coherent
zero-activity root keeps its real UID, Intent, realActivity, token and leaf identity.
Null base/top with top UID -1 and isRunning false does not prove task absence.
The custody case retains that root as pending, then requires two complete later
absence samples. Malformed tuples, active missing base, foreign identity and
changed tokens remain refused. The diagnostic case preserves the exact rejected
row and separates the first runtime refusal from the first cleanup refusal.
These are synthetic framework tests; they do not recreate an unrecorded live
TaskInfo sample or qualify phone cleanup.
