# Notes reads after an owned display release

This gate executes the complete production `PublicPersonalNotesReader`, `BackgroundTaskOrganizer` and `PublicPersonalNotesCustody` classes with explicit synthetic Android I/O, Binder objects, time and release-return signals. It does not contact a phone or establish device success.

The new reader uses three complete global ATM censuses after the caller has observed the actual display release and display absence. A custody-created `ReleasedRead` contains the already retained actual Task objects. Its constructor is private; it is unavailable before release returns and does not grant cleanup or business authority.

All rows must retain their Binder, UID, display, parent, intent, real/original activity and cookies. Complete global evidence must retain each observed task on its original display. A monotonically shrinking subset of those tasks may cause a complete triple to be discarded and re-read, within the original three-attempt, 1500 ms and request-deadline limits. New tasks, replacement identities, reappearance after disappearance, malformed responses and read exceptions remain refusals. A stable empty frame still needs the original two complete display/live/recents absence samples to finish custody.

## Coverage

The 112 named cases cover the full production reflection path, including a synthetic framework that throws whenever the removed display is queried through `getRootTasks`. Ordinary `frame()` retains that refusal; the new API makes no display-specific root query.

Tests verify exact actual task identity in all three global responses; null, partial and malformed global inputs; complete unrelated global rows; original bounds; presentation-only convergence; deadline and installation checks; and retained custody with pending residue. Focused disappearance cases cover complete and partial removal, repeated shrink exhausting the original bound, additions, same-Binder ABA, cross-attempt reappearance, a changed remaining Binder and an escaped task that disappears before the final census.

No read exception counts as an absence. No empty-activity row counts as an absent task. The opaque released snapshot cannot be created through an ordinary constructor or acquired before release has returned. Existing custody rules continue to reject escaped or replaced tasks, require actual display absence and require two later absence observations.

## Retained behavior

The runner executes the original Notes reader gate against the current production code: 71 reflection cases / 238 assertions, 14 empty-activity cases / 59 assertions, 12 stability cases / 60 assertions, and 47 original private-profile cases / 449 assertions. Those Java tests, the Android I/O fixture generator and the published synthetic fixture remain byte-identical.

Static checks restore only the two new additive Reader/Custody blocks and the one Notes cleanup call to verify the preceding source hashes. The old reader runner changes only its exact current Reader hash. The Ctrip ready-confirmation gate independently reverses this Notes call before checking its own original single-call change.

## Run

```sh
python3 -B tests/notes-after-release-reader/run_host.py \
  --source /absolute/source \
  --java-home /absolute/jdk17 \
  --json-jar /absolute/json.jar \
  --output /absolute/new-output-outside-source
```

The output directory must be new and outside source. The result includes exact source/tool pins, the retained-gate receipt, compile/execute outputs, named cases and assertion totals. Private phone originals are neither accepted nor copied by this gate.
