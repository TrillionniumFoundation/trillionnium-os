# Code41: background startup repair

Candidate `41 / 0.41.0-local-background-repair` is based on frozen v40 commit
`d59542de6e7d67c81a60275571f008c21d17b3dd`.

The reviewed background overlay and app-label fixture correction are integrated
in this candidate. No complete v41 host gate, Android build, installation or
ordinary phone task has passed yet.

## Confirmed predecessor failures

The ordinary v39 background Start failed before its first model step. The client
reported `socket not created`; the broker exited 70 and the recorded display ID
remained -1. The previous read-only permission probe had already verified a root
command under the ordinary application UID. Permission verification therefore
does not establish a working background session.

The source contained two independent startup blockers: it configured the local
socket timeout before Android had created its file descriptor, and it treated
the framework's `unknown` name for an empty organizer child as an unresolved app.
An absent display ID or a broker exit does not by itself justify changing an
unknown cleanup receipt to success.

Separately, the exact v40 source passed Mac Android compilation with 172 compiler
inputs, but its full Pocket4 host gate failed. Of 267 Python tests, the app-label
controller test was the single error: its derived fixture still injected a
grammar field after the base fixture had acquired that field itself. v40 was not
signed or installed. The original source and failing build evidence are retained.

## Background client and task snapshot repairs

`BackgroundSession.exchange` now connects the local socket before configuring its
read timeout. A failed connection still becomes the existing typed
`ConnectionUnavailable` result. Peer UID validation remains before any request
bytes are sent; request identity, size, generation and response checks remain in
place. No connection deadline, retry policy, task permission or broker operation
is expanded.

The broker reads the root task's `numActivities` field. Android computes this
over descendant non-finishing activities; zero must not be described as total
absence of all activity records. Only the exact child name `unknown` may be
skipped when the same root has zero such activities, is not visible, and has
neither a top nor a base component. Malformed names, missing fields, inconsistent
child arrays, out-of-bounds metadata and unknown names on nonempty or visible
roots still fail. Resolved package/component names remain in the snapshot even
when the activity count is zero, preserving cross-display app conflict checks.

The existing client fixture now reproduces Android's requirement for a created
socket before `setSoTimeout`, and checks connect/timeout/peer-authentication/IO
order and the typed absent-endpoint path. The broker tests compile the exact
production snapshot method and row policy with controlled framework field
fixtures. Cases cover the observed Razr organizer shape and negative variants;
these fixtures do not constitute an Android framework execution.

Primary implementation references for the framework metadata are:

- <https://android.googlesource.com/platform/frameworks/base/+/2f75500dfe0f3a7b0d6f7c57a843a09c55e9557b/services/core/java/com/android/server/wm/RootWindowContainer.java>
- <https://android.googlesource.com/platform/frameworks/base/+/a42e14ce6379/services/core/java/com/android/server/wm/Task.java>

## Bounded broker diagnostics

The app drains the owned Java `Process` merged stdout/stderr stream and retains
at most 65,536 bytes. It continues draining after the storage limit, avoiding a
full output pipe. Bytes and an independent JSON receipt are written with the
existing app-private, exclusive-file helper under the current task directory as
`background-broker-<generation>.bin` and `.json`.

The receipt binds the task, generation, app UID/PID, Java Process reference,
command hash and stored-byte hash. The Process reference is not an operating
system PID. It records observed/stored sizes, overflow, EOF/read failure and
whether persistence succeeded. The first terminal or session-close snapshot is
retained; a session-close snapshot may be partial and explicitly records its
capture reason and EOF state. Existing diagnostic files are not overwritten or
pruned by this change.

These diagnostic bytes never become model input, root command authority or lease
release evidence. Log text, EOF, process exit and a claimed release do not bypass
the existing authenticated cleanup, display and journal checks.

## Supplemental local verification

The actual full background client class passes 51 cases: the original 46, three
socket lifecycle regressions and two bounded-log/cleanup regressions. The
existing broker protocol suite passes 43 cases, and the exact production task
snapshot fixture passes 17 cases. These local results use either Java 8 syntax
and class targets or the available development JDK; they are not the complete
strict Java 8 API release or Android build gate. The unified host entry retains
all 92 existing record names and order, and the Android compiler input plan
remains 172 source files.

## App-label fixture repair

`tests/app-label/prepare_fixture.py` now uses the grammar field and assignment
already provided by the exact-admission base fixture. It verifies both expected
fragments occur exactly once instead of inserting duplicate members. The
production prompt builder, answer serialization, engine receipt extraction and
existing Java/Python assertions remain unchanged.

The existing exact fixture test passes 17 Java assertions and the two Python
grammar/receipt consumer assertions in a supplemental local compilation. This
uses Java 8 syntax/class targets on the available stripped JDK; it is not the
strict Java 8 API release gate. The original `--release 8 -Xlint:all -Werror`
command and full suite remain mandatory on the existing complete JDK17 host.

## Recovery and qualification boundary

The previous task's journal and receipts must keep their original bytes. Build
or installation tooling must not delete the journal, manufacture a clean result,
release its lease, or acknowledge it on behalf of the normal owner UI. The owner
will use the existing in-app cleanup and acknowledgement controls; task admission
continues to depend on the application's actual recovery checks.

The ordinary model, native runtime, system instruction, model-intention
projection, task authorization, observed tool bindings and model defaults are
unchanged. The background corrections preserve existing task/display/scope
ownership boundaries and include dedicated host regression checks.

Passing host tests or signing an APK cannot establish NPU/GPU inference quality,
virtual-display isolation, a successful cleanup or completed application work.
Those require new ordinary-app evidence from the exact v41 APK. No phone task
success or model selection change is claimed by this source candidate.
