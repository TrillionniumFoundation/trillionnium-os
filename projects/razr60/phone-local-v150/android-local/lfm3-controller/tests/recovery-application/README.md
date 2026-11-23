# Recovery Application host contract

This fixture executes the candidate's actual LocalProbeApplication and its actual pure
RecoverySlotHandoff, RecoveryDispatch, RecoveryJournalTransaction, RecoveryQuiescence and
DiagnosticStartupGate. The Engine fixture copies RunHandle, every recovery member, the
slot fields, ExternalRunLease/reserveExternal and cancelActive/isBusy verbatim from the candidate at test time; extraction
identities are recorded in a temporary EXTRACTION.json.

Android Looper/Handler/Context, normal Engine construction/model IO, task Session,
permission Session and diagnostics
are explicit host fixtures. This does not establish real Android scheduling, procfs,
filesystem durability, native cleanup or a phone task result. The real Session latch
adapter has its own qualification.

The tests exercise commit versus actual close, late cancellation, background close
notification, refused posts, stale callbacks, callback exceptions/reentry, proof UID/tx
binding and fresh UUID/cancellation state on a subsequent explicit confirmation.
The original 18 cases remain intact. Twelve additional permission integration cases
exercise an uninitialized/foreign Application, the independent permission gate,
preservation of an existing control barrier, an actual ExternalRunLease slot,
task/diagnostic/recovery exclusion, late gate changes, main-thread ownership and
Application termination without fabricated cleanup. The permission Session in this
fixture controls state only: it does not test production permission journaling,
historical reservation classification, real Process exit or authorization.

The normal Python unittest gate is tools/test_recovery_application.py. It requires
javac --release 8 -Xlint:all -Werror and has no stub SDK or skip fallback.

`run_host_tests.py --source <candidate> --output <new-directory>` provides a clearly
labelled supplemental Java 8 source/class-target run when the local JDK lacks a Java 8
API release image. `--release8` requests the original strict API contract and fails
without fallback if unavailable. Both modes retain generated fixture/extraction
hashes, compiler output, case counts and the no-phone/no-su limitations in the report.
