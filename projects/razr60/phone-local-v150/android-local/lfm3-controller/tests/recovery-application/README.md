# Recovery Application host contract

This fixture executes the candidate's actual LocalProbeApplication and its actual pure
RecoverySlotHandoff, RecoveryDispatch, RecoveryJournalTransaction, RecoveryQuiescence and
DiagnosticStartupGate. The Engine fixture copies RunHandle, every recovery member, the
slot fields and cancelActive/isBusy verbatim from the candidate at test time; extraction
identities are recorded in a temporary EXTRACTION.json.

Android Looper/Handler/Context, normal Engine construction/model IO, Session and diagnostics
are explicit host fixtures. This does not establish real Android scheduling, procfs,
filesystem durability, native cleanup or a phone task result. The real Session latch
adapter has its own qualification.

The tests exercise commit versus actual close, late cancellation, background close
notification, refused posts, stale callbacks, callback exceptions/reentry, proof UID/tx
binding and fresh UUID/cancellation state on a subsequent explicit confirmation.

The normal Python unittest gate is tools/test_recovery_application.py. It requires
javac --release 8 -Xlint:all -Werror and has no stub SDK or skip fallback.
