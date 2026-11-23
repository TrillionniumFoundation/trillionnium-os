# Postlaunch profile absence recovery — host qualification

This candidate adds an independent read-only recovery proof for a managed-profile lease whose recorded launch was attempted, whose recorded display is positive, and whose terminal journal remains `CLEANUP_UNKNOWN`. The existing prelaunch proof and ordinary broker-close proof remain distinct.

The checker requires fresh, complete profile task/recents, display, process, installation, boot, and elapsed-time evidence. The consumer accepts only its own completed checker process, a nonce-bound proof, and the unchanged original journal. It durably saves the original journal and a distinct recovery commit before retiring the exact lease. Owner acknowledgement remains a separate ordinary UI transaction. Historical task results are preserved.

## Run

Use the existing Java 17 host toolchain and pinned `json-20240303.jar` (SHA-256 `3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed`). Run with Python bytecode writing disabled and a fresh output directory outside the source tree:

```sh
python3 -B tests/profile-postlaunch-recovery/run_host.py --source . --java-home "$TEST_JAVA_HOME" --json-jar "$TEST_JSON_JAR" --output "$TEST_OUTPUT/policy"
python3 -B tests/profile-postlaunch-recovery/run_session_host.py --source . --java-home "$TEST_JAVA_HOME" --json-jar "$TEST_JSON_JAR" --output "$TEST_OUTPUT/client"
```

`run_host.py` also accepts an explicit private `--actual-lease` input. It checks the original journal's strict interpretation and the legacy prelaunch refusal; it neither copies that input into source nor proves current device absence.

## Executed boundaries

- Actual pure production policy and process-census code run with synthetic framework inventories and time. The unchanged prelaunch and bounded whole-census gates are included.
- The complete production `BackgroundSession` and both recovery clients run with explicit Android IO fixtures. Each client's single owned `ProcessBuilder` factory is replaced by its dedicated `Fake*RecoveryProcess`. Filesystem persistence, framing, cancellation, late identity/time changes, journal compare-and-swap, and receipt consumption follow the actual production paths.
- Both actual Service idle predicates are extracted verbatim. Controller, observer, read, action, cancellation, Web lease, and session state are explicit fixtures. This checks the predicates, not Android concurrency or worker scheduling.
- The generic shared background fixture projects both recovery process factories to an always-throwing boundary. The legacy scope fixture carries null recovery capabilities and always rejects profile-recovery eligibility.

The host receipts separate cases and assertions for each gate. They are software-boundary checks, not App-task success counts. The privileged Android checker, actual device absence, ordinary cleanup UI, and owner acknowledgement still require the corresponding real-device qualification. The checker does not remove tasks or terminate the old custodian. Its watchdog requests termination of its own child; that request alone is not evidence that a process exited.
