# Offline model import host checks

This suite runs the production streaming copier, private file transaction, fixed
asset registry, import session and the complete existing LocalModelEngine class.
Files, permissions, inode/link behavior, SHA-256 and link publication use real
non-root POSIX host files. It imports only small synthetic fixture bytes, never a
model or phone file. Android UID/FD inspection, directory fsync, document provider,
main looper, process inventory and application task/diagnostic admission observations
are explicit host boundaries. MainActivity and the real Application need the
separate Android API compilation and device UI test; this suite does not claim those.

Cases include short/oversized/wrong-hash streams, bounded long-length reads,
I/O failure, existing-model preservation, late destination arrival, publication
failure, interrupted-temp cleanup, blocked provider open/read/close and cancellation.
The session cases assert the real Engine process reservation rejects ordinary
inference, warm tasks and diagnostics until I/O and cleanup actually finish.
A final cleanup-failure case deliberately retains its slot until the test JVM exits.

Run with an existing JDK and pinned org.json jar:

    python3 tests/offline-model-import/run_host.py --source /absolute/source --output /absolute/new-output --java-home /absolute/jdk --json-jar /absolute/json-20240303.jar

No downloads, shell/ADB, model execution, application installation or phone mutation
are used.

