# Controller read recovery regression

This host gate compiles the actual Controller retry wrapper, all observation await
methods, the actual opaque Service proof class, and the existing create-new,
write, fsync record writer verbatim. The existing stale recovery bridge constructs
a real NativeAppSession and its private ReadRecoveryPermit through an actual
guarded rejection and successful outcome-journal callback. That original-action
journal endpoint is in memory with synthetic receipt hashes; the real file fsync
in this gate applies to the new Controller read-intent records. Tests exercise cross-producer object
identity, one task budget, durable-first ordering, real duplicate-file refusal,
Stop and identity changes around journal writes, original task/read deadlines,
fresh cancellation tokens, duplicate callbacks, and failure of the replacement
read without a third read.

Observer transport, Android observation carriers, the monotonic clock and
cancellation schedules are explicit synthetic host endpoints. The Android chmod
call is mapped to the private host files. Service read-worker drain and graph
identity are qualified in their separate observer gate. These tests do not
qualify Android execution, a model, a phone task or business completion.

Use the normal `--source`, `--output`, `--java-home`, and `--json-jar` arguments.
The source must include the sibling `native-stale-recovery` gate. Compilation uses
JDK17, Java8 target, UTF-8, warnings-as-errors, and the existing pinned real JSON
dependency. Output is create-only and records complete before/after source and
tool hashes plus the exact extracted method hashes.
