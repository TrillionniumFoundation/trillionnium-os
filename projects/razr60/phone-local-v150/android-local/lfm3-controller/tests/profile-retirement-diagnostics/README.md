# Profile retirement diagnostics

This portable host test compiles the current production ownership policy. All platform tasks, history, identity failures and latency are synthetic. It performs no phone, ADB, model or UI operation.

The diagnostic is an audit of calls made by the one original ProfileOwnedTask.retire invocation. Its duration clock is System.nanoTime and never consumes Platform.now; its offsets are not Android elapsed-realtime capture timestamps. The remove-leaf entry is entry into the original Platform.removeLeaf wrapper, not proof that its internal organizer transaction was reached. A void removal return has no acceptance Boolean. A true root-delete Boolean is a call result and does not prove task or virtual-display absence.

The trace keeps the first 24 calls, the final call, the slowest completed call, and separate remove-leaf/root-delete entries. Overflow is explicit. It never extends the original 1400 ms cleanup read window, changes the call order, or supplies cleanup authority. No task monitor is acquired when reading the trace and no trace monitor spans a platform call.

Run with --source, --java-home, --json-jar and a new --output directory. The runner additionally executes the unchanged existing 47/449 private ownership policy tests and 9/55 public history sampling tests. It imports the existing source list and uses the unchanged explicit synthetic public-recents fixture.

An optional --baseline-source runs the same eleven functional scenarios against the exact signed93 predecessor. It compares the full ordered platform-call log, the exact number of original elapsed-clock reads, fake elapsed time, first refusal, mutation order and cleanup flags. The default portable CI entry does not require that private source location. The twelve candidate scenarios also cover in-flight watchdog reads, failed/false/accepted-but-not-absent mutation results, two distinct history-read failure stages, immutable bounded output and a root call and a slow completed history read occurring after prefix overflow.

No test reproduces task6127 framework timings or claims that its unknown cleanup has been repaired. The diagnostics make the next original invocation observable; they do not provide a retry or recovery action.
