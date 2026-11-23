# Terminal session evidence gate

Run with an existing full JDK:

```sh
python3 -B tests/session-terminal/run_host.py --java-home "$JAVA_HOME" --output /absolute/new/output
```

The default gate uses synthetic records, including payloads large enough to reproduce the frozen R13 journal limit failure. It contains no captured phone records. It executes the actual terminal snapshot, writer, failure and startup methods extracted from LocalTaskSession; complete SessionTerminalEvidence, SessionJournalQueue and SessionRecovery; and the existing FilesRoot implementation. The frozen legacy method excerpt is pinned to the parent source and executes the old refusal as a negative control.

Both modes run the same core cases. The host mode compiles the exact helper. The Android ownership mode changes only the FileInputStream import to a shim whose close leaves the caller's descriptor open. Repeated validation checks real process descriptor counts and tracked descriptors. Negative close tests verify first and suppressed failures.

The IO adapter uses actual host files, descriptor sync, directory FileChannel.force and atomic replacement. Android UID numbering, fstat path lookup and JSON are explicit host adapters. This is not an Android runtime or phone durability claim. Administrative owner acknowledgement always rejects in this fixture, so it cannot fabricate recovery authority. Existing independent recovery and Android build gates remain required.

RESULT.json records production/fixture/runner identities, extracted method hashes, compiler/runtime exit codes and unchanged inputs. CASES.json equals its aggregate runtime object; case names include the execution mode. Source/target 8 bytecode is tested; Java 8 API cross compilation is not claimed.

The optional --actual-manifest accepts private result/owner paths for local replay. Both the manifest and output must be outside the component. The caller must first verify collection seals. The gate checks task, owner and authorization, preserves outcomes and complete bytes, and records local replay metadata. Private records and generated replay receipts must never enter the component or Git.
