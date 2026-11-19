# Local model settings host gate

This gate compiles the complete current LocalModelEngine and RuntimeConfigTransaction source files, with 35 current production dependencies, against explicit host platform ports and the existing pinned org.json 20240303 JAR. It never downloads dependencies, uses a phone, opens model weights, or starts the native model runtime.

Run on a non-root POSIX host with an existing full JDK that supports `--release 8`:

```text
python3 -B tests/local-model-settings/run_host.py --source /absolute/source --output /absolute/new-output --java-home /absolute/jdk --json-jar /absolute/json-20240303.jar
```

The JAR must be exactly 78332 bytes with SHA256 `3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed`. No Android SDK is needed for this host gate. Full production compilation against the Android SDK remains an independent required check.

## Scope and original cases

The transaction test preserves 43 cases and 196 assertions from the reviewed actual host suite. It exercises production private-file validation and the complete transaction implementation using real temporary files, real file fsync, atomic rename, and six real child-process halt points. It covers exact old raw bytes and absence, partial pending publication, commit/restore/rollback, unknown or foreign pointers, changed data, and file identity/permission/link failures. The dedicated r2 counterexamples remain unchanged.

The generation test preserves 15 cases and 100 assertions from the reviewed actual full Engine suite. The tests use the real executor and shared process reservation, including the original foreign-owner lease counterexample, empty-slot blocked admission, startup pending state, queue ownership, immutable once/warm generations, exact config source, and failed cleanup ownership. Every accepted inference request is stopped by a declared synthetic low-memory response before any weight or native process is reached. Successful host results do not validate 8B inference, hardware use, model selection quality, or any App operation.

Both test bodies are retained. The generation test introductory comment now describes this portable host compilation. The twelve earlier host ports are retained except Context gains a throwing getCacheDir method required to compile the entire production class without android.jar. ApplicationInfo also gains a null nativeLibraryDir field: it supplies no native directory and would fail if the declared low-memory boundary were bypassed. A thirteenth compile-only AssetManager return type is supplied because the existing throwing Context.getAssets method names it. Neither method supplies native assets or cache authority.

Android UID translation, descriptor metadata and directory fsync are declared surrogates. Real file fsync and atomic rename on this host do not prove Android power-loss durability. Context, Looper, memory reporting and the Application permission boundary are explicit host fixtures. No rendered settings UI, live AccessibilityService ownership, Android process inventory, device filesystem or platform permission is qualified here. These limits are written into the raw case receipts and the outer receipt.

## Evidence

All compiler/test argv, wall/elapsed time, exit codes and complete stdout/stderr are saved in a fresh output directory. The original typed case records are saved per suite and bound by SHA256. The gate requires exact case names, 43/196 and 15/100 counts, zero Phone/native-model effects, and unchanged production, fixture, tool and JSON inputs. CASE-CONTRACT.json preserves the original names. PRODUCTION-SOURCES.json lists the complete explicit compilation inputs. The canonical hook adds this gate without changing previous checks or their required counts.

## Framework private-directory aliases

`RuntimeContextFilesHostTest` adds 8 cases and 36 assertions against the same complete production engine and transaction. A real ancestor symlink models the platform alias in an Android application mount namespace. Engine initialization, configuration commit, and exact previous-byte restore succeed through the trusted `Context` entry, while ordinary `File` inputs retain their strict canonical requirement. Real files-leaf, model, configuration, settings, and transaction-directory symlinks remain rejected; a real directory replacement between identity samples and a synthetic wrong UID also fail closed. The original 43 transaction / 196 assertions and 15 generation / 100 assertions are unchanged. Host Context, UID/FD metadata, and directory fsync remain declared platform surrogates; this does not claim Android runtime or hardware inference acceptance.
