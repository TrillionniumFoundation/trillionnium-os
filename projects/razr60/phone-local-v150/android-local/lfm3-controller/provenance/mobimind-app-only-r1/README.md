# Ordinary-App MobiMind model-only overlay

This is a reviewed integration candidate for Hepta, based on the exact frozen code10 source manifest `519b46dba5078e591bc1c9ef1a0e20c92bef2a68e023108c6c7c582bea774394`. It preserves the existing text controller, label-first grammar, service action checks and model profiles. It does not install an APK or operate a device.

The new endpoint runs one visual inference in the ordinary application process's child. It is not a phone controller: no `LocalInference` implementation, phone-action parsing, `ActionDispatcher`, accessibility action, coordinate execution, or new network permission is connected to its output.

## Exact scope

- Six new classes in `src/`: fixed runtime/model pins, strict receipt JSON and evidence contracts, bounded private files, one-use fixture consumption, durable recovery contract, and the application-owned MNN engine.
- Three integration files, with their code10 base hashes recorded in `INTEGRATION-MANIFEST.json`: `LocalModelEngine`, `LocalProbeApplication`, and `MainActivity`. `integration-code10.patch` shows the actual changes against that base.
- The text engine supplies a shared external lease using its existing `PROCESS_ACTIVE` slot. This keeps text and visual native inference mutually exclusive and lets the visible Stop button cancel the owned visual child.
- `Application.onCreate()` inspects the visual journal before an Activity or service can accept a new request. An unfinished journal, AtomicFile sidecar, malformed record, or interruption latch blocks the shared slot. No old request or nonce is replayed.
- MainActivity accepts the private diagnostic launch only when the existing task session is neither pending/running nor blocked. Intent extras carry only a one-use nonce; all fixture and request authority comes from bounded private files.

## Verification performed

The real macOS JDK17/Android SDK34 compile of all 33 source files passed, producing 108 class files. The exact archive SHA is `2e4b73102c62222d6ea59cc92e50fdd8fe744e0a8e0953c532554713928a2f51`; its receipt is included in `host-evidence/android-compile-r2.json`. The first compile caught use of a non-public `Os.unlink` API. The corrected implementation uses the public `File.delete()` after path-identity verification; the exclusive, synced nonce claim is created first.

The pure Java suites contain 58 receipt/parser/hash assertions and 41 durable recovery assertions. They cover full model hashes, exact native input/output binding, OpenCL fallback rejection, honest CPU helper counts, EOS versus token limit, unknown/duplicate JSON, parent/UID mismatches, cancellation races, and blocked restart states.

The previously successful **shell** r3 receipt was read separately and left unchanged. The ordinary-App contract rejected its two UID fields and its shell library path. A documented in-memory schema-only projection of those three environmental fields passed all remaining r3 data-contract checks. That exercise proves schema compatibility only. It does not prove ordinary-App execution. Private raw output and device evidence are not included in this source package.

## Native packaging

Use the exact r4 worker and the unchanged r3-built libraries. Rename only the worker's APK member to `libhepta_mobimind_runner.so`; do not alter its bytes. Package the three files under `lib/arm64-v8a/` with the existing native runtime:

| APK member | Bytes | SHA-256 |
|---|---:|---|
| `libhepta_mobimind_runner.so` | 2,186,768 | `b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020` |
| `libMNN.so` | 6,408,488 | `5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d` |
| `libc++_shared.so` | 9,236,352 | `77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754` |

The prepared host directory is `/home/alex/razr-local-ai-20261108-dda84ccf/mobiinfer-opencl-build-r4/runtime`. r4 uses the same fixed MNN source revision `bce7456ce60b5e51b4d3b357f303515860353d8c` and existing `libMNN.so`; only the standalone worker changed for full-file ARMv8 SHA2 dispatch. Portable full-file hashing remains valid when hardware SHA2 is unavailable, but does not qualify as acceleration.

The installed native directory must come from `ApplicationInfo.nativeLibraryDir` under `/data/app/`. The Java preflight hashes all three binaries. It then invokes the worker directly with `ProcessBuilder`, without a shell. The child uses its private installed library directory and `/vendor/lib64` for OpenCL. The existing APK already declares the optional `libOpenCL.so` native library and `extractNativeLibs=true`; no additional permission is requested. This endpoint additionally rejects an APK declaring `INTERNET`.

The existing GenieX runtime's actual ELF closure did not package or depend on `libc++_shared.so`. The MNN worker uses its own shared C++ runtime in a separate process; no C++ objects cross between the two runtimes. The final APK still needs a real packager/ELF-closure validation, signing and normal-App device qualification. This draft does not claim those are complete.

## Private model and request layout

The complete pinned model package stays under:

```
files/model/mobimind-1.5-2b-w8a8-0717-f02848b6/
```

The native worker verifies the exact 11 loaded/provenance files on every request, totalling 3,279,787,206 bytes. The official download contains 15 files (3,398,455,629 bytes); keeping all 15 is fine, but unused graph-debug JSON and download metadata are not loaded. Original CPU configuration files are preserved. The worker writes a separate OpenCL runtime configuration for text and vision.

After the model import is complete, prepare a short-lived request from an existing official fixture and original PNG:

```
python3 tools/prepare_private_request.py \
  --fixture-dir /private/fixture \
  --image-file /private/original-screen.png \
  --output-dir /private/fresh-app-request \
  --deadline-ms 120000 --max-tokens 256
```

This host-only tool writes a staging tree and `REQUEST-HANDOFF.json`. It does not call ADB, install files, launch the App or run inference. The staging `files/` contents belong in the App's private files directory, with files mode0600 and directories mode0700. Import the one-use `mobi-probe-request.json` last. It expires within ten minutes, so do not create it before a long model transfer.

The one-use launch extra names are `auto_mobi_probe=true` and `mobi_nonce`; obtain the nonce from the private request, not from public logs. The private request pins the fixture SHA. The App verifies the original owner/history text, exact official prompt rendering, source revision, input PNG hash and dimensions, and prompt hash before claiming the nonce. It never accepts a host-provided path outside the fixed private layout. A durable exclusive claim remains consumed even when a later validation or launch fails. The trigger receipt reports uncertain consumption as null, not false.

The pinned renderer uses `(No history)` for the initial empty action sequence. Both explicitly supplied owner and history fields are bounded and nonempty; this is consistent with the official fixture renderer. This placeholder does not assert that any action was executed.

## Lifetime, deadline, output and limits

The App reserves a durable pending journal before launching a child. A single monotonic request budget includes Java preflight; only its remaining milliseconds are passed to the native watchdog. The worker separately enforces parent death, input/model binding and the deadline. Java monitors owned exit, cancellation and bounded logs, then uses a bounded terminate/force-terminate cleanup. It releases the shared model slot only after owned exit (or known no-start) and durable terminal publication. Unknown exit or publication state retains a block and creates an interruption latch where storage permits.

The engine belongs to the Application, so an Activity recreation does not create a second worker or cancel ownership. This is not a promise that Android will keep a background process alive indefinitely. If the App process dies, the native parent-death guard and the next-start journal inspection apply. Actual background completion, cancellation and restart behavior require normal-App device testing.

Runs are saved at `files/mobi-runs/<request_id>/` with original prompt, original PNG, fixture, complete raw output, native records, stdout/stderr and `app-receipt.json`. The App shows at most 16,000 raw characters but retains the full bounded output. It does not parse the raw JSON as a phone action. Old screenshots explicitly carry no live-freshness claim.

Successful qualification requires exact ordinary App UID and parent, installed library path/hash, all model pins, both input hashes, exact input-token budget, EOS completion, raw hash and post-generation binding, positive OpenCL runtime/execution evidence, and no whole-runtime OpenCL fallback. CPU helper operation counts remain visible; the App never claims all operators run on the GPU. Full-file SHA traces are independently verified; hardware capability flags alone are insufficient.

The current RAM preflight is an explicit engineering guard of 5 GiB available physical memory. It is recorded as a threshold, not a measured peak-memory result. The fixed context is 4096, image long edge1024 and token budget at most512. No automatic retry, network model, CPU backend substitution, tool dispatch, or visual phone controller is included.
