# Hepta ordinary app UID NPU probe

This independent debug Android package verifies the existing pinned GenieX 0.10.0 QAIRT Qwen3-VL-4B model under an ordinary application UID. It is not yet a phone agent. It declares no Android permission, including no INTERNET permission, and performs no phone actions.

Package: `org.trillionnium.hepta.localprobe`. Compile SDK 34, target SDK 35, minimum SDK 30. Plain Java 8 language/bytecode compiled by cached Temurin 17. No Gradle dependency downloads. Native ABI arm64-v8a; the runner is an installed PIE stored as `libhepta_probe_runner.so` in `ApplicationInfo.nativeLibraryDir`, never copied into writable app data for execution.

## Files and build

`build_mac.py` uses the existing Mac Android SDK/NDK and GenieX library cache. Its outputs are the tiny base APK, classes.dex and runner. Copy these outputs and this source directory to the Linux assembly host, then run `assemble_pocket4.py`. See PUBLIC-BUILD.md for explicit tool and SDK paths. Assembly packages the already cached QAIRT runtime, signs with a dedicated debug key, and records permission, ABI, manifest, signature and library SHA-256 checks. No model or signing key belongs in source control. Source may be committed to a dedicated local git branch; this does not imply remote synchronization.

Native sources pin GenieX commit `071f609995470bdb0e0769ab964754adfaab7e47` and header SHA-256 `c5d441ee290c5ec83f01ec1af9a7c16cdd8c740b522b78c23ed667062fc21e40`. The adapter only adds explicit plugin registration and QAIRT runtime path selection for Android's flat extracted library directory, plus child UID diagnostics. It preserves the existing one-shot worker's output and process supervision contract. Custom GBNF is disabled because this QAIRT build has an observed EOG grammar abort; any future phone controller must independently validate a complete strict action schema before executing anything.

## Device test contract (parent/root performs installation)

Import the entire already validated QAIRT model directory contents into the package's own `files/model` using debug `run-as`, with ordinary app ownership. Do not point the package at another application's data or a protected service owner domain. Image tests read only this package's private `files/probe-image.png`; the engine copies each image to a unique request directory before starting inference.

Launcher `.MainActivity` displays UID, private model location, native installation directory, available RAM, raw output and receipt. For a visible debug test, activity extras are `auto_run` boolean, `prompt` string, `system_prompt` string, `mode` text or image, `max_tokens` integer, `timeout_ms` long. The default text request is `只输出 42。`.

`files/runs/<32 lowercase hex request id>/` retains the complete prompt, optional system/image, full native stdout/stderr, raw generated text, unchanged `native-result.json`, and Java `app-receipt.json`. The Java receipt binds request ID, runtime, raw size/hash, SDK completion and actual `Process.waitFor` exit. An SDK report's `process_exit_observed:false` remains unchanged; only the outer supervisor can attest its child exited. A successful generated string alone is insufficient qualification.

## Engine API

`new LocalModelEngine(Context)` owns one native request at a time. `start(Request, Listener)` returns `RunHandle`; `RunHandle.cancel()` requests termination only of the owned Java Process. Listener callbacks run off the UI thread. `Request(String prompt, String systemPrompt, File imageOrNull, int maxTokens, long timeoutMs)` selects text or optional private image, not runtime or executable. `Result` includes public `runId`, `status`, `rawText`, nullable `exitCode`, `processExitObserved`, `inferenceCompleted`, JSON `nativeReceipt`/`receipt`, and `runDirectory`.

The engine clearly refuses a request while another is active, and refuses model startup if Android reports low memory or less than 5 GiB available. This is a conservative admission threshold, not a memory usage guarantee. The request has no automatic retry. Cancellation and timeout first call `Process.destroy`, then `destroyForcibly`; a request whose exit cannot be observed retains process ownership and blocks another inference until an owned reaper observes exit. Logs are full files, not parsed as action commands.

## Qualification boundary

Static build acceptance does not prove ordinary app UID access to Hexagon. Root must install this exact APK, import the model, verify a fresh model process is not already running, run text/image inference, inspect own child UID and actual QNN/HTP logs, test offline with the manifest's lack of INTERNET, and inspect receipt/exit/cancellation. Earlier root or shell NPU success is not app UID qualification. Only after that gate should independently prepared Accessibility observation/action code be integrated and tested.
