# Isolated Hepta Stop Observer test

## Reference build status

The isolated reference APK was compiled, signed and statically checked. It has
not been installed or exercised on the phone, and Stop behavior/service binding/
model-process exit have not been qualified. Public source uses environment-based
SDK/JDK paths; that path-only variant has not been rebuilt. No APK, runtime
receipt, screenshot or signing key is included in this directory.

Set `ANDROID_SDK_ROOT` (or `ANDROID_HOME`) and `JAVA_HOME` to existing SDK/JDK
directories before running the build script.

This is a separate, test-only instrumentation APK. It instruments its own package,
`org.trillionnium.hepta.stopobserver`, and never starts or instruments Hepta.
It has no Activity, service, receiver, network permission, shell command, global
action, coordinate gesture, app launch or settings mutation.

It acquires one `UiAutomation` object with the public
`FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES` flag (value 1). It never calls the
no-argument overload, changes that flag, uses UiDevice, or adopts shell permissions.
Connection or screenshot failure is terminal; there is no fallback.

## Modes

- `observe`: saves two bounded fresh active-window trees, one screenshot and a
  receipt; performs no UI action. A missing eligible Stop button is reported.
- `click_stop`: requires exact active package `org.trillionnium.hepta.localprobe`,
  stable window/tree around the screenshot, a complete tree, and exactly one
  visible, enabled, clickable `android.widget.Button` whose text is exactly
  `停止` and which exposes `ACTION_CLICK`. It checks the button and active root
  again after writing the intent record, then calls `ACTION_CLICK` once.

The source bounds each tree to 512 nodes and 2 seconds. If truncated or ambiguous,
no click occurs. The last target/root check must complete within 500 ms.
The screenshot and tree are not atomic; the receipt records this limitation and
the two observation timestamps. PNG encoding happens after the optional click.

Every invocation requires a new 32-character lowercase hex `run_id`. A private
directory is created exclusively before observing. Reusing that ID fails without
a click. There is no automatic retry. If instrumentation ends unexpectedly after
`click-intent.json` appears, the click outcome is unknown until independently
checked; never replay it automatically.

## Build

Run `python3 build_mac.py` inside this isolated source directory on the configured
Mac. It uses only the cached SDK 34/build-tools 34.0.0/JDK 17. The output directory
must not already exist. The script produces and verifies its own signed test APK,
stores compiler/signer/manifest/disassembly output, and makes no phone connection.

## Root-controlled qualification

The parent operator installs/runs this only after the primary matrix. Substitute
the already selected ADB executable, explicit port and device serial. These are
instructions, not commands executed by this project:

```sh
<ADB> -P <PORT> -s <SERIAL> install -t hepta-stop-observer-test-0.1.apk
<ADB> -P <PORT> -s <SERIAL> shell -T am instrument -w -r -e mode observe -e run_id <NEW_HEX_ID> org.trillionnium.hepta.stopobserver/.StopObserverInstrumentation
<ADB> -P <PORT> -s <SERIAL> shell -T am instrument -w -r -e mode click_stop -e run_id <ANOTHER_NEW_HEX_ID> org.trillionnium.hepta.stopobserver/.StopObserverInstrumentation
```

Never use Hepta as the instrumentation target. The `-r` above is the
`am instrument` raw-result format flag; it is not an app restart.
The observer never brings Hepta to the foreground; the operator must already
have its normal task UI visible for a Stop click to qualify.

Evidence is in the observer's private `files/observations/<run_id>/` directory and
can be collected with its own `run-as` identity. The instrumentation result also
contains the final receipt. A successful instrumentation return or
`action_accepted:true` is only an input-dispatch observation. Neither proves that
the local model process exited or that no later phone effect happened.

Before and after the test, independently verify Hepta's accessibility service
remained connected, bind the task/model run, inspect its actual process-exit
receipt, and observe the absence of later actions. Equality of the recorded
enabled-services setting does not prove unchanged service binding.

## Primary API references

- https://developer.android.com/reference/android/app/UiAutomation#FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES
- https://developer.android.com/reference/android/app/Instrumentation#getUiAutomation(int)
- https://developer.android.com/reference/android/app/UiAutomation#getRootInActiveWindow()
- https://developer.android.com/reference/android/app/UiAutomation#takeScreenshot()

Host compilation is not a phone-side qualification result.
