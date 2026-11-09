# Build the independent local controller

The source is an ordinary Android app candidate, versionCode **25**, versionName
**0.25.0-local-gpu-cache-verified-navigation**. A successful build is not device acceptance or adoption into
the protected owner-open implementation. Read `CONTROL-INTEGRATION.md` first.

Code25 adds a private OpenCL kernel-cache path for explicit GPU requests and a
general search-result navigation instruction. Real cache hits and phone-task
completion remain pending device verification; see `docs/CODE25-QUALIFICATION.md`.

## Source and host verification

Run from this directory with an existing JDK 17, Python 3.10+ and a C compiler:

```sh
python3 -B tools/verify_source.py
python3 -B tools/run_host_checks.py --out /absolute/new/host-evidence
```

The output directory must not exist. This tests the real pure-Java code, generated
grammar, native publication/context/parent-death contracts and host test drivers.
Synthetic phone fixtures remain explicitly separate from device tests.

## Android compilation

`build_mac.py` supports macOS and Linux despite its retained legacy filename.
It requires JDK 17, Android platform 34 and build-tools 34.0.0. The retained
Mac toolchain is actually NDK **28.1.13356709 (r28b)** according to its
`source.properties`; its local cache directory is misleadingly named
`28.2.13676358`. A directory name is not proof of the installed revision.
It uses dependencies already present on the build host:

```sh
export JAVA_HOME=/absolute/path/to/jdk-17
export ANDROID_SDK_ROOT=/absolute/path/to/android-sdk
export ANDROID_NDK_ROOT=/absolute/path/to/verified-ndk-r28b
export GENIEX_ANDROID_LIB_DIR=/absolute/path/to/geniex-v0.10.0/lib
export HEPTA_BUILD_OUT=/absolute/new/android-build
python3 -B build_mac.py
```

`ANDROID_NDK_ROOT` may point to the same installed NDK in another directory.
Small unsigned outputs are `base.apk`, `dex/classes.dex`, the arm64 PIE runner,
and `mac-build-receipt.json`. The receipt binds current Java, resources, native
sources and generated-code inputs to artifact hashes. Source is checked before
and after compilation. The native runner is linked for a 16 KiB maximum page
size; that does not qualify every packaged/vendor library on a real 16 KiB device.

If the pinned GenieX library group is not cached, this separate optional command
downloads the official release on the build host, checks its exact size and
SHA256, and extracts only bounded regular `.so` members into a new directory:

```sh
python3 -B tools/fetch_pinned_runtime.py --destination /absolute/new/geniex-runtime
```

The resulting `lib` subdirectory is `GENIEX_ANDROID_LIB_DIR`. Keep the verified archive beside it: assembly rechecks every packaged library against that archive. For a pre-existing cache, set `GENIEX_ANDROID_ARCHIVE` to the complete original SHA-pinned release tarball. A matching core library alone is not enough. This downloader
does not run on the phone and does not download model weights. The app itself has
no INTERNET permission or download mechanism.

## Assembly and signing

Keep source and unsigned outputs together. Set `AAPT2`, `APKSIGNER`, `READELF`
and `KEYTOOL` if those tools are not on PATH. Use GNU `readelf`. For an upgrade
of an existing installation, retain its original private signing key:

```sh
export HEPTA_SIGNING_KEY_PATH=/private/path/to/original/hepta-local-debug.jks
export HEPTA_REQUIRE_EXISTING_KEY=1
export MOBIMIND_ANDROID_RUNTIME_DIR=/absolute/path/to/verified-mobimind-r4-runtime
export UI_VENUS_ANDROID_RUNTIME_DIR=/absolute/path/to/verified-ui-venus-app-native-build
python3 -B assemble_pocket4.py
```

The assembler refuses stale build inputs, changed artifacts, mismatched actual
APK identity/version, missing runtime libraries and unexpected dependencies.
It checks the manifest, service guard, ABI, signature, resource alignment and
packaged library hashes. It outputs `hepta-local-0.25.0.apk` under the build output
and `control-v25-static/STATIC-ACCEPTANCE.json` as its static packaging receipt.

The separate `MOBIMIND_ANDROID_RUNTIME_DIR` must contain the unchanged r4
`hepta-mobimind-probe`, `libMNN.so`, `libc++_shared.so` and their original
`BUILD-RECEIPT.json`. Their exact byte counts, hashes and dependencies are in
`native/mobimind-runtime-pins.json`; the retained source and build provenance are
under `provenance/mobimind-worker-r4/` and
`provenance/mobimind-worker-r4-build.json`. These are not GenieX release members.
The assembler checks each group independently and refuses a same-name
replacement. It additionally verifies the MNN PIE's sole `$ORIGIN` RUNPATH and
direct MNN/C++ dependencies, required for the child environment described in
`docs/CODE15-MNN-LOADER.md`.

The exact three compiled MNN members currently come from the separately retained
and verified Android r4 build. This source bundle contains their identities and
rebuild sources, not their binary payloads or a public binary download endpoint.
The worker's retained README describes the fixed MNN checkout and two-stage
NDK build. A new build must be checked for byte identity; if it differs, its new
pins require a new candidate and fresh qualification rather than an override.
A CI job without these verified runtime inputs cannot claim full code20 APK
assembly merely from a successful Java/native compilation stage.

A fresh development checkout may omit both signing variables to create a local
development key. CI uses that mode only for static packaging checks. Its key is
not a replacement for an installed app's signer. Keys, model weights and phone
evidence must stay outside source control. Nothing in these scripts installs an
APK, enables Accessibility, changes a model, or starts a phone task.

## Native runtime and subsequent device gates

The text runtime is GenieX 0.10.0 `llama_cpp`, pinned to its Android arm64 release.
The assembler includes its same-version llama/OpenCL/Hexagon dependency group
and only the HTP v79 DSP library. It declares optional vendor FastRPC/OpenCL
libraries and derives plugin/DSP lookup paths from the installed native library
directory. NPU/GPU selection must fail if the requested device is unavailable;
there is no automatic CPU fallback. Gemma E4B/E2B and experimental Bolt are explicit text profiles;
weights and projectors are not bundled in the APK. The separate MNN endpoint
remains a private model-only diagnostic: its raw output does not dispatch phone
actions. It requires its own ordinary-App GPU and cleanup qualification.

After a normal same-signer package update, preserve the app-private model and
Accessibility configuration. Verify actual installed APK bytes and version,
model SHA, ordinary UID accelerator execution, action effects, clean stop/restart,
offline operation and sustained thermal behavior. `tools/phone_inventory.py`
collects a bounded read-only inventory using an existing ADB server.
`tools/PHONE-SUITE.md` describes the separately authorized task driver. The
shipped navigation plan has no candidate APK hash and cannot run as-is.

## Separate UI-Venus App worker

`UI_VENUS_ANDROID_RUNTIME_DIR` contains `libhepta_ui_venus_runner.so` and its
original `BUILD-RECEIPT.json`. The pinned App worker differs from the shell probe.
`native/ui-venus-runtime-pins.json` binds its actual Android artifact, preserved
build receipt and full independent native source manifest. Assembly adds exactly
one native member and does not replace the original sixteen. Actual ELF machine,
PIE interpreter, unique `$ORIGIN` RUNPATH and every DT_NEEDED entry are checked.
No model weights are included. Read `UI-VENUS-APP-PROBE.md` before a separately
authorized private model-only request; successful assembly never triggers one.
