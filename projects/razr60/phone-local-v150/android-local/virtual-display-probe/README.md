# Bounded virtual-display probe

This directory contains a standalone Android shell helper and its host build script. It is a feasibility probe, outside the Hepta APK. The tested Java source is preserved byte for byte.

## Observed result

One authorized experiment on Android 16 with Snapdragon 8 Elite used a phone-side, detached shell process to create a secondary display. An external deterministic controller launched the calculator there, read fresh accessibility nodes before each of seven display-targeted clicks, and obtained **23 × 19 = 437**.

| Check | Observation from that run |
| --- | --- |
| Local model | `local_model_used=false` |
| Hepta integration | `apk_integration_tested=false` |
| Main-display focus | Unchanged in 27 samples; maximum sampling gap 0.1874 seconds |
| Input method | Hidden in the sampled main-display state |
| Input-routing focus | `FocusedDisplayId: 0`; the calculator and Hepta retained their respective per-display focused windows |
| Targeted Back | Exited the calculator task on the secondary display |
| Cleanup | Helper reported release; the display was confirmed removed |

Sampling does not exclude shorter, unsampled focus changes. These observations establish the calculator tool path, not end-to-end local-agent operation, general app compatibility, or uninterrupted main-screen use. Raw UI, screenshots, device identifiers, and host-specific paths are intentionally excluded from this directory.

## Display and process behavior

The first private-display attempt rendered content but did not expose the target accessibility tree on the tested device. The successful version uses `PUBLIC` with `OWN_CONTENT_ONLY`, plus touch, trusted-display, own-focus, no-top-focus-steal, and destroy-content-on-removal flags. `OWN_CONTENT_ONLY` avoids mirroring the default display; a public display is not a private security boundary.

The source requests hidden Android 16 flag values. `DisplayManager.VIRTUAL_DISPLAY_FLAG_*` and `Display.FLAG_*` are different enumerations: the two integers in the creation receipt must not be compared for equality. Check the resulting display/window state and intended behavior instead.

The helper creates a 720 × 1280 surface at 240 dpi, sets the display IME policy to hidden, and retrieves windows through `getWindowsOnAllDisplays()`, selecting only its current display ID. The observation connection uses `FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES`. It does not provide launch, tap, or Back RPCs: those actions in the experiment came from the external controller with an explicit target display.

A fresh shell-owned directory is the only control surface:

- `observe`: write `observation.json` with the target windows and bounded node traversal.
- `capture`: capture the next available frame; image capture is opt-in.
- `stop`: release the display and terminate.

Receipts include a random generation and the allocated display ID. Password-node text and descriptions are redacted; observations and optional images can still contain application content and should remain in the private run directory.

The five-minute TTL is checked by a Handler callback scheduled every 250 ms. It is **not a hard watchdog**: a stalled event loop or process can delay cleanup. Shutdown cleanup is also best effort. No secure-capture or always-unlocked flag is requested.

## Build

Use Python 3, JDK 17, Android SDK platform 34, and a D8/R8 jar. The script does not download tools, contact a phone, or install an APK. Supply tool locations explicitly; the output directory must not already exist.

```bash
python3 build_probe.py \
  --jdk /path/to/jdk17 \
  --sdk /path/to/android-sdk \
  --d8-jar /path/to/android-sdk/build-tools/34.0.0/lib/d8.jar \
  --out /path/to/new-probe-output
```

`--sdk` also accepts the platform-34 `android.jar` directly. The output includes `probe.dex`, compiler output, and `build.json` with tool versions and input/output hashes. Reproduce the tested build with the toolchain and arguments recorded below; a different compiler or D8 version can produce a different DEX from identical source.

- Java source SHA256: `8e1e905c0eac4e7412e8657aff672f3d4baa4907c2fff82db7b3662de6d363b8`.
- Device-tested DEX: 12,828 bytes; SHA256 `a16fdbf259544b3567681a2f368fc432a6d5a40ac24f70abc17eba6fb965d076`.
- Exact DEX reproduction succeeded with Temurin JDK 17.0.7+7 and SDK Build Tools 34.0.0, whose D8 reports `8.2.2-dev` (build `facedf41bbd28b563d1e9e09c5f72d7c5ca598d5`).
- Compiler options: `javac -source 8 -target 8`; D8 `--min-api 30 --lib android.jar`.
- SDK-34 `android.jar` SHA256: `6cea1df3efb77103ac3e2beb9bf4718964b0e0869ab16d39d29d5cbae1c147ad`.
- D8 jar SHA256: `d43c8a94c9b1f1da1a7cc49c32b81e8cee1708b37ee8b530a81a0688222b42c0`.

To require the exact tested DEX, add `--expect-dex-sha256 a16fdbf259544b3567681a2f368fc432a6d5a40ac24f70abc17eba6fb965d076`. A mismatch returns a failure status while retaining the build receipt.

## Authorized shell execution

The experiment used the user's existing authorized Android shell privileges. This directory does not grant privileges or change device policy. Hidden framework APIs and trusted-display creation require suitable permissions and may differ between Android builds.

Create a new mode-0700 shell-owned directory matching `/data/local/tmp/hepta-vdisplay-[a-zA-Z0-9-]+`, copy `probe.dex` there, and start the helper through `app_process`. The successful run used phone-side `setsid`, redirected stdin/stdout/stderr, and a detached process so its lifetime did not depend on an ADB child process.

Illustrative command, **inside the already-authorized phone shell**, after preparing the unique directory and DEX:

```sh
CLASSPATH=/data/local/tmp/hepta-vdisplay-UNIQUE/probe.dex \
setsid app_process / org.trillionnium.hepta.displayprobe.VirtualDisplayProbe \
  /data/local/tmp/hepta-vdisplay-UNIQUE \
  </dev/null >/data/local/tmp/hepta-vdisplay-UNIQUE/helper.log 2>&1 &
```

Read `created.json` and use its allocated display ID; do not hardcode the ID from a prior run. A controller must launch, observe, inject input, send Back, and validate receipts against that same display and generation. Create `stop` when finished, then verify both `terminal.json` and removal of the display.

Production integration still needs a display-bound Hepta observer/action contract, immutable task scope, fresh-node checks, cancellation/cleanup, independent lifecycle supervision, and local-model end-to-end qualification. This helper has no network or arbitrary RPC interface and does not itself implement an agent.
