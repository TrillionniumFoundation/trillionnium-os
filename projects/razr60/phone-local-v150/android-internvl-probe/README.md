# Hepta Intern NPU diagnostic

This separate Android package evaluates the declared Intern3.5-VL-2B W4A16
SM8750/HTP79 package with GenieX 0.10.0 and QAIRT 2.50. It performs only local text
or single-image inference. It has no Accessibility service, phone action API,
Android permission, or INTERNET permission.

Package: `org.trillionnium.hepta.internprobe`. Label: `Hepta Intern NPU 验证`.
The application owns one diagnostic engine across Activity recreation. The engine
keeps the qualified QAIRT process/exit/cancellation supervision and fixed NPU
profile. `ENGINE-DELTA.diff` records the limited Java changes. Native sources are
unchanged; the build requires the exact previously qualified runner binary.

## Current status

Source and the build request are prepared. This Intern APK has **not been built,
installed, or qualified on a phone**. The declared model target has four language
parts, a 4096-token compiled context, a 448×448 image input and 256 visual tokens.
Those metadata values do not prove that the model archive has finished downloading
or that its actual configuration/tokenizer has been inspected.

The archive, tokenizer and configuration hashes remain unknown until the staged
artifact is available. The Qwen3-VL-4B tokenizer hash and its token-budget rule are
not reused. The diagnostic receipt explicitly marks model identity and input
context admission as unverified. Successful SDK generation and a real child exit
cannot by themselves establish that an input was not truncated.

## Build with cached dependencies

The scripts follow the environment-variable convention used by `android-local`:

```sh
export ANDROID_SDK_ROOT=/path/to/android-sdk
export JAVA_HOME=/path/to/jdk-17
export HEPTA_QUALIFIED_RUNNER=/path/to/qualified/libhepta_probe_runner.so
python3 build_mac.py
```

The pinned runner SHA-256 is
`fe2c34782f5a043621e72ea26f5a805b2629c98cc66b51a49bb0b10bf1247b5a`.
The script uses cached SDK 34 and build-tools 34.0.0, targets Java 8 and Android 35,
and creates a dedicated diagnostic debug key. It does not download dependencies
or operate a phone. A new output directory is required.

Copy the source, its generated small build outputs and its private diagnostic key
to the isolated assembly directory. Keep that key out of source control. Then:

```sh
export GENIEX_ANDROID_LIB_DIR=/path/to/geniex-bench-android-arm64-v0.10.0/lib
export APKSIGNER=/path/to/apksigner
export AAPT2=/path/to/aapt2
export READELF=/path/to/readelf
python3 assemble_pocket4.py
```

`runtime-libraries.json` pins all 31 cached native payloads byte-for-byte against
the qualified Code6 runtime, including the installed PIE runner. The assembled APK
is checked for its independent package, absence of permissions/control services,
library identities, signature and Android resource alignment. No model, SDK
binary, signing key, raw phone UI or private runtime result belongs in public
source control.

## Model and diagnostic input

Only the parent operator imports and tests the model after verifying the actual
staging result. Preserve the original weights/configs and rebase a separate copy
for this package's own private `files/model`. The required configuration entry is
`files/model/genie_config.json`. Do not point it at another app's files.

Image diagnostics read this app's private `files/probe-image.png`. The original
input is copied to a unique run directory. The native SDK applies the model's own
chat template and vision preprocessing; the diagnostic UI does not resize it.

For a visible diagnostic request, `.MainActivity` accepts the same inference-only
extras as the qualified diagnostic flow: `auto_run`, `prompt`, `system_prompt`,
`mode` (`text` or `image`), `max_tokens`, and `timeout_ms`. Defaults are text
`只输出 42。`, 128 output tokens for text, 256 for image, and 120 seconds. There is no
task/control intent. Recreation displays the current engine instead of replaying
`auto_run`; there is no automatic inference retry.

Runs retain prompt/system/image, stdout/stderr, native result, raw text and the
outer process receipt under this app's own `files/runs/<run_id>/`. The engine does
not accept a second request until its owned native process has actually exited;
unknown termination keeps the process ownership gate closed. It retains the
conservative 5 GiB available-memory threshold from the qualified baseline, which
is not a measured Intern memory requirement.

## Qualification still required

After the artifact is available, verify its exact configuration, tokenizer and
complete file hashes; construct an appropriate input-token bound using that actual
tokenizer/template; install the exact diagnostic APK; and test ordinary app UID
text/image NPU execution, output binding, real exit and cancellation. Record QNN
HTP execution evidence. No result from another model or package qualifies this
Intern model automatically.
