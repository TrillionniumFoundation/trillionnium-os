# Public source build and verification

This is a public projection of the Android control candidate built at local
source commit `71cac4bc9cefdf4c82113e15911d47316e10a10d`. The frozen source archive
SHA256 is `6700bc8ed1dc9c1e0db71760a8929b702426c2cb087e24fea055247f55985db7`.
Java, resources, manifest, native worker and the pinned SDK header retain their
exact frozen bytes. Build scripts use explicit environment paths instead of
one operator's cached workspace. `PUBLIC-SOURCE.json` records each original
source hash and all public transformations.

## Build prerequisites

Use an existing JDK 17, Android platform 34, build tools 34.0.0, and Android NDK
28.2.13676358. The app compiles to Java 8, supports API 30 and targets API 35.
No build step downloads dependencies. Obtain the exact licensed GenieX 0.10.0
Android arm64 SDK separately; the scripts preserve the SDK/header hash checks.
Model weights, SDK shared libraries, signing keys and device traces are excluded
from this repository.

For the Mac compile step, set `JAVA_HOME`, `ANDROID_SDK_ROOT` (or `ANDROID_HOME`),
and `GENIEX_ANDROID_LIB_DIR`. The latter points to the extracted SDK `lib`
directory containing `libgeniex.so` and the `qairt` subdirectory.
`ANDROID_NDK_ROOT` optionally selects the installed NDK directory; otherwise the
pinned NDK version below the selected SDK is used.

```sh
python3 build_mac.py
```

Copy only the generated `base.apk`, `dex/classes.dex` and
`libhepta_probe_runner.so` under the same source tree's `out` directory on the
Linux assembly host. Set `GENIEX_ANDROID_LIB_DIR` for that host. `apksigner`,
`aapt2`, `readelf` and `keytool` must be on PATH, or specify their paths with
`APKSIGNER`, `AAPT2`, `READELF` and `KEYTOOL`.

```sh
python3 assemble_pocket4.py
```

The assembly step creates a local development signing key if absent, stores it
only under the ignored `keys` directory, packages the pinned SDK libraries and
verifies the actual APK manifest, permissions, resource alignment and library
hashes. It does not install the app, import weights or enable Accessibility.
The development package remains `org.trillionnium.hepta.localprobe` and declares
no INTERNET permission. Treat its debug signing key as local build state.

## Host checks

Run the parser verification with an existing JDK 9 or newer. The output
directory must be new; it contains source hashes, compiler output and assertions.

```sh
mkdir -p out
python3 control-tests/action-parser/run_host_tests.py \
  --source src/org/trillionnium/hepta/localprobe/ActionDecision.java \
  --out out/parser-host-check
mkdir -p out/budget-classes
javac --release 8 -encoding UTF-8 -Xlint:all -Werror \
  -d out/budget-classes \
  src/org/trillionnium/hepta/localprobe/ConservativeTokenBudget.java \
  control-tests/BudgetHostTest.java
java -cp out/budget-classes BudgetHostTest
```

On Linux, the native publication contract fixture verifies no-clobber result
publication, including pre-existing destination and symlink refusal:

```sh
cc -std=c11 -Wall -Wextra -Werror native/tests/publish_contract.c \
  -o out/publish-contract
out/publish-contract
```

## Acceptance scope

Host parser/budget/publication checks and APK compilation establish only their
named properties. They cannot establish actual Hexagon graph execution,
Accessibility behavior, process cancellation on the device or completion of an
owner's app task. Device qualification must retain the real SDK/HTP execution
evidence and independently check visible UI postconditions. A model `done`
decision remains `model_reported_done`, with
`goal_independently_verified=false`; it is not generic task-success evidence.
No device acceptance is transferred merely by copying or rebuilding this source.

## Device acceptance driver

`tools/phone_acceptance.py` submits one explicitly requested task through the app-private nonce entry and independently checks final UI predicates and bound native receipts. Read [tools/PHONE-ACCEPTANCE.md](tools/PHONE-ACCEPTANCE.md) before using it on an explicitly selected device. No device or ADB port is selected by default. Its in-memory fixtures can be run without any phone:

```sh
python3 tools/test_phone_acceptance.py
```

## Revision 6 status

Revision 6 (`0.2.3-local-control`) changes the controller system instructions
and APK version. The action parser, Accessibility implementation, token budget,
process lifecycle and native runner are byte-for-byte unchanged from revision 5.
The retained parser suite passed 41 accepting cases, 548 rejecting cases and
142 field assertions; the budget suite passed 11 assertions. These checks are
reused by exact source and test hashes, not rerun or broadened by this publication.
See `HOST-CHECKS.json` and `BUILD-VALIDATION.json` for identities and scope.

The subsequent four-case real phone task matrix completed with **0/4 passing**.
`PHONE-QUALIFICATION.json` records the sanitized outcomes. Invalid action fields,
redundant app opening and a copied observation-ID error stopped the tasks; no
goal was independently verified. This checkpoint is work in progress, not a
release or a claim that offline phone control is complete. The original private
evidence remains separate; screenshots, raw UI text and task payloads are not
published.

The reference source build produced APK SHA256
`995d2283daa7e1db3740309951065be8422e9e385d8f23f10c93fad6a05af394`.
That binds the recorded candidate, but does not promise that a rebuild with a
different signing key or build path produces identical APK bytes. The public
build-script changes parameterize paths; their syntax and exact source-only
projection were checked, but a separate public-path APK rebuild is not claimed.
