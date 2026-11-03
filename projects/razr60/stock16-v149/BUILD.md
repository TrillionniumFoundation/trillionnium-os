# Build and source preparation

All commands below produce host-only outputs in a **new** directory. None deploys
or signs an application, invokes ADB, modifies a device, or starts a production
provider. Replace the example paths with your retained, hash-verified inputs.
The original captured builders are preserved alongside the new drivers.

## 1. Native API36 programs — Linux

Requirements: Python3, bubblewrap, readelf, retained Clang `clang-r584948b`, captured
AOSP headers and stock16 shared link inputs. `native/api36/recipes.json` contains
the exact 3 build recipes and 1,038 SHA256/size input pins. The driver validates
these inputs before and after compilation and runs the tools in an isolated
network namespace with read-only dependency mounts.

On the original configured host:

```sh
python3 native/api36/rebuild.py --out /absolute/new-output/native-api36
```

For moved input trees, supply a JSON object mapping recorded absolute directory
prefixes to new absolute directory prefixes:

```sh
python3 native/api36/rebuild.py \
  --root-map /absolute/input-root-map.json \
  --out /absolute/new-output/native-api36
```

The returned receipt must report `compiler_success`, `all_binaries_match_installed`,
`external_dependencies_unchanged`, and `source_unchanged` as true. The three
binary hashes are listed in `README.md`. API36 targeting does not erase the
recorded AOSP17 header provenance.

## 2. Unicode and screenshot DEX helpers — macOS reference build

The captured `build.py` files refer to the original Mac SDK/JDK paths. The wrapper
below validates their hashes and substitutes only the SDK/JDK assignment nodes
in memory; the files, source and command flags remain unchanged.

```sh
python3 android/rebuild_dex_helper.py unicode-v148r2 \
  --sdk-root /absolute/android-sdk \
  --jdk /absolute/temurin17 \
  --out /absolute/new-output/unicode
python3 android/rebuild_dex_helper.py screen-codec-v148r1 \
  --sdk-root /absolute/android-sdk \
  --jdk /absolute/temurin17 \
  --out /absolute/new-output/screen-codec
```

Use `platforms/android-34/android.jar`, build-tools **34.0.0**, and the measured
Temurin17 toolchain. Compile SDK34/java8 and runtime minimum API36 are separate
properties. Reference hashes are in `dependencies/java-mac.json`; Linux tools
with the same version label may have different executable hashes and require a
separate verification record. Both wrappers were run on the reference Mac and
produced the exact installed JAR hashes.

## 3. Desktop sidecar and visual test probe

These captured builders already accept explicit tool locations:

```sh
python3 android/desktop-sidecar-v145/build_unsigned.py \
  --sdk-root /absolute/android-sdk --jdk /absolute/temurin17 \
  --out /absolute/new-output/sidecar
python3 android/visual-probe-v148r1/build_unsigned.py \
  --sdk-root /absolute/android-sdk --jdk /absolute/temurin17 \
  --out /absolute/new-output/visual-probe
```

Compare the uncompressed APK payload members against the retained signed
baselines, excluding signature-only container metadata. The fresh sidecar has
7/7 matching members; the probe has 3/3. Public certificate identities are in
`verification/apk-payload-comparison.json`. Private keys are neither necessary
for these comparisons nor included in the snapshot.

## 4. HEPTA49 — Linux reference build

Retain this input layout under a reference root:

```text
inputs/source_3/prebuilts/jdk/jdk21/linux-x86/
inputs/source_3/prebuilts/sdk/current/public/android.jar
inputs/source_3/prebuilts/sdk/current/public/core-for-system-modules.jar
inputs/source_3/prebuilts/sdk/tools/linux/{bin,lib,lib64}/
inputs/R8_9_3_27/r8-9.3.27.jar
```

First generate the javac system image in a separate new output:

```sh
python3 android/hepta49/prepare_system_modules.py \
  --jdk /absolute/reference/inputs/source_3/prebuilts/jdk/jdk21/linux-x86 \
  --core-jar /absolute/reference/inputs/source_3/prebuilts/sdk/current/public/core-for-system-modules.jar \
  --out /absolute/new-output/android-system-modules
python3 android/hepta49/rebuild_unsigned.py \
  --reference-root /absolute/reference \
  --system-modules /absolute/new-output/android-system-modules/system \
  --out /absolute/new-output/hepta49
```

The helper rebuild follows the AOSP `build/soong/java/system_modules.go` sequence:
generate `java.base` exports, compile module-info with `--system=none`, create a
JMOD, and jlink with the system-modules plugin disabled. Its public core stub JAR
has SHA256 `f31de8c02da7ef7f610c5026e129bcbb4f698db9303eca1ed2c46995a51293ad`.

This recovered dependency yields a working host build with the precise DEX
limitation documented in `README.md`. The original signed build used a different
core-all system image that is presently unavailable. Replacing this limitation
with a claim of exact signed reconstruction would be incorrect.

The source manifest is unchanged. The wrapper cannot accept `--sign` and clears
the original profile's signing inputs. Do not use the preserved historical
builder's signing path for this host-only reproduction.

## 5. Complete GNU backend source — pinned baseline plus four overlays

Start with a local Git clone containing the exact frozen upstream commit:

```sh
python3 backend/prepare_workspace.py \
  --checkout /absolute/trillionnium-os-clone \
  --out /absolute/new-output/gnu-source
```

This source-only helper requires Python3.11+. It resolves the exact fixed commit,
exports Git objects rather than the checkout's mutable working tree, rejects
unsafe archive paths/links, verifies every file in the frozen source manifest,
checks each overlay's expected previous/new hash, and checks all declared Cargo
workspace members. It does not fetch, write the supplied clone, copy `.git`,
compile Rust, or build a filesystem image. The four allowed overlays are:

| File | Role |
|---|---|
| `apps/trillionnium-owner-open-host/src/bin/r5_control_host_v4/process.rs` | Production core change |
| `tools/owner-open/owner_open_broker_admission_v2.py` | Production broker change |
| `tools/tests/test_owner_open_inspect_observation_lane.py` | Host fixture |
| `apps/trillionnium-owner-open-host/tests/r5_late_cancel_known_terminal.rs` | Host fixture |

The small `source7` directory is a provenance subset and intentionally remains
byte-preserved; it is not a substitute for this full checkout. The source helper
has not been represented as a fresh GNU compile. Historical GNU build receipts
in `gnu-core-provenance` must retain their original dates and scope.

The next GNU rebuild needs the recorded Rust cross target, GNU compiler/sysroot,
exact dynamic runtime libraries and full image construction inputs. Until those
are freshly rebuilt and verified, the existing 931-entry rootfs remains a pinned
prebuilt runtime. Its full image is not redistributed by this source snapshot.

## 6. Provider source checks

The v149 provider is Python source. Its own `provider/v149-r1/README.md` describes
offline checks and contracts. The `validation/` records inside that directory
are the frozen candidate results. Root separately reran the same suite on the
deployment Mac, added one compatibility regression, and recorded the live switch.

Source tests may be run without connecting to a phone. Review the exact test
entry points and fixtures before doing so. Production provider scripts include
site-specific route/device defaults and are not started by these build steps.

## Verification files and limits

`verification/` preserves freshly obtained compiler results, exact payload
comparisons, relocation checks and the HEPTA49 disassembly difference. Historical
source provenance remains under `backend/frozen-intake-v142` and in part manifests.
No unsigned build here has been installed. Only Root's separate v149 provider
deployment changes the current host service; phone and model acceptance remain
separate evidence.
