# Reconstruct the original MNN runtime without changing its identity

This independent helper builds the fixed MNN source and original r4 worker, then
requires all three complete runtime files to match the installed candidate's
existing size and SHA-256 pins. It admits frozen Code 14 source manifest
`ae815ddf677ab3591f9d588cae19d9067fe86d04445d562b9f2583a9147f7edf`.
It does not edit that source, install an APK, contact a phone, fetch model weights,
change runtime pins, strip an ELF, or rewrite a compiled file.

## Why the first source rebuild differed

The earlier independent helper rebuilt MNN and the worker successfully, but its
worker had a different complete hash. MNN and the NDK C++ library already matched
the original full-file hashes. A read-only section comparison localized the
worker differences to debug information, symbol-table offsets, and build ID.
The original and new compiler inputs used distinct absolute paths.

A new isolated worker-only compilation normalized the three observed source,
build, and MNN-header path prefixes to their original recorded spelling. It used
the actual pinned r28b compiler and original optimization/linker settings. All 986
entries of the original compiler dependency list were compared with the selected
new inputs before compilation. The resulting freshly linked worker matched the
original **entire file**, 2,186,768 bytes and SHA-256
`b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020`.

The integrated helper then completed a fresh two-stage Mac build in 72.093
seconds. Authoritative job `1a1bd9743fd-138b0-71a` exited 0 with all three complete
files matching, the unchanged Code 14 static verifier passing, and an
assembler-ready `runtime` directory created. Its new receipt is retained at
`evidence/mac-r28b-r2a/NEW-BUILD-RECEIPT.json`, SHA-256
`62640d6fefbfe02ff45cbe25fc1e9b65656134537d1c652dfad1d307e999dd13`.
It used helper SHA-256
`62309fa20e51186f37f59e6aba1ea8ace08fb086131b61b47383f89e3c42e861`.
The source qualification, actual compiler command, and complete three-file
comparison are retained beside that receipt. Linux CI has not yet been run.

That worker-only proof is retained separately under
`hepta-mnn-worker-path-repro-r1`; its report SHA-256 is
`d02d1127eae15c231413d07f341e951ea4d3bd84a3b9a204b0163d606991b437`.
Its authoritative Mac job `1a1bd91b0ca-138b0-70d` completed with exit 0. The report
contains all dependency hashes, exact compiler/linker argv, six mapping flags,
and original/rebuilt complete identities. No original output file was reused as
the rebuilt worker.

## Minimal compiler delta

The helper passes paired `-fdebug-prefix-map` and `-ffile-prefix-map` options for:

- The new worker source directory to the original worker source directory.
- The new worker build directory to the original compilation directory.
- The new MNN source directory to the original MNN-header directory.
- When different, the actual host NDK prebuilt directory to the original recorded
  NDK prebuilt spelling.

These options normalize path spelling in compiled output. The file-prefix option
can also affect source-location strings; this is not a claim that only DWARF can
change. The whole-file gate decides whether the complete output is the original
runtime. The recorded original path names are output metadata destinations, not
directories written by the build, and they need not exist on the new host. A
Linux host remains recorded as Linux with its actual NDK, compiler hash, and
source.properties; a mapping to a historical Darwin path does not change that.

For the pinned r28b CMake toolchain, `CMAKE_CXX_FLAGS_RELEASE` receives only the
additional mapping suffix. The toolchain prepends its original `-O3 -DNDEBUG`.
The helper checks the actual compilation argv for exactly one copy of both
optimization flags, the original `-g`, and one copy of every mapping flag. An
initial integration attempt redundantly supplied the optimization flags; the
new actual-argv gate rejected it with exit 2. That rejected attempt remains in
its own Mac output directory and was not accepted as an original runtime.

## Tool and source identity

The actual NDK is **28.1.13356709 (r28b)**. Its original directory was named
28.2.13676358, which is not a version attestation. `toolchain-provenance.json`
contains the observed source.properties, actual Clang 19.0.0/Android build
13324770/r530567d version, compiler SHA, and original CMake records. Every new
build records its own actual tool paths, versions, and hashes.

MNN is the fixed public commit
`bce7456ce60b5e51b4d3b357f303515860353d8c` from
`https://github.com/doulujiyao12/mobiinfer`. The helper creates a non-hardlinked
local clone and checks out that commit without changing the supplied cache.
It copies the frozen worker source and applies its three pinned observation
transforms only to the new MNN checkout. Both upstream and transformed source
hashes must equal the retained original build receipt. The original
`MNN_USE_LOGCAT=OFF`, OpenCL/LLM/OMNI/CV settings, and disabled HTTP/MLS settings
remain explicit and are checked against CMake's actual cache.

MNN and the worker are compiled in separate real build stages. The target C++
library is copied from the verified NDK. No prior MNN or worker binary is used as
a substitute for either source build.

## Whole-file acceptance

| File | Required bytes | Required SHA-256 |
|---|---:|---|
| `hepta-mobimind-probe` | 2,186,768 | `b3899c03f88070e0042132dc9f17d81437d2b018c3406598f97939fc52ff9020` |
| `libMNN.so` | 6,408,488 | `5019009bfc9b209afeb89d23db0f1c52985cc1111e3364a448f7c7ed7a4c457d` |
| `libc++_shared.so` | 9,236,352 | `77a34d3f03b17709f3f6473f37cb7795314e51fa3e5e652b5c37d53cfd05c754` |

The unchanged Code 14 verifier additionally checks arm64 ELF structure,
dependencies, the worker's single `$ORIGIN` RUNPATH, observational hook symbols,
and guarded SHA2 instructions. Frozen App source is verified before importing
its code and again after the build.

- Exit 0 requires all three complete identities plus static validation. Only
  then does `out/runtime` receive the exact outputs and an unchanged copy of the
  **original** build receipt. `NEW-BUILD-RECEIPT.json` separately describes this
  new build, including the actual helper script hash.
- Exit 3 means source compilation and static checks completed, but bytes differ.
  No assembler-ready runtime directory or original receipt is published.
- Exit 2 means source/tool/build/static validation failed. Evidence is retained;
  no successful original-runtime claim is made.

Neither a successful reconstruction nor a newly signed CI APK proves ordinary
App OpenCL availability, model semantics, tool execution, cancellation, or the
functional acceptance suite. Those remain separately bound device observations.

## Run

```bash
python3 -B rebuild_exact_runtime.py \
  --app-source /absolute/frozen-code14-source \
  --mnn-checkout /absolute/local-mnn-git-cache \
  --ndk /absolute/android-sdk/ndk/28.1.13356709 \
  --cmake /absolute/path/to/cmake \
  --output /absolute/new/rebuild-output
```

The output directory must be new and outside all original inputs. No model
download, phone access, or APK assembly is part of this command.

`workflow-proposal.yml` remains an unpublished proposal. It invokes the helper
before assembly and publishes `MOBIMIND_ANDROID_RUNTIME_DIR` only after exit 0.
It does not swallow exit 2/3 or upload the runtime binaries. Evidence JSON/logs
are retained on failures. A future Linux CI run must pass its own complete hash
gate; the Mac result does not establish cross-host reproduction.
