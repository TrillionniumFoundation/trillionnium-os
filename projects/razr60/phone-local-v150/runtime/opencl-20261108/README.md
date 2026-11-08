# Android OpenCL candidate — 2026-11-08

## Status and scope

This directory records an isolated **candidate** build of unmodified upstream
llama.cpp for the phone's Qualcomm Adreno 830. It is not a replacement release
of the existing Hepta r9/r10 service.

At this build checkpoint, the Android executables compiled, passed static ELF
inspection, and were copied to pocket4 with matching SHA256 values. The build
agent did not install or execute them on the phone. Phone tests are recorded
separately by the integration driver. The initial visual tests did **not** pass;
successful loading, exit status, GPU offload, or token throughput alone does not
establish correct vision or successful phone control.

The original `BUILD-MANIFEST.json` is immutable build evidence for
`llama-server`, `llama-bench`, and `llama-mtmd-cli`.
`LLAMA-CLI-BUILD-SUPPLEMENT.json` records the subsequently built text CLI without
changing that original manifest.

## Fixed inputs

| Input | Fixed identity |
| --- | --- |
| llama.cpp commit | `d6be065572cdb7bf64014c8c5771e210c9570e44` |
| Official source archive | `https://codeload.github.com/ggml-org/llama.cpp/tar.gz/d6be065572cdb7bf64014c8c5771e210c9570e44` |
| Archive bytes / SHA256 | `39127760` / `2c9c3a5265e4180d0bbde672b2d6d8f177fcf360dd79127357ca00923a0483e7` |
| OpenCL-Headers repository | `https://github.com/KhronosGroup/OpenCL-Headers.git` |
| OpenCL-Headers commit | `82f60316cc142e7b21dc1d8983b26de18858fbd9` |
| Actual NDK revision | `28.1.13356709`, release `r28b` |
| Installed NDK directory used | `/Users/qianqi/Library/Android/sdk/ndk/28.2.13676358` |
| CMake used | `/opt/homebrew/bin/cmake`, version `4.3.2` |
| Phone link-only OpenCL library | `/vendor/lib64/libOpenCL.so`, `87504` bytes |
| Link-only library SHA256 | `cd35cf1ecbfb2053e45566421aa605f819b69ceb5264706ed4feb15bed0942f9` |

**The NDK directory name is misleading:** its own `source.properties` reports
r28b / 28.1.13356709. Reproduction must record the actual properties, not infer a
toolchain version from the enclosing directory name.

The two source pin JSON files are inputs consumed by the build script.
The original source archive, extracted source, headers checkout, NDK, and the
phone's vendor library are intentionally not included in this small evidence
package. No model weights or private API keys are included.

## Prepare a fresh build directory

The supplied script uses its own containing directory as its build root and
the exact Mac tool paths above. Use a new directory; the script intentionally
refuses to overwrite existing manifest/log/artifact files. Copy these three
files into that new directory:

- `build_android_opencl_r2.py`
- `llama.cpp-source.json`
- `OpenCL-Headers-source.json`

Create `logs/`, `artifacts/`, and `vendor-link/` there. Download the fixed
source archive, preserving this exact filename:

```sh
curl --fail --location \
  https://codeload.github.com/ggml-org/llama.cpp/tar.gz/d6be065572cdb7bf64014c8c5771e210c9570e44 \
  --output llama.cpp-d6be065572cdb7bf64014c8c5771e210c9570e44.tar.gz
```

Verify its size and hash **before extracting**:

```sh
python3 - <<'PY'
from pathlib import Path
import hashlib
p = Path("llama.cpp-d6be065572cdb7bf64014c8c5771e210c9570e44.tar.gz")
assert p.stat().st_size == 39127760
assert hashlib.sha256(p.read_bytes()).hexdigest() == "2c9c3a5265e4180d0bbde672b2d6d8f177fcf360dd79127357ca00923a0483e7"
PY
tar -xzf llama.cpp-d6be065572cdb7bf64014c8c5771e210c9570e44.tar.gz
mv llama.cpp-d6be065572cdb7bf64014c8c5771e210c9570e44 llama.cpp
git init OpenCL-Headers
git -C OpenCL-Headers remote add origin https://github.com/KhronosGroup/OpenCL-Headers.git
git -C OpenCL-Headers fetch --depth 1 origin 82f60316cc142e7b21dc1d8983b26de18858fbd9
git -C OpenCL-Headers checkout --detach FETCH_HEAD
```

The build script checks the headers' Git HEAD, so a headers tarball without
Git metadata is not an equivalent preparation for this exact script.
In the recorded session, downloading the source on pocket4 and copying through
the already configured `hepta-pocket4` SSH alias avoided slow Mac internet
transfer. That transport choice does not change the source pin.

Use a read-only ADB pull from the target phone to obtain **its own** library at
`vendor-link/libOpenCL.so`. For this session the explicit host-side command was:

```sh
/home/alex/.local/bin/adb -P 5061 -s ZY22LS7WZT \
  pull /vendor/lib64/libOpenCL.so vendor-link/libOpenCL.so
```

That command belongs on the already configured pocket4 host; transfer its
result into the fresh Mac build directory if building there. It only reads the
phone. Do not copy the vendor library into a distributable binary package or
into the NDK sysroot. The script validates the exact library hash above; an
updated driver requires new provenance instead of silently reusing this pin.

The expected prepared layout is:

- the build script and both source pin JSON files in the root;
- the exact `llama.cpp-<commit>.tar.gz` archive in the root;
- `llama.cpp/` containing the untouched extracted archive;
- `OpenCL-Headers/` containing the pinned Git checkout;
- `vendor-link/libOpenCL.so`;
- empty `logs/` and `artifacts/` directories.

Run `/usr/bin/python3 build_android_opencl_r2.py` on the Mac. The script invokes
CMake itself and limits compilation to four jobs. It does not contact ADB,
change phone services, or run phone inference.

## Build configuration

The complete executable arguments are in `BUILD-MANIFEST.json`. Relevant
choices are Android arm64-v8a / API 28, Release, static C++ and static project
libraries, OpenCL with embedded Adreno kernels, `GGML_NATIVE=OFF`, and
`GGML_OPENMP=OFF`. Vulkan and Hexagon are not built. CPU support remains
available for explicit controls and unsupported operations. HTTPS, subprocess
features, web UI downloads, examples, and upstream test targets are disabled
for this candidate. Disabling upstream test targets is not a claim that any
phone acceptance test passed.

The archive source tree was unchanged across the build:
`c8390d3da1f25f74309f2c346b245017bff9545eaf56211aef6c99138de89608`.
The digest algorithm is implemented in the supplied build script.

## Strip deployment copies

Keep the original unstripped `artifacts/` files for diagnosis. The deployment
files were made by copying them into `deploy/` and invoking:

```sh
/Users/qianqi/Library/Android/sdk/ndk/28.2.13676358/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-strip \
  --strip-unneeded deploy/llama-server
```

Apply the same command to deployment copies of `llama-bench` and
`llama-mtmd-cli`. Record SHA256 after stripping, since it differs from the
unstripped binary. Use the NDK's `llvm-readelf -h -d` on each final copy.

The produced files are AArch64 Android ELFs with `libOpenCL.so` in
`DT_NEEDED`, no build RPATH/RUNPATH, and no `libc++_shared.so` dependency.
No additional project .so files are needed. The target device still needs its
own existing vendor OpenCL driver and the system libraries that driver uses.

The three deployment hashes and unstripped hashes are both retained in the
original manifest. A different compiler, build path, or host environment may
produce different bytes; the recipe establishes repeatable inputs and flags,
not a claim of byte-identical builds across unrelated environments.

## Additional text CLI

Build the extra target against the same configured tree:

```sh
/opt/homebrew/bin/cmake --build build-opencl --target llama-cli --parallel 4
```

Copy `build-opencl/bin/llama-cli` to a new deployment file, strip it with the
same NDK tool, and write a separate supplemental manifest. The recorded
stripped CLI is 15,920,848 bytes with SHA256
`b632be32926ebae64ad104b154c235a31b80f3a219c5dcc6269a7bf1e3fdfe14`.

This version supports `--single-turn` / `-st`, `--simple-io`, and
`--no-display-prompt`. With `-p PROMPT`, `--single-turn` exits after the
response. Do not use `llama-mtmd-cli -p PROMPT` without an image as a text
single-turn control: that program's single-turn branch requires both a prompt
and an image. It otherwise enters its interactive branch.

A strict CPU control uses `--device none`; `-ngl 0` alone does not guarantee
all GPU computation is disabled. A vision CPU control also uses
`--mmproj-device none`. GPU tests must use the device name returned by the
phone's own `--list-devices`.

## Hepta integration limits

These are pure upstream executables. They do not contain Hepta's persistent
request-ID journal, `/hepta/requests/:request_id` endpoint, custom
`/slots` receipt fields, or CPU cancellation safe-point changes.
The existing r9 native implementation explicitly requires zero GPU layers
when its CPU cancellation safe-point mode is enabled.

Consequently, these executables are suitable for isolated capability and
quality tests. Production integration still requires an explicit protocol
port/adaptor, identity and artifact pin updates, and tested GPU cancellation
and slot-release semantics. Removing the CPU-only guard or treating HTTP
client termination as completed GPU cancellation is not an integration fix.

The model must also pass visual and structured-action correctness checks.
The initial synthetic-image output was invalid, so the candidate must not be
represented as an accepted vision model or a completed offline phone agent
based on its build or throughput results.
