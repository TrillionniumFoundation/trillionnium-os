# Hexagon FastRPC close: one-line backport for the pinned SDK

This is an unadopted source-review candidate for GenieX v0.10.0's exact llama.cpp dependency. It changes one function-pointer parameter from the 32-bit handle type to the 64-bit handle type. The accompanying host regression extracts the actual production typedef, pointer storage and forwarding wrapper, checks them against an independently pinned Qualcomm FastRPC API declaration, and calls a synthetic peer through that wrapper.

No SDK tree, shared candidate, app package or phone was changed. There is no Android/DSP build or device qualification in this capsule.

## Verified source and upstream fix

- [GenieX v0.10.0](https://github.com/qualcomm/GenieX/releases/tag/v0.10.0) is commit `071f609995470bdb0e0769ab964754adfaab7e47`. Its [`third-party/llama.cpp` gitlink](https://github.com/qualcomm/GenieX/tree/071f609995470bdb0e0769ab964754adfaab7e47/third-party/llama.cpp) pins `19cce6919992fdffd92e0ac152caaf1e2b8f254e`.
- The [exact pinned driver](https://github.com/ggml-org/llama.cpp/blob/19cce6919992fdffd92e0ac152caaf1e2b8f254e/ggml/src/ggml-hexagon/htp-drv.cpp) still declares `remote_handle64_close_pfn_t` with `remote_handle`, although its forwarding wrapper accepts `remote_handle64`.
- [Upstream PR 30952](https://github.com/ggml-org/llama.cpp/pull/30952), authored by `dmnobunaga`, merged on 2026-11-10 at 00:10:14 UTC as [`cf6463ace735a570d5734da4957d54b720cac6f8`](https://github.com/ggml-org/llama.cpp/commit/cf6463ace735a570d5734da4957d54b720cac6f8). Its only code change is this parameter-type correction. [Release b12241](https://github.com/ggml-org/llama.cpp/releases/tag/b12241), published at 01:44:35 UTC, targets that commit.
- The API fixture uses [Qualcomm FastRPC `remote.h`](https://github.com/qualcomm/fastrpc/blob/8f5927397d1b7c87e6724cb1ddbde956a7f34cab/inc/remote.h): `remote_handle` is `uint32_t`, `remote_handle64` is `uint64_t`, and the close prototype takes `remote_handle64`. This header is an external, exact test input; it is not a change to the deployed SDK dependency.

The upstream author reports a close result changing from `0x2c` to zero on Snapdragon 8 Elite Gen 5 / Hexagon v81. That report does not establish behavior on this razr's Hexagon v79. Upstream also limits its claim about complete RPC memory cleanup and repeated lifecycle behavior. No result here attributes the razr's separate `0x2e` condition, incorrect app actions, or Bonsai behavior to this ABI defect.

## Exact backport

`hexagon-close-abi.patch` applies to `ggml/src/ggml-hexagon/htp-drv.cpp` at the pinned llama.cpp commit. It changes one line and does not replace the file with the newer upstream version.

| Identity | Value |
| --- | --- |
| Pinned source Git blob | `437e367c9d35d58de9d5f1c0b310d218910f50f0` |
| Pinned source SHA256 | `8b93060b8f5a0aceb77c708d1772c56699810e901a52ab0ae1a4826f9f3e6854` |
| One-line backport Git blob | `246286b6494f05ba7d6b285a73e07f3ba34e9095` |
| One-line backport SHA256 | `926f4a49fa4b5f840c9ec424add67b509b2171e03d537409f02662bc9b35d273` |
| New upstream file Git blob | `9ae4ea7275ac57f077fa35fa3ba192b77c96fc8f` |

The backport blob differs from the newer upstream file because other changes occurred between the two source revisions. `BASELINE.json` separates these identities from the repository commit used only to publish this review capsule. Refuse a different target hash; reconcile its source separately.

Before any integration, work in a separate exact source checkout, verify the original SHA256, and apply the patch from that llama.cpp root. The recorded patch check applied the published patch to an isolated copy and obtained exactly the backport SHA above. This capsule does not apply it to GenieX, rebuild a plugin, or install a binary. Reversing this one hunk in the exact reviewed source is the source rollback; no device rollback is involved.

## Reproduce the host ABI check

Supply the two external files with the exact hashes in `BASELINE.json`:

1. `htp-drv.cpp` from llama.cpp commit `19cce6919992fdffd92e0ac152caaf1e2b8f254e`.
2. `inc/remote.h` from Qualcomm FastRPC commit `8f5927397d1b7c87e6724cb1ddbde956a7f34cab`.

Then use an existing C++ compiler and a new output directory:

```sh
python3 test_close_abi.py \
  --driver-source inputs/htp-drv.cpp \
  --fastrpc-header inputs/remote.h \
  --output host-abi-result
```

The runner refuses other input hashes and existing output directories. It leaves both inputs unchanged, derives only the reviewed one-line variant in memory, and compiles small extracted fixtures. It does not download anything. `--compiler` can select an existing compiler executable.

The original FastRPC handle typedefs and close declaration come from the exact header, not from a guessed integer-width mock. Platform export and annotation macros are empty in this Linux host fixture. The production forwarding wrapper and pointer storage are copied unchanged into a separate translation unit from the synthetic peer. Compilation uses `-std=c++17 -O0 -fno-lto -Wall -Wextra -Wconversion -Werror -pedantic-errors`.

### Recorded outcomes

| Check | Result |
| --- | --- |
| Baseline compile | Expected exit 1: `FAST_RPC64_CLOSE_ABI_MISMATCH`, a narrowing diagnostic in the actual wrapper, and incompatible function-pointer assignment |
| Patched compile | Exit 0 under the same compiler flags |
| Patched behavior | Exit 0: 6 actual stub dispatches; 5 inputs have nonzero high 32 bits; all complete handles and return values preserved |
| Input integrity | Both external inputs unchanged after the run |
| Patch application | Published patch applies cleanly to an isolated exact copy; resulting bytes match the backport SHA |

The baseline fixture is never executed through an incompatible function pointer. The six handle bit patterns and return values are synthetic ABI probes, not valid-device-handle claims or measured DSP error codes. `baseline-compile.stderr` and `patched-behavior.stdout` are byte-exact host outputs; `VALIDATION.json` binds their hashes and the extracted member identities. The recorded environment was x86_64 with GCC 14.2.0.

## Scope and attribution

This evidence covers the host C++ type boundary and the production wrapper's forwarding behavior. It does not exercise `dl_get_sym`, load `libcdsprpc`, prove Android arm64 calling behavior in a rebuilt plugin, execute a Hexagon DSP, validate v79 cleanup or repeated sessions, run a model, or qualify any phone task. Actual integration still needs the matched source build, binary provenance and separate device ownership/acceptance. No SDK-wide upgrade is proposed.

The patch is a backport of the upstream authors' MIT-licensed correction. The llama.cpp MIT copyright and permission notice are retained in `LICENSE-llama.cpp-MIT.txt`. The externally extracted FastRPC declarations retain Qualcomm Innovation Center's 2024 notice in generated fixtures; its BSD-3-Clause terms are retained in `LICENSE-fastrpc-BSD-3-Clause.txt`. Full SDK and API source files are not republished here. The regression runner and synthetic peer are review scaffolding, not replacements for either upstream component.
