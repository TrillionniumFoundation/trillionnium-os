## Standalone 35B MoE qualification (B4)

**Scope: two fixed mock JSON decisions and one cancellation in a standalone native process. This does not establish Hepta App UID inference, Hepta tool dispatch, or an App business-success result. Hepta's default controller remains LFM3.**

The test device was a 16 GB razr with the original Snapdragon 8 Elite and Hexagon v79. MiniCPM-V 4.7 35B-A3B used MobiInfer Android v0.4.5, pinned to `659c3cb5a38493147444a47e0e0762664aacba06`. The converted bundle is from `fengerhu1/MiniCPM-V-4.7-35B-A3B-gguf-hexagon`, pinned to `f125f5a71552e70ccc2d5b0061f77f311bee70c5`. OpenBMB authored the base model; it is not the publisher of this GGUF/expert conversion. The verified 45-file bundle occupies 19,315,173,512 bytes, including Q3 HTP-tiled experts, the resident GGUF, and unused vision/DSpark assets. Configuration retained the trained top-8 experts, bank 256, decode window 21, context 2048, batch/ubatch 128, four inference threads and eight I/O threads. HTP0/HTP1 are logical sessions, not evidence of two physical NPUs or independent VRAM.

### Measurements

| Fixed fixture | First captured stdout | Prompt evaluation | Decode evaluation | Minimum system MemAvailable | Peak child PSS |
|---|---:|---:|---:|---:|---:|
| `note-json` | 7,707 ms | 115 tokens; 22.68 tok/s | 18 runs; 4.37 tok/s | 6,017,396 KiB | 139,732 KiB |
| `adversarial-json` | 11,937 ms | 142 tokens; 17.27 tok/s | 32 runs; 4.62 tok/s | 5,994,852 KiB | 517,131 KiB |
| `cancel-after-token` | 10,206 ms | 119 tokens; 18.73 tok/s | 5 runs; 4.79 tok/s, interrupted | 5,999,336 KiB | 501,908 KiB |

These are captured stdout and native perf measurements, not independently profiled model-token TTFT. Both JSON cases reached native EOG and normal exit 0. Cancellation took **158 ms from actual SIGINT to `waitpid_ECHILD`**, without hard kill. All three cases recorded **41/41 full-layer-offload** and HTP0/HTP1 logs, complete capture, verified cleanup of the owned process tree, zero operator UI inputs, unchanged main-screen focus, and thermal status 3. Layer placement does not establish that every operator ran on the NPU. No energy, sustained thermal, vision or DSpark test was performed.

### Original verdict preserved; CLI framing reviewed offline

The original B4 verdict remains `false, false, true`, with `all_cases_passed=false`. Its whole-stdout JSON decoder rejected the fixed CLI trailer ` [end of text]\n\n\n`. The pinned completion source writes that trailer after native EOG; it is console framing, not a model token. Both preceding JSON objects exactly matched the fixed fixture expectations.

The separately reviewed offline adjudicator requires the exact source-version-specific trailer, one unambiguous marker, and one entire strict UTF-8 JSON object equal to the fixture. It rechecks original raw-file hashes, plan, normal signal-free exit, capture, full offload and ECHILD evidence. **34 checks passed: one positive case and 33 rejection cases**, including extra JSON, arbitrary leading/trailing data, markers inside strings, duplicate keys, truncation, interruption and missing cleanup. A second independent host replay produced the identical report hash. Original records were not rewritten and the phone was not rerun. This qualifies only the two mock decisions and cancellation.

### Memory workaround and remaining integration

B4 changed only `LLAMA_MOE_IO_POOL=1`. The pinned O_DIRECT scratch buffer uses a raw `thread_local` pointer without a thread-exit destructor. With the pool disabled, repeatedly created/joined readers lose their final allocation. An exact-block host reproduction measured 128 allocations/zero frees over 16 waves of eight temporary readers, versus eight allocations and flat RSS with persistent readers.

B4 decode PSS stayed at 139,036–139,732 KiB for notes, 126,731–142,187 KiB for the adversarial fixture, and 129,544–131,084 KiB for cancellation. The approximately 500 MiB peaks occurred before first stdout. System MemAvailable stayed above approximately 5.72 GiB; the unchanged 3/2 GiB memory protection did not fire. PSS excludes some shared DSP/system allocations and is not total model RAM.

The pool is a single-process workaround: terminating its workers still leaves their final scratch allocation until process exit, and failed pool construction can fall back to temporary readers. Production integration needs RAII scratch lifetime management, an isolated runtime ABI, actual Hepta grammar and task/observation/display binding, repeated context/cancellation tests, and real tool results. The 115/142-token prompts do not qualify Hepta's much longer controller context. No further parameter sweep or default-model change follows from these results.

### Evidence identities

| Evidence | SHA-256 |
|---|---|
| Preserved original B4 run | `e7060ce3876b47d3b65147d1be0cdbceff313f3c66c4870b9a44ed9e12378bea` |
| Frozen B4 plan | `c3fe48348d7964b6bcace181a8c15611108ff159e7ffab9259d019e0362525ab` |
| Verified converted 45-file bundle manifest | `83ccf0b0234649a692371f8d54155350e2b27b13bd8d4bbfa4d98ddb917de454` |
| Accepted offline framing report | `c5c4bea01b08d33fd6f5377c49c2e5ef65ce7419ed834071fae6b878bcb2524e` |
| Offline adjudicator | `c98a6a32989908869be050ee1906abb4ae5b7b059caf974e5e81528fd86e7f9d` |
| Framing/execution checks | `bf93fa413dfa2bdd8414413beea42e10f15b2c15bba38e8a033fd1fc1a2c7724` |

### Primary sources

- [Qualcomm Snapdragon 8 Elite](https://www.qualcomm.com/smartphones/products/8-series/snapdragon-8-elite-mobile-platform): hardware family and Hexagon NPU; theoretical throughput is not substituted for this device's measurements.
- [OpenBMB model card](https://huggingface.co/openbmb/MiniCPM-V-4.7-35B-A3B): model identity and Apache-2.0 weight license.
- [Pinned converted GGUF/Hexagon bundle](https://huggingface.co/fengerhu1/MiniCPM-V-4.7-35B-A3B-gguf-hexagon/tree/f125f5a71552e70ccc2d5b0061f77f311bee70c5): conversion provenance and the exact verified revision.
- [Pinned MobiInfer README](https://github.com/IPADS-SAI/Mobiinfer-Android/blob/659c3cb5a38493147444a47e0e0762664aacba06/README.md) and [MIT runtime license](https://github.com/IPADS-SAI/Mobiinfer-Android/blob/659c3cb5a38493147444a47e0e0762664aacba06/LICENSE). The published 23.3 tok/s figure uses 8 Elite Gen5 and is not this device's result.
- [Pinned completion source](https://github.com/IPADS-SAI/Mobiinfer-Android/blob/659c3cb5a38493147444a47e0e0762664aacba06/tools/completion/completion.cpp): native EOG console marker at lines 979–981 and final newlines at line 997; stdout routing is in the same commit's common/log.h and common/log.cpp.
- [Pinned expert-slot source](https://github.com/IPADS-SAI/Mobiinfer-Android/blob/659c3cb5a38493147444a47e0e0762664aacba06/src/llama-moe-slot.cpp): pool at lines 204–258, raw TLS scratch at 3062–3078, temporary-reader fallback at 3560–3569.
