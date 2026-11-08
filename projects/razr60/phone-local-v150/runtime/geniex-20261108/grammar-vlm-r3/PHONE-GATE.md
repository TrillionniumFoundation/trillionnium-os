# R3 standalone QAIRT phone gate

The independent five-case phone gate passed on 2026-11-08. This qualifies the tested root/magisk, isolated-network model path and its error contract. It does not qualify the production UID 2000 worker domain, launch the provider, or demonstrate real App control. The harness executed zero UI actions.

## Exact candidate

Profile: `qairt-output-grammar-core-r2-vlm-r3-v1`.

| Artifact | SHA256 |
|---|---|
| R2 core | `06e65cbec4de0831e0010c02ff424e197a519f35b137344cb62ff92369abdb5d` |
| R3 VLM | `773e23de3f892d2cd9c468e7b0af32e6c254af341d4ed0e7ef0eda95f6ee1d73` |
| Frozen single-request worker | `67d4e368da136f74a7ab1022013cf1def64f75ebb32d91962772e28a2363864f` |
| Complete runtime manifest | `cba2dba9d5b728cee9206af901493a987478babf0c072503972c4a1f2a2a6ca6` |
| Gate runner | `8e0ffef382ee0f7640016960e6209f928adb3e11a8fa945e11b84070d826e5b8` |

The new phone runtime is `/data/local/tmp/hepta-geniex-vlm-r3-20261108`. It is a separate copy of the R2 runtime with only `lib/qairt/libgeniex_vlm.so` replaced. The official SDK, processor, vision processor, QNN libraries, frozen worker, and Qwen3-VL-4B model files remain unchanged. Relative to the official runtime, the candidate changes only the core and VLM libraries.

## Observed results

| Case | Observed process exit | SDK generate rc | Raw result | Prompt / generated tokens | Process time |
|---|---:|---:|---|---:|---:|
| Invalid grammar | 70 | -201201 | Empty; explicitly rejected | 32 / 0 | 8.93 s |
| No-grammar recovery | 0 | 0 | `42` | 33 / 3 | 9.75 s |
| Grammar discriminator | 0 | 0 | `B`, while prompt requested `A` | 32 / 2 | 9.67 s |
| Blue button, upper layout | 0 | 0 | Complete `mobile_use` JSON; coordinate `[500,250]` | 407 / 38 | 12.65 s |
| Blue button, lower layout | 0 | 0 | Complete `mobile_use` JSON; coordinate `[499,728]` | 407 / 38 | 12.36 s |

Times include worker/model loading and are not a throughput benchmark. Both image coordinates fall inside the correct blue button. The harness verifies the original complete UTF-8 JSON, exact keys, current screenshot identifier, two integer coordinates in the 0–1000 range, and the image-specific target box. It performs no output repair and no action dispatch.

The invalid grammar returned the existing SDK error `GENIEX_ERROR_VLM_GENERATION_FAILED` (-201201). The other seven SDK status values, including destroy and deinit, were zero. The frozen worker recorded `error=sdk_generate_failed`, `generation_complete=false`, `worker_outcome=not_completed`, and planned/observed exit 70. Its raw text file was empty. The existing QAIRT profile adapter still labels this failed result's stop reason `eos`; this field alone is not a success criterion. The nonzero SDK result and failed worker completion are mandatory rejection conditions.

The old R2 harness expected exit 1 for a graceful SDK failure, whereas the frozen worker source `07cd434b…` explicitly uses exit 70. The independent R3 harness uses the actual frozen contract. R2 actually aborted with exit 134 and remains a failed negative test in its unchanged historical evidence.

## Isolation and final checks

Every request ran under a fresh `unshare -n` namespace with empty IPv4 and IPv6 routing tables. The worker timeout was 55 seconds; Android `timeout -k 5 60` bounded each phone process independently of the host. Power mode was the frozen sustained-high-performance enum 6. No worker PID remained after each request or at the end.

All 52 official runtime files, 52 R2 files, 52 R3 files, 24 model files, worker hashes, synthetic image hashes, owner-stop digest, and retained-claims digest were verified. The final checks passed. The existing owner stop and production runtime were preserved.

## Reproducible evidence

Durable job: `1a1bb7bb0e2-13c47-2a2`, terminal succeeded, exit 0, complete durable output.

The 145 raw evidence files and per-file hash index are in `../evidence/qairt-vlm-r3-smoke/`. The original `RESULT.json` is 33,849 bytes, SHA256 `8af9108bdbbe67d81f4c2b2efcde8ebe0d40f80a1e7e5047ec732aa0b171cfad`. The exact runner is `../../../tools/phone_qairt_vlm_r3_grammar_smoke.py`.

The preceding pure-CPU SDK boundary probe is recorded separately in `../grammar-sdk-boundary-probe-r1/evidence/phone-probe-r1/`. It establishes that the original SDK C ABI did not contain the tested processor exception, while a local error-return boundary did; it does not load a model or claim a complete explanation of all cross-library exception behavior.
