# Code18 build and qualification

Code18 source commit is `bd4abff7d1867dcb796bee1da9a194a0da152496`.
Its complete 865-member source manifest is
`2b32fd6c47cabd3c6fe778c3ebe18cb04933c19c4bd7f8289b9569e8c61a3954`.

The change preserves current actionable nodes before old textual and action
history can exhaust the prompt budget. Retained history records factual
package transitions, explicitly describes omissions, and uses the resolved
app catalogue for open targets. Fresh LFM3 configurations default to NPU8192.
An existing explicit configuration is preserved, including an explicit 4K
configuration; this change does not silently migrate it.

## Actual signed Android build

`LOCAL-PREPARATION.json` is a path-sanitized projection of the original
preparation receipt. The Mac toolchain actually compiled Java, DEX and the
Android arm64 native worker; Pocket4 assembled and verified the APK with the
original signer. No new signing key was created. The packaged APK has SHA256
`3db3860bb8613bea3afb36062bf93bf7acadcad9a026e99edea40fab154293d5`,
versionCode 18, and no declared INTERNET permission.
The local APK is separate from the APK produced with an ephemeral CI signer.

All 16 packaged native library members match Code17 byte for byte.
`NATIVE-CLOSURE-COMPARISON.json` retains their exact identities.
The controller's native action protocol, grammar/freshness guards and runtime
payloads were not changed for this prompt-budget correction.

## Complete exact-head CI

[Run 42574950487](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42574950487)
completed successfully for the exact Code18 source commit. Its macOS MNN
producer and Linux consumer both succeeded. The original host suite passed
all 47 gates on the supported Linux/JDK runner, and real Android compilation,
static acceptance and CI packaging completed. The transferred MNN runtime
was verified against the same source head, workflow run and attempt.

`CI-QUALIFIED.json` binds the run, job and artifact identities. The downloaded
artifact ZIPs were independently checked against their full sizes and GitHub
SHA256 digests. All 119 source inputs in the host receipt were independently
matched to the frozen Code18 source. `CI-HOST-CHECKS.json` retains the actual
47-gate receipt.

The CI-only GenieX transport adapter kept the original source fetcher,
archive identity and extraction checks. Its 15 offline fault-injection tests
passed. In this actual run the original official release URL succeeded on
the first attempt; the 98,545,327-byte archive matched SHA256
`248b49c83bc74238babc0d9ebf46f0c8b6d2e9b6de3ffb90c2a5a2042523831f`.
`CI-RUNTIME-TRANSPORT.json` records that selection. The fixed official asset
API fallback was fixture-tested; this run did not exercise it.

Both earlier Code17 workflows that stopped at HTTP 504 are retained:
[42565206107](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42565206107)
and [42569728212](https://github.com/TrillionniumFoundation/trillionnium-os/actions/runs/42569728212).
Each had passed the unchanged 46-gate Code17 host suite before the download
failure. They are not relabelled as successful workflows.

## Local platform and replay boundaries

The original local preparation was a split-platform result: 27 Java compile
and contract gates passed on the cached Mac JDK, and the Linux Python tools
and private staging suites passed 152 and 4 tests respectively. The Mac run
still encountered the existing Linux-specific shell fixture. The preparation
receipt preserves that fact; the later complete CI result is separate.

Five retained historical frames could be reconstructed exactly: calculator
steps 9, 12 and 15, and Settings steps 5 and 15. Their original Code17 prompts
and grammars matched byte for byte. Code18 preserved all 25 calculator nodes
and all 30/29 current Settings nodes in the checked configurations. Three old
Launcher frames remain unresolved because their stored node JSON omitted
cross-package node identities. No complete historical replay pass is claimed.

## Phone qualification is separate

These records prove source, host and Android build qualification. They do not
claim that a particular model reliably completes phone tasks, ordinary Start
and Stop, background execution, restart or lock-screen recovery. Current
phone results must name their exact APK, model/configuration, frozen plan and
entry point. Earlier Code17 failures remain in
[the retained phone regressions](../code17-build-and-qualification/phone-regressions/).
Raw phone logs, private task identifiers, device identifiers, signing keys,
models and APK binaries are not included in this evidence directory.

## Retained Code18 phone rerun

The [independently audited public phone summary](phone-regressions/PUBLIC-SUMMARY.md)
and [safe machine-readable result](phone-regressions/PUBLIC-SUMMARY.json)
record LFM3 NPU8192 at **0 pass / 4 fail** using the unchanged targeted cases.
All 62 native calls completed and had positive HTP offload evidence, while
the original strict task failures remain unchanged.

The calculator retained its relevant 25 current nodes and grammar choices.
A distinct find-app issue remains: the separate 1024-byte recent-history cap
removed explicit provenance of a read-only find call, even though the two
actual rows (1047 bytes) would fit the complete 8192 context. This is a
demonstrated integration factor, not a proven sole cause or a passing verdict.
Code19's stability-window change does not repair this history cap.

All four acceptance records show known cleanup and all 62 native exits were
observed. The offline wrapper's actual `phone_cleanup_known` is null and is
preserved, while its normal completed-and-restored branch independently
verified radio preferences/default connectivity twice. No global/current
live-phone idle flag is invented. Ordinary Start/Stop, background execution
and restart remain separate qualifications.
