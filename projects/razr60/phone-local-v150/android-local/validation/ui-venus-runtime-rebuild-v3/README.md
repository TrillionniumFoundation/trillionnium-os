# UI-Venus Q4_0 worker: exact macOS rebuild and Linux transfer

This v3 admits only the public Code20 click-policy source manifest
`1e5041491e3d2b9472b66db28d1cf2c602b45df8c3d0e8c9ee717e91cfd881ca`.
The earlier public Code20 v2 helper remains unchanged. This helper builds the
already frozen Q4_0 ordinary-App worker from its pinned C source, using the
actual r28b toolchain and the same twelve GenieX SDK libraries. It does not
download model weights, contact Android, run inference, or package an APK.

The native source boundary is explicit: 19 original native files, 18 byte-for-byte
unchanged, and only four model identity literals changed in `native/venus-runtime.inc`.
The model filename, size, whole-file SHA-256, and profile name identify Q4_0.
The original F16 projector, native VLM implementation, App entry guard, compiler
flags, context 8192, output limit 1024, and native deadline 300000 ms remain fixed.
The receipt must say `original_core_byte_unchanged=false`; a Code17 Q4_K_M
receipt or the old 17-unchanged-file boundary is rejected.

The rebuilt worker must be exactly 58144 bytes with SHA-256
`5fa2dcae05fb649157d96481c5890c157301c76dab3522fcabcbe01b9b0d8551`.
Its actual ELF type, imports, dependencies, `$ORIGIN` RUNPATH, SHA2 instruction
ownership, model pins, SDK library closure, and full native boundary report are
checked. A mismatch returns nonzero and does not authorize the original assembler.
The unchanged historical `BUILD-RECEIPT.json` is copied only after success for
the frozen runtime verifier; `NEW-BUILD-RECEIPT.json` separately records the new
source compile and link. Historical evidence alone cannot satisfy the latter.

## Workflow use

Use the adjacent MNN v9 compiler qualifier first. On macOS, invoke this directory's
`rebuild_exact_runtime.py` with `--app-source`, `--ndk`, `--sdk-libs`,
`--compiler-identity`, and a fresh `--output` directory. Package only its verified
`runtime` directory and `NEW-BUILD-RECEIPT.json` in a new transfer directory, then
run `verify_ci_runtime_bundle.py bind` with that directory, the same source, the
compiler identity, and the actual source HEAD, workflow run ID, and attempt.

On Linux, run the same transfer script with `verify` and the same HEAD/run/attempt.
It independently verifies every original runtime byte, the new source-build
receipt, the actual compiler observation, and the closed four-member transfer
bundle before allowing assembly. An artifact from an earlier source, workflow,
or attempt is rejected. This establishes same-workflow reconstruction and transfer,
not phone functionality or Linux compilation of this worker.

The existing MNN compiler qualifier is reused by exact SHA; its accepted compiler
containers and signature-range comparison are unchanged. Native receipt fields
`full_multimodal_token_admission_proven` and `no_context_shift_proven` remain false.
No runtime build or phone qualification is claimed by the host identity tests.

Run the focused contracts with `HEPTA_PUBLIC_SOURCE` set to the frozen public
source and `python3 -B -m unittest discover -s validation/ui-venus-runtime-rebuild-v3
-p test_identity.py -v`. They verify source and receipt identities without starting
a compiler, downloading data, or contacting a phone.

The source identity, dependency paths/hashes and revision label are the only
rebuild-code changes from v2. All native source, model, SDK, compiler, ELF and
receipt qualification checks remain unchanged. The additional tests admit the
new complete source and reject its historical manifest and both earlier rebuild
helpers. These tests use explicitly synthetic receipt fixtures for rejection
contracts; they do not manufacture a fresh-build qualification.
