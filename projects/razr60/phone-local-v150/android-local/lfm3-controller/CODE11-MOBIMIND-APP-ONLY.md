# Code11: ordinary-App visual model qualification

Version 11 / `0.11.0-local-vision-probe` preserves the complete code10 text
controller, label-first grammar and dispatch checks. It adds one private,
one-use, model-only MobiMind endpoint. Its raw visual response cannot execute
phone tools. The visual action planner under separate development is absent.

The six new App classes and three integration changes come from the exact
frozen overlay under `provenance/mobimind-app-only-r1`. The integration manifest
binds its base to code10 source manifest
`519b46dba5078e591bc1c9ef1a0e20c92bef2a68e023108c6c7c582bea774394`.
Its README describes the nonce, private fixture, shared inference lease,
Application lifetime, recovery latch, deadline, visible cancellation, native
receipt and explicit limits. No Android permission is added.

## Separate native provenance

`native/mobimind-runtime-pins.json` fixes the already-built r4 worker,
`libMNN.so` and `libc++_shared.so`. These are three separate build artifacts;
they are not claimed to belong to the GenieX release archive. The worker is
renamed only as an APK member to `libhepta_mobimind_runner.so`; its bytes stay
unchanged. MNN and C++ library bytes remain from the previous genuine Android
build. This candidate genuinely recompiles its Java/DEX, Android resources and
existing GenieX worker; it does not claim to recompile MNN mathematics again.

The exact r4 worker sources and original build receipt are preserved under
`provenance/mobimind-worker-r4` and
`provenance/mobimind-worker-r4-build.json`. MNN's upstream revision is
`bce7456ce60b5e51b4d3b357f303515860353d8c`. Full source membership verification
includes these provenance inputs.

Assembly requires both `GENIEX_ANDROID_LIB_DIR` / `GENIEX_ANDROID_ARCHIVE`
and `MOBIMIND_ANDROID_RUNTIME_DIR`. It checks the source-bound Java hashes
against packaging hashes, the original build receipt, all three complete
payload hashes and sizes, their exact ELF `NEEDED` lists, the total APK library
closure, and the unchanged worker's Android PIE interpreter. Any overlap with
an existing GenieX member is rejected. After signing, every actual packaged
library is hashed again. Static acceptance distinguishes the two provenance
groups instead of treating a missing archive proof as success.

## Private qualification request

The retained, host-only staging tool is:

```
python3 provenance/mobimind-app-only-r1/tools/prepare_private_request.py \
  --fixture-dir /private/fixed-official-fixture \
  --image-file /private/original-screen.png \
  --output-dir /private/new-request-staging \
  --deadline-ms 120000 --max-tokens 256
```

It has no device or process access. It pins the original owner/history,
official prompt, screenshot and request; install its one-use request last,
after a complete model import. Its ten-minute expiry must not be used to
justify replaying an old request. The ordinary App's private endpoint is
`auto_mobi_probe` with the exact `mobi_nonce` from the staged request.

An ordinary-App pass requires the real application UID and parent, installed
native library path and hashes, all eleven complete model-file hashes, exact
prompt/image/input-ID binding, observed OpenCL runtime and operation evidence,
EOS, owned exit and durable known cleanup. CPU helper operations stay visible.
Neither host compilation, static APK acceptance nor a shell-UID model run is
an ordinary-App pass. Background operation, visible cancellation, safe idle
restart, offline execution and phone task completion remain separate device
acceptance requirements. No functional qualification is claimed by this source
freeze or build.
