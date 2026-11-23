# Exact runtime rebuild for frozen Code15

This version admits only the frozen Code15 source manifest
`aaae9cd4505dc4c3dbbb0d8f246b1193f284ed18b2be1263f40445df466575db`. It differs from the preserved
`../mobimind-runtime-rebuild-v2` helper only in that source binding, its revision
label, and the generic `app_source_modified: false` receipt field. The build
commands, public MNN revision, worker source, model/runtime pins, path mappings,
compiler identity recording, and full-file comparison gate are unchanged.

The earlier Code14 build and failed cross-host reproduction evidence remain in
`../mobimind-runtime-rebuild-v2`. Those reports are historical evidence; they
are not new Code15 CI results. A fresh current-HEAD workflow must rebuild the
runtime and pass its own complete size/SHA-256 comparison before assembly.

## Build and refusal behavior

Run `rebuild_exact_runtime.py --app-source APP --mnn-checkout MNN --ndk NDK
--output NEW_DIRECTORY` using the fixed public MNN checkout and actual NDK
28.1.13356709/r28b. The workflow runs this on macOS. Source/build path spelling
is normalized with the existing compiler prefix-map flags; compiler producer
strings and binary contents are not edited afterward. The actual compiler
container identity and build host remain in the new receipt.

All three runtime outputs must match the original complete files. A mismatch
returns exit 3 and does not publish the runtime directory for the original
assembler. No old-binary fallback or pin rewrite exists. The original receipt
is copied unchanged only after the new build passes; the separate new receipt
records the actual reconstruction.

Linux independently revalidates the current workflow's macOS-built payloads and
assembles the APK. This does not describe an identical Linux compilation. The
companion `../mobimind-ci-host-split-v3` binds exact HEAD, run, attempt, this helper,
source manifest, compiler observation and new receipt.

Helper SHA-256: `403ffdda09572c28a7d6621eeb8b5b06e0b39b75581fcc3a82e24a873b725579`.
