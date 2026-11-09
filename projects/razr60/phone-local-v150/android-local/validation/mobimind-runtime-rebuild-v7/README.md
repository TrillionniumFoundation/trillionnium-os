# Exact runtime rebuild for frozen Code19

This helper admits only the frozen Code19 source manifest
`9817f2af3937a402b52176565233c763869495d203080deffd7e279f9f621b69`. It differs from the preserved
`../mobimind-runtime-rebuild-v6` helper only in its exact source binding,
revision label, and rejection message. The build commands, public MNN revision,
worker source, model/runtime pins, path mappings, compiler identity recording,
and complete file comparison gate are unchanged.

The Code18 helpers and their historical evidence remain in the v6 directories.
A fresh workflow for the current commit must rebuild the runtime and pass its
own complete size and SHA-256 comparison before assembly. Local source-binding
checks do not substitute for that rebuild or for phone acceptance.

## Build and refusal behavior

Run `rebuild_exact_runtime.py --app-source APP --mnn-checkout MNN --ndk NDK
--output NEW_DIRECTORY` with the fixed public MNN checkout and actual NDK
28.1.13356709/r28b on macOS. Existing compiler prefix-map flags normalize build
paths. Compiler producer strings, signatures, ELF sections, and binary contents
are not edited afterward. The actual compiler identity and host remain in the
new receipt.

All three complete runtime files must match the original pins. A mismatch
returns exit 3 and does not publish a runtime directory for the original
assembler. The unchanged original receipt is copied only after the new build
passes; the separate new receipt records the actual reconstruction.

The companion `../mobimind-ci-host-split-v7` binds the exact commit, workflow run,
attempt, helper, source manifest, compiler observation, and new receipt. Linux
independently revalidates that same workflow's macOS-built files before
assembly. This does not claim identical compilation on Linux.

Helper SHA-256: `b585c1654ce91888bc4906b32fbe8ac1ace22987f445d1af25994d084f19dc78`.
