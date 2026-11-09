# Exact runtime rebuild for the public Code20 click-policy derivative

This v9 helper admits only application manifest `1e5041491e3d2b9472b66db28d1cf2c602b45df8c3d0e8c9ee717e91cfd881ca`.
The preserved v8 helper admits the earlier public Code20 source. This helper
changes only the application source identity, revision label and rejection text.
The public MNN revision, worker source, model/runtime/SDK pins, build options,
debug path mappings, compiler qualification and complete ELF comparison gates
remain unchanged.

The four Java compile inputs changed. Historical builds and the earlier phone
results do not qualify this derivative. A fresh workflow for its exact commit
must perform the actual rebuild, compare every original runtime byte and bind
the new build receipt to its own run and attempt before assembly. Source
identity tests alone are not a runtime build or phone acceptance.


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

The companion `../mobimind-ci-host-split-v9` binds the exact commit, workflow run,
attempt, helper, source manifest, compiler observation, and new receipt. Linux
independently revalidates that same workflow's macOS-built files before
assembly. This does not claim identical compilation on Linux.

Helper SHA-256: `592f4c5ce13a1233c3259924cbb197c89d16a02c481010a4fe8685c9733df198`.
