# Exact runtime rebuild for the Code19 deadline037c candidate

This independent helper admits only app source manifest
`fdab3c67d726aa44c19c9efe4d65cc845ee433dbabe2d97f7fe7fb07b92bcec7`.
The app patch was introduced at commit
`a08f23614f48581f4bb23238e0c5bf2430b7d411` on frozen Code19 base
`fdb7eca8d3a434c515da547365fcc47bb2f510d3` (base app manifest
`9817f2af3937a402b52176565233c763869495d203080deffd7e279f9f621b69`).
The app change binds action cancellation to the original task deadline, retires
completed waits, accepts the first callback, and checks activity after preserving
the received action receipt. Its independent host regression files are also in
the candidate app manifest. This helper does not change app source during a build.

The preserved `../mobimind-runtime-rebuild-v7` remains byte-for-byte unchanged.
The rebuild implementation differs from v7 only in the exact app manifest hash,
revision label, and rejection message. No extra source hash or wildcard is
admitted. Complete source membership, file size, hash, and symlink checks remain.

All build commands, MNN commit, worker source, runtime pins, compiler identity
checks, original receipt, ELF checks, debug path maps, and full-file comparison
gates are unchanged. Run `rebuild_exact_runtime.py --app-source APP
--mnn-checkout MNN --ndk NDK --output NEW_DIRECTORY` with the fixed public MNN
checkout and actual NDK 28.1.13356709/r28b on macOS. The tool does not download,
assemble an APK, contact a phone, or rewrite a binary or pin.

All three complete runtime files must match the original pins. A mismatch
returns exit 3 and does not publish the runtime directory for the original
assembler. The unchanged original receipt is copied only after a successful
comparison; the separate new receipt records the actual build and helper hash.

`../mobimind-ci-host-split-v8-deadline037c` binds the actual checked-out source
HEAD, workflow run, attempt, helper, app manifest, compiler observation, and new
receipt. Linux independently verifies the same workflow's macOS-built bytes.
The run's actual source HEAD remains a required transfer input; it is not
substituted with the historical app-patch commit above.

Helper SHA-256: `5f2a6a8f8ebd729abf4dd5d75d89af80feaa87180f9b3ea6ff32358d7a07c5c3`.

The companion `test_deadline_source_binding.py` runs before the macOS build in
CI. Its source qualification and refusal tests do not establish successful native
compilation, Android packaging, installed APK identity, or phone task completion.
The first deadline candidate run (`42582322495`, job `129043773124`) passed app
source closure and compiler qualification but the v7 helper rejected its different
app manifest before any native or Android compilation. This derived helper
removes only that known admission mismatch. A fresh CI run is still required.
