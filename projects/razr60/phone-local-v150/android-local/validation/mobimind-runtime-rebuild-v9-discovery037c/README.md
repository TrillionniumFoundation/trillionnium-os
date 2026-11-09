This helper admits the isolated discovery-provenance source only; compiler, runtime, ELF, producer/consumer and publication checks retain their frozen behavior.

# Exact runtime rebuild for the Code19 discovery037c candidate

This independent helper admits only app source manifest
`eb85ee802f2718233553281529cc7c8cc166b6a37c0c09a3a3c58b75b0e4a26e`.
The discovery-provenance source derives from reviewed deadline commit
`d023ddbf0061b7e39963f98b67e74bc04fc0b46b`, app manifest
`fdab3c67d726aa44c19c9efe4d65cc845ee433dbabe2d97f7fe7fb07b92bcec7`.
Its Java change preserves one completed read-only app-search provenance fact
through prompt-history trimming. The original task deadline/cancellation fix
remains included. No model, compiler, native or runtime pin is changed.
The companion `test_discovery_source_binding.py` checks the exact source and
unchanged runtime qualification before a fresh CI build. Passing these local
contracts does not establish native compilation, Android execution or task success.
The v7 and v8 helpers remain immutable historical candidates; this new helper
admits only the new exact source without removing their original gates.

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

`../mobimind-ci-host-split-v9-discovery037c` binds the actual checked-out source
HEAD, workflow run, attempt, helper, app manifest, compiler observation, and new
receipt. Linux independently verifies the same workflow's macOS-built bytes.
The run's actual source HEAD remains a required transfer input; it is not
substituted with the historical app-patch commit above.

Helper SHA-256: `c6a6af2b0f6995a57e202d7b39263285890f70641de5b77cad635afab909566e`.

The companion `test_discovery_source_binding.py` runs before the macOS build in
CI. Its source qualification and refusal tests do not establish successful native
compilation, Android packaging, installed APK identity, or phone task completion.
The first deadline candidate run (`42582322495`, job `129043773124`) passed app
source closure and compiler qualification but the v7 helper rejected its different
app manifest before any native or Android compilation. This derived helper
removes only that known admission mismatch. A fresh CI run is still required.
