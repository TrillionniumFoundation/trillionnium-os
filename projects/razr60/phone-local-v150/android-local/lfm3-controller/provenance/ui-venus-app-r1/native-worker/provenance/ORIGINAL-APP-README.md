# UI-Venus ordinary-App native entry draft

This is a new, uncompiled native candidate for a single, local UI-Venus visual-model request. It is not merged into Code15 or Code16. It has no action dispatcher, network client, server, model downloader, ADB command, APK installer, or fallback to shell execution. The existing shell worker and its qualification records remain unchanged.

## Exact change

The baseline is `hepta-ui-venus-vlm-prepared-draft-r2`. Seventeen of its eighteen native files remain byte-for-byte identical, including the entire VLM implementation, official mobile prompt, model and projector pins, GGUF/template checks, all SDK calls, sampler, deadline, input hashes, output format, parent-death implementation and native publication code. Only `native/probe-worker.c` changes. Its new helper is `native/app-entry-guard.h`.

The proposed installed filename is `libhepta_ui_venus_runner.so`. It must be a separately pinned APK native-library member. The old shell ELF SHA must not be used for it. An actual new ELF size/SHA will exist only after review and an Android NDK build.

The existing same-directory bootstrap still requires the executable and `libgeniex_plugin_llama_cpp.so` to be in the canonical `HEPTA_LOCAL_NATIVE_LIB_DIR`. The twelve pinned GenieX libraries are unchanged. Java must verify their whole-file pins before launch; the native bootstrap does not pretend to hash every loaded library. Actual backend maps remain an external qualification requirement.

## Leading argument contract

These options must precede the original VLM options, in this exact order:

```
libhepta_ui_venus_runner.so
  --expected-parent-pid <Process.myPid()>
  --expected-app-uid <Process.myUid()>
  --app-files-dir <getFilesDir().getCanonicalPath()>
```

The unchanged parent guard consumes the first pair. The new entry guard consumes the next two pairs and leaves the original VLM argument sequence intact. Duplicate wrapper flags, an unexpected order, a noncanonical files directory, shell UID, a UID below 10000, a mismatching real/effective UID, and an unexpected direct parent are refusals. No device serial or numeric phone UID is embedded in this source.

The expected parent must be the direct `org.trillionnium.hepta.local` App process. Before bootstrap and after the VLM core returns, native code checks PPID, the parent's unique `Pid:` field, all four `Uid:` values, and its actual `/proc/<pid>/cmdline`. Only the exact package name followed entirely by one or more NUL bytes is accepted. This handles observed Android argument-storage padding without accepting an additional argument, `:process` suffix or shell parent. The already implemented `PR_SET_PDEATHSIG=SIGKILL` guard remains active. A denied or unreadable proc field is a refusal; there is no alternate identity source or SELinux modification.

UID and direct-parent checks are not a SELinux-domain proof. The receipt explicitly says so. A separate live observation must still establish the ordinary-App domain, exact executable, full argv, PID/startticks and loaded library maps. Java independently binds its own UID, PID, canonical `getFilesDir()` and the owned `Process` to these results.

## Private paths and original VLM options

Let `F` be the canonical App files directory and `R` be a fresh lowercase 32-hex request ID. All four directories `F`, `F/ui-venus-model`, `F/ui-venus-runs` and `F/ui-venus-runs/R` must already exist, be canonical, owned by the current App UID, and have mode 0700. Native does not create or chmod these directories.

```
--request-id R
--mode vlm
--runtime llama_cpp
--compute npu
--vit-device GPUOpenCL
--model F/ui-venus-model/UI-Venus-2-9B-Q4_K_M.gguf
--mmproj F/ui-venus-model/mmproj-UI-Venus-2-9B-f16.gguf
--prompt-file F/ui-venus-runs/R/prompt.txt
--system-file F/ui-venus-runs/R/system.txt
--image F/ui-venus-runs/R/screen.png
--result-file F/ui-venus-runs/R/native-result.json
--text-file F/ui-venus-runs/R/raw.txt
--ctx-size 8192
--max-tokens 1024
--threads 4
--timeout-ms 300000
--log-level debug
```

The original core also permits an explicitly selected GPU language backend; the first Java candidate selects NPU language and OpenCL vision. No implicit CPU retry is added.

Input files remain canonical, regular, owned, mode 0600 and single-link. The core retains its complete, held-FD model and projector hashes, exact size checks, input hashes and post-run metadata binding. The wrapper additionally requires the exact private layout above. Core result, raw output and the new binding receipt must initially be absent. Existing sidecar publication rules are unchanged.

The directory postcheck binds canonical paths, device/inode, owner/group and mode. It does not compare directory mtime, size or link count: this request itself publishes outputs and Java maintains its journal. Input/model file postchecks retain the original stronger metadata comparisons.

## Timing and cancellation

`--timeout-ms` remains exactly 300000. No remaining-budget substitution is accepted. The core starts its monotonic timer after its argument/path checks and before input reads and complete model hashing. Wrapper identity checks and the existing plugin bootstrap precede that point. Java preflight has its own bounded timing evidence.

To preserve the full native budget, the coordinating Java draft uses a 325000-ms launch watchdog, followed by its existing TERM, 2-second force-stop escalation and 12-second exit-confirmation boundary. Those are supervisor limits, not a claim that an uninterruptible SDK phase must exit on its own at 300000 ms. Actual owned-process exit and durable terminal publication remain mandatory before releasing the shared model slot. The native wrapper does not alter signal handlers, generation fences or the core's destroy/deinit path.

## Separate App binding receipt

The original `native-result.json` schema remains `hepta.ui-venus-vlm-once.result.v1`. Its conservative `production_receipt`, `process_exit_observed` and ordinary-App qualification flags are unchanged. It cannot observe its own eventual process exit.

After a normal return from the core, the wrapper publishes `app-process-binding.json` with schema `hepta.ui-venus.app-process-binding.v1`, using the existing no-overwrite, file-fsync, renameat2-NOREPLACE and directory-fsync path. The exact fields are in `APP-PROCESS-BINDING.json`. It binds the App UID/parent, canonical private directories, request ID, core return code and before/after identity checks. It does not claim actual exit, SELinux proof, loaded-library proof, GUI correctness, complete multimodal token accounting, or permission to execute a model action.

For success, Java must require actual child exit 0, both return-code fields 0, all before/after scope and parent checks true, the unchanged core's complete successful inference contract, exact input/model/runtime/sidecar hashes, and its own request/nonce/UID/PID/paths. The parent status hashes can differ between checks because proc status is live; each must still be a valid full SHA. Parent cmdline hashes can be independently recomputed from the exact package bytes and the recorded all-NUL padding length.

Early argument, parent or private-path failures may return without a native receipt. They are failures, and Java still records the observed owned exit and cleanup state. A post-core identity failure forces wrapper status 78. Binding publication failure forces status 74; a pre-existing completed core receipt cannot override that observed wrapper exit.

## Preserved model-only limits

The request is an explicit first-frame, empty-history evaluation using the complete original PNG and unchanged OWNER. The exact official mobile SYSTEM is rendered by the independent Java input contract. Raw GUI action text is recorded, never executed. Text-only diagnostic IDs are not the complete multimodal input; this change adds no claim that all image tokens were counted or no context shift occurred. These limits stay visible in the unchanged native result.

## Validation state

The source-only byte comparison is reproducible with `python3 verify_source_boundary.py`. It does not compile or execute a native binary, load a model, or contact a phone. After review, the exact C entry functions passed 36 host assertions with `-std=c11 -Wall -Wextra -Werror`; see `tests/HOST-CHECKS.json`. Android NDK compilation and ordinary-App execution remain pending at this source checkpoint. A successful host compile does not establish device backend or GUI-task qualification.
