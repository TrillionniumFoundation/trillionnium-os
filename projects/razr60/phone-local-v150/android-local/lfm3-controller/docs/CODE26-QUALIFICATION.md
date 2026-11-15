# Code26 qualification boundary

## Problem and resulting behavior

Local phone-control trials showed that a planner can repeat already-entered input or report arrival at a parent page while the current observation still shows a child page. The current observation and allowed targets were present, but the model had to reconstruct the previous field and navigation transition from an action-only trace.

Code26 presents the complete recorded events first and the current screen last, with explicit top-level JSON line boundaries. `last_transition` carries two real observations for the most recent recorded step: each source observation ID and package, editable field text and view IDs, node-truncation status, observed window title and its truncation flag, and observed or unknown IME visibility. Empty text stays empty; unknown title and IME state stay null. Password and foreign-package fields are excluded. No fields are matched across views, no page role is inferred, and no action authority or completion decision is added. The original event row remains the source for acceptance, dispatch and stale status. An after-observation that does not match the current screen is rejected.

The owner instruction, complete event history, eligible target domain, grammar, execution freshness checks, no-effect protection, model and task deadlines, recovery ownership and independent task goals are retained. The formatted input is different and requires new native token-budget and device task evidence. Host checks cannot establish improved model decisions.

## Additional exact model candidate

The closed Java, native and host registries additionally admit `qwen3.5-9b-q4_0`:

- Repository: `unsloth/Qwen3.5-9B-GGUF`
- Revision: `3885219b6810b007914f3a7950a8d1b469d598a5`
- File: `Qwen3.5-9B-Q4_0.gguf`
- Bytes: `5379417312`
- SHA256: `17670346b4260ddcb0173965145155885024f3c9a4a24389a3370751edbcde24`
- Architecture: existing `qwen35`; exact same-input token admission is mandatory.
- Available-memory admission threshold: 8 GiB, qualification headroom rather than measured peak memory.

The source is the [pinned artifact](https://huggingface.co/unsloth/Qwen3.5-9B-GGUF/blob/3885219b6810b007914f3a7950a8d1b469d598a5/Qwen3.5-9B-Q4_0.gguf). Its size exceeds unsigned 32-bit capacity; the existing 64-bit whole-file identity contract is preserved. Same-architecture 4B and 9B token-budget receipts are not interchangeable. No projector, vision dispatch, thinking protocol, CPU mode or network permission is added. The GenieX and llama.cpp runtime pins are unchanged. Neither successful loading nor quality on this device is implied by registry admission.

## Required evidence

Run the full host contract suite and compile/sign the exact source before installation. Verify installed APK identity, unchanged private configuration and clean lifecycle state. Qualify any selected model with actual local inference and independently observed phone goals; keep old failures and fixed-input screening separate from new complete task results. Offline operation, ordinary UI Start/background execution, Stop and restart each require their own actual evidence. There is no automatic model selection, retry or replay based on a host test pass.
