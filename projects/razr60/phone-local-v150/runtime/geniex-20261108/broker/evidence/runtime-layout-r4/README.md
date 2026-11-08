# Actual QAIRT runtime layout — R4 source candidate

The tested Android package keeps `libgeniex_core.so`, `libgeniex_vlm.so`, and `libgeniex-proc.so` under `R/lib/qairt`. The previous production validator incorrectly required the core and VLM directly in `R/lib`, preventing the tested package layout from being admitted. This candidate corrects that source-level deployment blocker without moving or duplicating any library.

## Production grammar contract

For either explicit R2 or R3 grammar profile, with `plugin_path=R/lib`:

- Core and VLM must be canonical `R/lib/qairt/libgeniex_core.so` and `R/lib/qairt/libgeniex_vlm.so` with the existing exact profile hashes.
- `LD_LIBRARY_PATH` must contain exactly, in order: `R/lib`, `R/lib/llama_cpp`, `R/lib/qairt`, `R/lib/qairt/htp-files`, `/system/lib64`, `/vendor/lib64`.
- `GENIEX_QAIRT_LIB` must be `R/lib/qairt/htp-files`; the counter library must be `R/lib/qairt/libgeniex-proc.so` with its original fixed hash.
- Before artifact checks, tokenizer counting or model execution, the exact native command rejects either core or VLM name in either of the first two loader directories. Regular files, other existing objects and symlinks, including dangling symlinks, cause exit 65.

The explicit Python-only nonproduction fixture policy retains the original flat layout. JSON configuration cannot select that policy. The no-grammar v1 branch is unchanged. Old R2 JSON missing the optional VLM fields still derives the original VLM path from the actual core directory and retains the original VLM hash. A previously accepted flattened production grammar configuration is now rejected; it was inconsistent with the tested runtime package.

Only `native_backend.py` and `tests/test_backend.py` changed. AST comparison confirms the only changed production methods are `BackendConfig.validate` and `NativeBackend._command`. Worker, counter, native supervisor, r9 parser, timeout handling, cancellation, UNKNOWN handling and token budgets are unchanged.

## Evidence and limits

The local 15-test contract suite passed. It includes production-layout admission/rejection, old v1 and R2 JSON parsing, the nonproduction flat fixture boundary and eight real shell negative subcases covering both core/VLM names in both earlier loader directories as regular files and dangling symlinks. Each executed the full generated production command with a test-only trace; exit 65 preceded every artifact-hash/counter/model command and left the private stage empty.

A new real r6 supervisor integration test covers the same eight negative subcases and independently validates original native waitpid and process-group-absent receipts plus subsequent inspection. It is present but has not executed for this revision. The full suite now contains 15 contract and 19 native integration tests. The cloud host's known AF_UNIX restriction and the current remote connector outage prevent claiming a full-suite result here.

The prior 31-test pass belongs to the prior source SHA. It does not qualify this R4 source. No phone operation, model inference, UI action, activation, existing p4 candidate mutation, or claim/ledger mutation occurred. Root will review this patch and build a new `geniex-native-grammar-layout-r4/source` candidate when remote execution is available; the existing R3 directory and its evidence remain unchanged.
