# Local control contract

Package `org.trillionnium.hepta.local` has its own app UID, model storage, engine and task session. Normal users enter a Chinese instruction and press Start. Stop cancels only the app-owned request; uncertain process exit blocks new work. Reopening the launcher reattaches to the existing session, never replays a task. Activity backgrounding lets the Accessibility service observe the foreground application.

The controller preserves the exact owner instruction. UI text is untrusted data. It asks the real local LFM3 model for a single strict action object, rejects unknown fields/invalid Unicode/unknown nodes, and permits at most two format/policy repairs per task. Rejected output executes zero actions. There are no task-specific command templates or mock model results.

Actions are `find_app`, `open`, `click`, `type`, `scroll`, `back`, `home`, `wait`, and `done`. `find_app` reads the task's installed launcher snapshot using a bounded `query` and `offset`; it dispatches no UI effect. Search results replace the next prompt's application projection, with a `next_offset` that accounts for budget truncation. Text-only model clicks require a node supplied in the current prompt. System dialogs may legitimately use package `android`; the parser accepts this precise exception. `open` still requires an exact supplied application package and a freshly verified launchable catalogue entry. Every other action, including `find_app`, must match the current observed package. The Accessibility service independently rechecks window identity, tree, node identity, enabled state and lock state before dispatch. Password nodes remain excluded. Requested app launch and actual foreground arrival are recorded separately.

A small set of visible noninteractive readouts accompanies actionable nodes so the model can see results before choosing `done`. Final status remains `model_reported_done` with `goal_independently_verified:false`. The external test driver must verify visible final predicates, matching task/nonce/owner, actual native process exit, runtime/model binding and positive accelerator offload evidence.

## Fixed runtime and optional private parameters

Only the fixed official GGUF filename under the application's own `files/model` is accepted. No model or executable path is accepted from an Intent. Default settings are NPU, 4096 context and four threads. An optional app-owned, regular, one-link mode0600 `files/model/runtime-config.json` can contain exactly:

```json
{"schema":"hepta.local-runtime.v1","compute":"npu","context_tokens":4096,"threads":4}
```

Only `compute=npu|gpu`, `context_tokens=4096|8192`, and `threads=1..8` are allowed. Configuration is read once for the application process. Changes apply on a deliberate subsequent process start after all work has finished. Unsupported settings fail explicitly; there is no automatic fallback. A selected/resolved device is distinct from independently demonstrated accelerator execution.

## One-use private debug task

`tools/create_debug_task.py` prepares a private request with schema `hepta.private-debug-task.v1`, a 64-hex nonce, exact instruction and an expiry of at most ten minutes. The file must be imported to this package's own `files/debug-task.json` as its UID, mode0600. A visible launcher Intent containing only `auto_task=true` and `test_nonce=<nonce>` can consume it once. Arbitrary launcher extras cannot authorize actions or pick a model/runtime executable.

The debug trigger, `files/control-session.json`, task-specific `files/control-tasks/<task-id>/`, and native `files/runs/<run-id>/` preserve binding, exact prompts/outputs, accepted/rejected actions, private screenshots and final receipts. These traces may contain private phone content and stay outside source control.

Native publication uses fsync(file), renameat2(RENAME_NOREPLACE), then fsync(directory), with no overwriting rename fallback. Native timeout, cancellation and cleanup receipts remain distinct from the outer process's observed exit.

## Revision 2 grammar and memory admission

Every control request carries a generated GBNF tied to its exact observation ID, current package, displayed launchable target packages and displayed enabled non-password nodes by capability. Grammar branches forbid node_id on open/back/home and require the fields appropriate to click/type/scroll/wait/done. Diagnostics use no grammar. The strict parser and fresh service checks remain independent execution gates; neither grammar nor repair rewrites model output. Native reads only grammar.gbnf in the same canonical private request directory as the prompt, with ordinary UID/mode/link checks and an input SHA receipt.

Revision 3 also permits a `find_app` branch bound to that same observation/package, requiring exactly `query` (0..64 Unicode scalar values, no NUL) and `offset` (canonical integer 0..4095), plus the optional common `reason`. The lookup searches only the installed launcher snapshot captured for this task. It cannot supply a new package, component, Intent, URL or executable. See `APP-DISCOVERY.md`.

The fixed /proc/meminfo MemAvailable and MemTotal fields are accepted only as bounded integer kB values with no duplicates, valid units, physical total bounds and available <= total. Missing/unavailable kernel fields use the validated ActivityManager estimate; malformed kernel fields fail closed. Android lowMemory=true always rejects. The 3 GiB threshold is unchanged. Both indicators and the actual admission source are recorded before and after inference. MemFree, swap and MemTotal never substitute for MemAvailable.
