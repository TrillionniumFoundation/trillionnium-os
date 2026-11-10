# Version 29 task-scoped model worker candidate

This candidate changes model lifetime within a controller task. The first
request still loads and verifies the selected model. Subsequent requests in the
same task retain the owned process and SDK model instance. Every request passes
its complete current prompt and resets model state before generation. The
candidate does not reuse a prior prompt's KV prefix or change the controller's
action policy. This integrated source inherits the complete closed model
registry and CLI consumers from version 28, including Bonsai 2 9B Q2_0 and
Orvena 4B Q4_K_M. The saved configuration and original default are preserved;
the warm runtime does not select a model or backend automatically.

Phone qualification is pending. Host tests with protocol peers or fake SDK
functions do not establish real GenieX model behavior, NPU/GPU execution,
latency, memory headroom, thermal behavior or phone task success. Actual Android
compilation and signed artifacts require separate receipts for these exact
source inputs. Existing version 27, version 28 and the earlier warm-only
version 29 host results remain historical evidence for their exact sources.

## Ownership and lifetime

`LocalModelEngine.beginWarmTask` reserves the existing process-wide model slot
for a random 32-hex generation and the controller's 32-hex task ID. Loading is
lazy: observation can fail or the user can cancel before a child is launched.
The normal diagnostic `LocalModelEngine.start` API retains its one-shot path.
No model worker persists across tasks and no failed worker is restarted.

The app and native worker serialize requests. The app owns the actual
`java.lang.Process`. Its dedicated reader consumes bounded ASCII control frames
from an inherited pipe. Before the SDK is bootstrapped, native code duplicates
the control descriptor and redirects plugin stdout into the generation's
stderr log. The model's generated text is published into private files and is
never interpreted as IPC.

The fixed initial argv selects model, compute backend, context and thread
count. Later IPC changes only the 32-hex request ID, consecutive sequence,
maximum token count and deadline. Native code derives private input/output
paths from the canonical initial runs root. It rejects foreign task or
generation IDs, repeated request IDs, nonconsecutive sequences, oversized
frames and requests outside the fixed bounds. A generation accepts at most 64
requests; the controller retains its existing 20-step and repair limits.

For the first request, native code performs the full pinned model SHA-256 read,
opens and retains its descriptor, loads the vocabulary, initializes GenieX and
creates the model. Later requests require the same held descriptor and named
file metadata and reuse that model. Each request independently reads and hashes
its prompt, system text and grammar, applies the chat template, checks the full
context budget and captures exact prompt/token evidence. `geniex_llm_reset`
must return zero before every generation. A reset failure retires the worker.
Per-request input IDs, template results and generated output are freed; model
and vocabulary destruction occur during task closure.

The first request retains the existing model-specific physical-headroom
admission. Later requests do not reserve the already loaded model weights a
second time; they still require a valid fresh physical-memory measurement and
Android `lowMemory=false`. The distinction is explicit in the app receipt.
It does not guarantee that a subsequent allocation succeeds or that Android
will keep the app alive under pressure.

## Request and terminal evidence

| Evidence | Schema | What it establishes |
| --- | --- | --- |
| Native request | `hepta.geniex-task-request.result.v1` | Complete output publication bound to task, generation, request, sequence, PID, input/output hashes, context and selected backend; actual cumulative hash/init/create/reset counts |
| App request | `hepta.local-model.task-request.v1` | Matching control reply, native contract and output bytes; durable create-only request receipt; request accepted while its task still owns the process |
| Native terminal | `hepta.geniex-task-session.result.v1` | Actual destroy/deinit return values, counts, close request and final metadata check; it cannot establish its own process exit |
| App terminal | `hepta.local-model.task-session.v1` | Actual owned `Process.waitFor` result, exit code, force-termination history, native terminal binding and whether physical cleanup is known |

Successful request receipts explicitly use `process_exit_observed=false` and
`exit_code=null`. Native request `worker_exit_status_planned` is null and the
request status is separate. The native terminal also leaves
`process_exit_observed=false`. Only the app's wait on its actual child can
produce an observed-exit result. A retained model instance is never treated as
an exited per-request process.

Per-request files remain under `files/runs/<request-id>/`. The generation's
shared logs, native terminal and app terminal reside under
`files/runs/<generation>/`. The controller's final `model_session` binds the
generation and exact app terminal receipt SHA-256. App request and terminal
receipts use exclusive new-file creation, descriptor fsync and parent-directory
fsync. Missing or failed receipt publication prevents a successful request or
terminal validation.

The offline collector accepts the new schema only with one complete generation,
all consecutive unique request IDs, consistent actual worker and app PIDs,
matching embedded native receipts, one init/create/hash, one reset per request,
actual terminal exit and successful destroy/deinit. It binds the shared
accelerator log to that same generation. Existing one-shot evidence still
requires an observed per-request exit. Independent UI goal predicates remain
required for a phone-test pass.

The suite's dispatched-action verifier independently rereads the collected
request and terminal files. A cached collector success is insufficient. Every
request must match the current task, expected app UID, parent/worker PIDs,
generation and consecutive request sequence. File lengths and SHA-256 values,
the native output and the step's exact raw model text must agree. The selected
action must be the same decoded decision. The full generation must have its
actual terminal exit and the task result must bind the exact terminal receipt.
A missing terminal, changed raw output, foreign generation or schema downgrade
cannot qualify an effect. This verification preserves the one-shot path and
does not treat a successful warm request as an exited process.

## Cancellation, deadlines and failures

User Stop cancels the task owner and active request. The app rejects cancelled,
retired, mismatched or late control frames. The controller retains its own
cancellation, deadline and observation-freshness checks before dispatch. Model
output cannot directly dispatch a phone action.

GenieX 0.10.0 does not provide an independent C cancellation API used here.
Cancellation signals the owned process; if it does not exit, the app escalates
to forced termination and waits for the actual result. A graceful CLOSE waits
two seconds before TERM; TERM has two seconds before KILL; KILL is followed by
an eight-second observed-exit wait. The app never concurrently resets or
destroys an SDK handle from another thread. Native code handles serial reset,
generation and destruction on its owner thread.

A cancelled request, native failure, invalid receipt, timeout or failed app
receipt publication retires the entire generation. The model slot is released
only after a durable terminal publication and actual child exit, or proven
non-start. Unknown cleanup preserves ownership and blocks new tasks. A forced
exit can establish physical cleanup without qualifying a successful native
terminal; the two facts remain distinct.

Engine closure schedules the same serialized task finisher before shutting
down its executor. Task closure and engine closure share one finisher. The
parent-death guard remains armed before SDK bootstrap and is cleanup protection,
not an observed-exit receipt.

## Required validation

`tools/run_host_checks.py` retains Java `--release 8 -Xlint:all -Werror` and C
`-std=c11 -Wall -Wextra -Werror`. The generated feature-test macro guards preserve
an already established glibc feature set and leave the pinned upstream worker
unchanged.

New Java lifecycle tests use real child processes with explicit synthetic
protocol peers: two requests share one living process, stale identities and
overlap are rejected, cancellation cannot accept a late frame, noncooperative
shutdown requires and records forced exit, deadlines retire the child, and a
process whose exit cannot be observed remains unknown.

The native lifecycle harness compiles the actual generated C worker and IPC
loop with explicit fake SDK/vocabulary functions. It checks one init/create/hash
and vocabulary load, reset before each complete prompt, distinct prompt/token
evidence, task close, model metadata change rejection, foreign generation and
duplicate request rejection, reset failure, and retained one-shot behavior.
It does not load a model or simulate an accelerator result for qualification.

Receipt tests exercise missing terminal evidence, invented per-step exit,
unknown final exit, late/uncommitted requests, stale generation/PID, duplicate
or missing sequences, incorrect reset/create counts, destroy failure, shared
log absence and corrupt output. The collector's original model, context,
grammar, offload and independent-UI checks remain in force.
File-backed suite tests pass explicit synthetic records through the real
collector and then the real action verifier; their counterexamples retain
cached positive flags so those flags cannot hide changed request or terminal
files. These fixtures are host evidence only.

Before installing this candidate, build and sign the exact frozen source and
record its complete identity. Subsequent phone qualification must verify real
create/reset counts and PID reuse in an ordinary app UID, compare first and
later request timing, confirm Stop and timeout leave no owned worker, and
repeat the offline phone-task suite. No such phone result is claimed by this
source candidate.
