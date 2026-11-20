# Bounded initial webpage readiness

This amendment follows the timing-only source at `5ad80a9`. Phone traces from
that source showed an uncommitted blank page reaching a model request, a complete
native comparison rejecting a changed protected node before any retry could run,
and an initial flight document changing before its first usable observation.
These are failure observations; they do not establish a price or a flight result.

The initial `no_main_frame_commit` state now waits for a real capture before
publishing a model domain. The wait has one fixed deadline, capped by the original
task deadline, a maximum of 64 pending reads and a 500 ms spacing. Both native
snapshot handoffs and capture RPCs receive the same pending deadline. A late
captured or state-changed response is rejected even if the client returns it.
The bound task, webview instance, display and window cannot change during the wait.

A complete comparison's protected-node inequality has a dedicated exception type.
It rejects the old frame and can enter the existing bounded read-only content
retry. Identity, storage, cancellation, worker-lifecycle and other integrity errors
retain their prior handling. The same initial document path applies to supported
shopping and flight goals; unknown goals gain no retry. Existing 32-second content
budget, maximum two extra content reads, URL/epoch/instance binding, worker drain,
fresh native comparison and all action authorization checks remain in force.
Neither an action nor a model call is replayed by these waits.

Known loading, page-change and observation-timeout messages are translated only
when ordinary UI text is rendered. Raw controller state, evidence and advanced
diagnostic logs retain their original technical strings.

`run_host.py` compiles the exact current and original observation/retry methods.
The original methods fail three explicit behavioral counterfactuals; the current
methods pass bounded-wait, identity, cancellation, persistence and late-response
cases. IPC, clock, native authority and calendar-pending detectors are explicit
host fixtures. Repeated future frames are synthetic. These tests do not establish
real Android IPC, native authority, a successful website task or model quality.
The existing real-DOM, calendar, native worker and complete host gates remain
separate prerequisites. `HOST-VALIDATION.json` contains sanitized input hashes and
receipts; no private page body, task instruction, screenshot or signing material.

Run with an existing Java 17 JDK and the pinned `org.json` 20240303 dependency:

```sh
python3 -B tests/web-readiness/run_host.py --output /tmp/hepta-readiness-new \
  --java-home "$HEPTA_JAVA_HOME" --json-jar "$HEPTA_JSON_JAR"
```

The source also includes a separate native first-token metadata checkpoint.
It emits one fixed-format stderr line after the first nonempty token callback of
each warm request, with task/generation/request/process/monotonic identity and no
generated text. It does not change SDK callbacks, cancellation, deadlines or
success receipts. Its host tests use the actual generated callback with an
explicit fake SDK. A phone Stop-during-decode pass still requires a live matching
checkpoint and the normal cleanup evidence from the actual phone request.
