# 2026-08-27 owner-open duplex JSONL provider runtime source record

Evidence level: **L1 source-authored, validation pending**  
Branch: `codex/owner-open-r4-foundation-20260827`  
Implementation: `tools/owner-open/jsonl_provider_runtime.py`

## Scope

This record covers provider-neutral process and JSONL mechanics for r4 W1.2.
The runtime starts an exact argv without a shell, creates a new process session,
handles bounded nonblocking stdin/stdout/stderr, parses strict JSON object
records, lets a caller return exact response bytes, and reports one terminal
observation.

It does not know what a provider event means. It does not select or execute a
tool, open credentials, contact an endpoint, invoke Codex, normalize events into
the Rust Host protocol or claim a same-turn effect.

## Source set

| Path | Purpose |
| --- | --- |
| `tools/owner-open/jsonl_provider_runtime.py` | Provider process, strict JSONL, duplex response and lifecycle mechanics |
| `tools/tests/test_jsonl_provider_runtime.py` | Fake provider success/failure/fault integration matrix |
| `tools/tests/test_000_owner_open_import_bootstrap.py` | Deterministic postponed-annotation lookup under unittest discovery |
| `docs/status/owner-open-r4-w1-jsonl-runtime-status.json` | Machine claim ceiling and remaining holds |
| `docs/implementation/owner-open-codex-provider-v1.md` | W1.0–W1.4 sequencing |

## Intended source facts

1. `shell=False` and exact argv preserve process argument boundaries.
2. `start_new_session=True` supplies a process-group lifecycle boundary.
3. stdout, stderr and stdin are nonblocking OS pipes.
4. stdout is split only at newline boundaries and line/aggregate sizes are
   independently bounded.
5. recursive duplicate JSON members are rejected before event handling.
6. every record must be one UTF-8 JSON object; unknown fields/events are kept.
7. the event handler can return exact byte/string responses without the runtime
   interpreting their semantics.
8. initial stdin, handler response, aggregate outbound, stdout, stderr and event
   count have separate mechanical ceilings.
9. timeout and cancellation signal the complete provider process group and reap
   the process.
10. provider exit code, signal, bounded raw stderr, byte/event counts and a
    mechanical/protocol error are retained in one terminal value.

## Authored duplex fixture

The primary fake provider test:

1. receives one exact prompt argv;
2. emits a start event;
3. emits a shell tool call in two stdout writes;
4. waits for a successful tool-result JSON line;
5. continues and emits another event;
6. emits a deliberate failing shell call;
7. waits for a result with exit code 7;
8. continues after the failure;
9. emits one final event and exits normally.

The runtime does not generate the results; the test's caller handler supplies
them. This proves only that the duplex process mechanics can carry a future Host
bridge without assuming tool semantics.

## Authored fault matrix

- unknown future event with nested extensions;
- duplicate member, including nested duplicate;
- malformed, truncated and non-object records;
- non-zero provider exit with stderr;
- timeout with a forked descendant;
- event-driven cancellation;
- handler and sink exceptions;
- JSONL line, stdout, stderr and handler-response exhaustion;
- exact argv and binary initial stdin;
- empty/NUL/oversized request rejected before spawn.

## Required validation

```sh
python3 -m py_compile \
  tools/owner-open/jsonl_provider_runtime.py \
  tools/tests/test_000_owner_open_import_bootstrap.py \
  tools/tests/test_jsonl_provider_runtime.py
python3 -m unittest discover -s tools/tests -p 'test_*.py' -v
```

A later host integration test must replace the test handler with the actual
Rust Host call registry and owner-open process runtime. The Python fixture is
not product effect evidence.

## Current hold

No real runner output is captured. No Codex binary, probe report, launch prefix,
credentials, model, endpoint, Rust Host, Root Linux or Android target is bound to
this record. Compatibility with an installed Codex JSON event dialect remains
unproven.

## Accurate statement

> A bounded provider-neutral duplex JSONL process runtime and fake provider
> lifecycle/fault tests have been authored. They show the intended mechanical
> carrier for W1.2, not a live or integrated Codex turn.
