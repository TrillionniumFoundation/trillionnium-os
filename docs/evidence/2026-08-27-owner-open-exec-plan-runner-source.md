# 2026-08-27 owner-open validated provider exec-plan runner source record

Evidence level: **L1 source-authored, validation pending**  
Branch: `codex/owner-open-r4-foundation-20260827`  
Implementation: `tools/owner-open/execute_codex_exec_plan.py`

## Scope

This record binds the three prior W1 source layers:

1. executable-bound CLI help observation;
2. unexecuted owner-open `exec --json` prefix plan;
3. provider-neutral bounded duplex JSONL process mechanics.

The executor revalidates and then may run the planned process only when the
operator supplies explicit `--execute`, prompt transport, provider kind and
environment mode.

## Source set

| Path | Purpose |
| --- | --- |
| `tools/owner-open/execute_codex_exec_plan.py` | Plan/executable/prompt validation and process execution |
| `tools/tests/test_execute_codex_exec_plan.py` | Library and black-box execution boundary tests |
| `schemas/owner-open-codex-exec-prefix-v1.schema.json` | Closed generated-plan shape |
| `docs/status/owner-open-r4-w1-exec-plan-runner-status.json` | Machine claim ceiling |

## Validation chain

Before spawn the executor requires:

- a private single-link regular plan file;
- recursive duplicate-member rejection;
- exact plan schema;
- exact canonical SHA-256 over the plan without its digest;
- all generated-only claims in their false state;
- the unselected prompt-delivery boundary;
- an exact absolute `argv[0]` matching the plan's executable path;
- a fresh executable measurement matching the planned SHA-256;
- a private bounded UTF-8 prompt file;
- explicit `argv-final`, `stdin-close` or `stdin-keep` transport;
- explicit `fixture` or `codex` provider-kind label;
- explicit inherited or empty environment selection.

No fallback executable, option, prompt mode or environment mode is inferred.

## Event record boundary

Every provider JSONL record is captured with:

- source plan/config generation;
- monotonic sequence and elapsed time;
- exact raw-line SHA-256 and base64;
- parsed provider object;
- `normalized_host_event = null`;
- `same_turn_tool_effect_proven = false`.

The source runner does not interpret or normalize Codex event semantics. That is
an explicit Rust Host integration gate.

## Terminal record boundary

The terminal evidence retains:

- plan/probe/executable/config identities;
- selected access-policy label;
- provider-kind and prompt/environment modes;
- prompt digest/size, never prompt content;
- process terminal kind, exit code, signal, counts and bounded raw stderr;
- execution success as a process fact;
- all provider-contact/model/compatibility/Host/tool/device/release claims false.

A `provider_kind=codex` label records the requested executable class only. It
cannot prove that an endpoint was contacted or a model was invoked.

## Authored tests

- validated fixture plan preserves exact prefix and prompt argument;
- one fixture tool call receives a caller-supplied result and reaches final;
- missing `--execute` leaves the invocation log and evidence files empty;
- CLI evidence files are mode 0600;
- plan preimage/claims/executable drift and argv[0] substitution fail before
  spawn;
- argv prompt rejects NUL while stdin preserves exact NUL bytes;
- plan and prompt symlinks/non-private modes are rejected.

## Required validation

```sh
python3 -m py_compile \
  tools/owner-open/probe_codex_cli.py \
  tools/owner-open/build_codex_exec_prefix.py \
  tools/owner-open/jsonl_provider_runtime.py \
  tools/owner-open/execute_codex_exec_plan.py \
  tools/tests/test_probe_codex_cli.py \
  tools/tests/test_build_codex_exec_prefix.py \
  tools/tests/test_jsonl_provider_runtime.py \
  tools/tests/test_execute_codex_exec_plan.py
python3 -m unittest discover -s tools/tests -p 'test_*.py' -v
```

## Current hold

No real runner output is attached. The source pipeline has not consumed an
installed Codex probe report and has not executed a real provider. There is no
Rust Host call registry, owner-open shell/ADB handler, Root Linux placement,
Android image, physical effect or failure/recovery evidence.

## Accurate statement

> The source now contains an executable-bound, explicitly authorized pipeline
> from help observation through an unexecuted plan to a bounded fixture provider
> process. It is still source/fixture infrastructure, not a live Codex or
> same-turn product capability.
