# Owner-Open Provider JSONL

Current module: `MOD-PROVIDER`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns provider process lifecycle, bounded strict JSONL framing and same-turn tool callback transport. Codex/provider remains the only semantic principal; this adapter adds no fallback, approval or retry policy.

Installed Codex and event-driven cancellation work remain tracked in the G1 gap register. Current state is generated under `docs/generated/`.

The public `max_line_bytes` setting now bounds inbound stdout JSONL frames;
its default is 1 MiB, with an output channel of two lines and a 512 KiB stderr
prefix. The old 32 MiB /64-line default could reserve 2 GiB. Config validation
before spawn now checks a 16 MiB aggregate raw reservation covering Vec growth,
queued/reader/blocked/current lines, channel metadata and stderr/text copies.
Owned configuration is capped at 4 MiB; config/Command/inherited-env staging
reserves 12 MiB. Inherited values are limited to 64 KiB each /1 MiB total.

Before DOM allocation, quote/escape-aware token counting rejects dense JSON
above a 2 MiB logical decode reservation; actual owned capacities are checked
again after decode. Canonical decode staging has a separate 16 MiB envelope for eight bounded
representations, including JCS byte/index buffers. Consuming the incoming call
releases envelope/normalization copies before JCS; normalized owned and encoded
requests are checked before dispatch.
The byte limit alone does not grant admission to a dense array/object.

Outbound tool results use an independent 32 MiB line ceiling. Default 16 MiB
runtime output still fits: result events/base64 serialize from borrowed bytes,
without a whole result Value/string/framed Vec, through one fixed 64 KiB writer.
The line is counted before writing, and all flushes share one finite deadline.
Inbound DOM/raw values are released before tool invocation.

If a nondefault runtime observation history exceeds the outbound ceiling, the
result retains `status: terminal`, generation, full terminal, observation hash
and registry identity, with `events: []`, `events_truncated: true` and an
`observation_gap` containing the tool event domain/call ID, sequence bounds,
event count and omitted output byte count. This is observation loss; it does
not rewrite the runtime `output_truncated` field, authorize effect replay or
claim that a terminal response includes every observation. Consumers must expose
that gap. This optional response extension leaves the ordinary complete-result
shape intact. Disconnect/write failure still reports its real failure.

These are named per-session source allocations, not full process/child RSS
qualification. Runtime outcome/turn retention, multiple sessions, caller-held
responses, allocator overhead and external Codex memory need shared admission
accounting and measured installed workload evidence.

## Detailed contracts and local verification

- [MOD-PROVIDER](../../docs/modules/MOD-PROVIDER.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-provider-jsonl --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.
