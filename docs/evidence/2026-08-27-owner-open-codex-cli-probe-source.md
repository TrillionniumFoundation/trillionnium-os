# 2026-08-27 owner-open Codex CLI probe source record

Evidence level: **L1 source-authored, validation pending**  
Branch: `codex/owner-open-r4-foundation-20260827`  
Implementation: `tools/owner-open/probe_codex_cli.py`

## Scope

This record covers a read-only capability probe for an explicitly selected
installed Codex CLI. The probe exists to prevent the owner-open Host from
hard-coding stale source version labels or guessing current CLI flags.

It executes only:

```text
--version
--help
exec --help
```

It never starts `codex exec`, supplies user input, opens a credential file,
contacts a provider, starts MCP, invokes a model or claims a tool effect.

## Source set

| Path | Purpose |
| --- | --- |
| `tools/owner-open/probe_codex_cli.py` | Executable measurement and bounded help observation |
| `tools/tests/test_probe_codex_cli.py` | Fake CLI normal and fault matrix |
| `docs/implementation/owner-open-codex-provider-v1.md` | W1.0–W1.4 implementation gates |
| `docs/status/owner-open-r4-w1-codex-probe-status.json` | Machine claim ceiling and remaining holds |

## Intended source facts

1. The executable must be a real regular executable, not a symlink.
2. Group/world writable executables are rejected.
3. Device, inode, UID/GID, mode, byte size and SHA-256 are recorded.
4. The file is re-statted after hashing and any identity change fails.
5. Each help command has one bounded timeout and output cap.
6. Raw stdout/stderr, sizes and SHA-256 values are recorded.
7. Advertised options are observed by exact option-token matching.
8. Missing or failing help output is a probe error; no old flag fallback is
   selected.
9. Requested reports are written privately and atomically.
10. All provider/model/turn/tool/device/release claims remain false.

## Authored fake CLI tests

| Test area | Intended proof |
| --- | --- |
| Normal help fixture | Only three help/version commands execute |
| Capability observation | JSON, sandbox, full-access, bypass, model and config options are recorded when advertised |
| Executable/output binding | Executable and raw probe digests match exact bytes |
| Atomic report | Mode 0600, no temporary file remains, non-claims retained |
| Symlink/mode rejection | Unsafe executable paths/modes fail before probing |
| Non-zero help | Probe stops without attempting later commands |
| Timeout | Absolute command timeout fails without an exec turn |
| Oversized output | Bounded observation fails without consuming arbitrary output |

## Required validation

```sh
python3 -m py_compile \
  tools/owner-open/probe_codex_cli.py \
  tools/tests/test_probe_codex_cli.py
python3 -m unittest tools.tests.test_probe_codex_cli -v
```

After host tests pass, an explicitly selected installed binary may be observed:

```sh
python3 tools/owner-open/probe_codex_cli.py \
  --codex /exact/path/to/codex \
  --output /private/evidence/codex-cli-probe.json \
  --json
```

The resulting report must be reviewed before a launch prefix is generated. A
probe against one executable hash cannot authorize or describe another binary.

## Current hold

No output from a real installed Codex CLI is bound to this record, and the
repository's observed GitHub Actions job had no assigned runner. Therefore:

- Python tests are not claimed passed;
- no installed CLI capability is claimed;
- no provider contact, model turn, JSON event stream or full-access execution is
  claimed;
- W1 remains before the live provider bridge.

## Accurate statement

> A read-only, executable-bound Codex CLI help probe and fake CLI tests have
> been authored. They establish a controlled way to discover runtime options;
> they do not execute or prove a Codex turn.
