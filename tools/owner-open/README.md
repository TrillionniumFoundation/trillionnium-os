# Owner-open development tools

These tools are explicit owner bootstrap, observation and source-qualification
utilities. They are not semantic approval gates and their output is not, by
itself, an integrated Codex turn or device-effect claim.

Canonical entries:

- `probe_codex_cli.py` — read-only executable/help observation;
- `build_codex_exec_prefix.py` — executable-bound, unexecuted launch prefix;
- `jsonl_provider_runtime.py` — provider-neutral bounded duplex JSONL process
  mechanics for W1.2 fixtures and bootstrap adapters;
- `prepare-adb-reverse-v1.sh` — explicit W3-A owner-host reverse bootstrap.

The unversioned `prepare-adb-reverse.sh` was an intermediate source draft. It
must not be referenced by plans, automation or evidence; use the `-v1` tool.

Every tool has a corresponding machine status/evidence boundary. A help probe,
launch prefix, fake provider, reverse mapping or qualified ELF may never be
promoted to same-turn, physical-device or release evidence without the later
acceptance gates.
