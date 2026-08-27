# Trillionnium owner-open process runtime

This crate is the W2/W3 mechanism-only process substrate for the r4 owner-open
path. It is intentionally independent from the pre-r3 plan, Authority,
capability-lease, risk, approval, P01 custody and `shell.exec.v1` broker graphs.

## Implemented source behavior

- `shell.exec` command strings execute as `<configured-shell> -c <command>`;
- `shell.exec` argv executes the exact first element with the remaining elements
  preserved, without shell expansion;
- cwd, inherited environment deltas and binary stdin are passed mechanically;
- stdout and stderr are emitted as raw byte chunks with one monotonically
  increasing per-call sequence;
- one accepted record, at most one started record and exactly one terminal event
  are emitted for every mechanically valid request;
- timeout, cancellation and output exhaustion terminate the complete process
  group, apply a bounded TERM-to-KILL grace period and reap the child;
- `adb.exec` invokes the configured ordinary adb executable with exact argv;
  unknown/future subcommands remain valid and no serial, host, port, target or
  privilege argument is injected;
- `target_id` is correlation metadata only and never changes the command.

## Explicit non-claims

This source slice does not yet prove:

- a live Codex provider producing the tool call;
- integration into `trillionnium-owner-open-host`;
- Root Linux namespace, UID/GID/capability or cgroup placement;
- an ARM64 adb client or transparent Android relay in a device image;
- durable event persistence, resume or post-restart reconciliation;
- Android Soong/init/SELinux inclusion;
- physical shell/ADB effects, reboot, power-loss or release qualification.

Those remain separate r4 acceptance gates. This crate must not be presented as
owner-open dogfood completion until the same Codex turn drives it through the
integrated Host and L4/L5 evidence is captured.
