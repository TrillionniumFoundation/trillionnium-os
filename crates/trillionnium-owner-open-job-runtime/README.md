# Owner-Open Job Runtime

Current module: `MOD-JOB-RUNTIME`  
Program authority: `docs/START_HERE.md`  
Machine contract: `docs/machine/module-catalog.v1.json`

This crate owns durable long-running pipe and PTY job mechanics, controls, observations, process-group lifecycle and restart reconciliation.

Admission correctness is closed at L1; installed lifecycle, slow-path lock removal and target evidence remain tracked by `GAP-PROCESS-LIFECYCLE-001` and `GAP-CONC-JOB-START-HOTLOCK-001`. Current state is generated under `docs/generated/`.

## Detailed contracts and local verification

- [MOD-JOB-RUNTIME](../../docs/modules/MOD-JOB-RUNTIME.md)

From the repository root (source tests only):

```sh
cargo test --locked -p trillionnium-owner-open-job-runtime --all-targets
```

Use the linked module runbook for state ownership and recovery. This command
does not establish installed-target, device, fault or release qualification.

Process framing (command/argv, environment, paths and PTY dimensions) is checked
before registry or durable acceptance. An empty argument after a nonempty argv
executable is preserved. Rejected new jobs do not retain per-key observation
state when durability is unavailable; inspection exposes the journal status
without an accepted job marker. These internal fixes preserve the v1 journal
schema and require no migration. Rollback restores the prior rejection behavior;
source tests alone do not qualify installed memory use or recovery latency.

The manager now accepts at most eight concurrent process owners (default and
hard ceiling, previously a default of 256). Profiles above that ceiling or the
32 MiB aggregate raw process-buffer reservation are rejected before opening a
journal. Each process channel has 16 entries; the reservation also counts the
cloned initial stdin, reader buffers, blocked sends and dispatcher staging.
Resident observations share a 16 MiB/4096-event budget across all jobs, including
owned string/byte capacities and event slots, with 1 MiB reserved for bounded
cursor/key metadata. Prefix eviction returns deque capacity and reports the
existing exact inspection gap; it does not remove an uncertain job identity.
Manager-owned registry history has 16 events per key and 256 keys in total.

At registry capacity, only a terminal whose full request and terminal match a
durable journal record and which has no live/pending process owner may be
archived. Inspection retains the journal-derived runtime cursor and reports the
archived prefix as a gap. Repeated exact starts still return the durable terminal;
request drift remains a conflict. Unknown and observed-but-undurable terminals
remain fenced and may exhaust admission until explicitly reconciled. No WAL or
identity record is deleted. These changes preserve existing journal/wire bytes.

The budgets bound these named resident structures and raw process buffers. They
do not prove a whole-process 64 MiB RSS bound: journal state, serialization and
other host modules still allocate additional memory. V2 journal recovery now
visits authenticated on-demand records one at a time; bounded whole-history
inspections can explicitly refuse capacity without claiming recovered coverage.
Process-wide accounting and installed resource measurements remain required.
