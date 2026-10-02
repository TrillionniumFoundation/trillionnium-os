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

The linked job module now shares a 48 MiB active/retained pool and an independent
16 MiB working pool across manager and registry constructors. The process
reservation also has a 32 MiB/16-owner ceiling and is charged against the same
48 MiB pool. Start preflight counts actual spare capacities, argv/env nodes,
path storage and initial stdin before digest serialization. Inherited settings
are bounded and snapshotted before acceptance. I/O workers and reapers retain
their own Arc of the process charge through buffer retirement and cleanup.

Registry future history/attachment/terminal headroom, journal derived identities
and actual observation windows consume that shared resident pool. Durable
terminals retain event IDs and authenticated record hashes; their payloads load
on demand and no longer accumulate as full cached DOMs. Recovery borrows headers
without cloning payloads. Metadata pressure refuses before WAL acceptance and
preserves uncertain identities. Memory-only development terminal caches have an
8 KiB owned-storage bound and share one Arc rather than copying the same Value.

Numeric output DOMs and JSON escaping are preflighted before cloning/encoding
under the shared working lane. The default 64 KiB output chunk remains valid;
larger profiles can fail the working bound before journal creation. Inspection
streams and filters records with a bounded working envelope, but still scans
unrelated scopes until an indexed scope visitor is available. Refusal is an
explicit error and never means that a missing prefix was recovered.

These logical charges do not prove a whole-process 64 MiB RSS bound. Allocator
overhead, independently owned event stores, other host modules, the initial host
environment lookup and caller-retained/cloned Vec/Value responses need their
separate boundaries and installed measurements. No qualification is promoted.
