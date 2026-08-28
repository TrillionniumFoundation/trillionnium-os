# Owner-open long-running jobs implementation v1

Status: **source implemented; exact checkout and physical qualification pending**

## Source closure

```text
job wire
  -> selected v5 transport Host
  -> job-aware v7 execution core
  -> JobManager
  -> JobJournal + JobRegistry
  -> pipe or PTY process group
  -> bounded runtime observations
  -> job-specific Host stream
  -> v5 persisted delivery window
```

The implementation is isolated from the legacy plan, Authority, capability-lease, privilege-broker, typed ADB and sealed shell-broker crates.

## Packages

### `trillionnium-owner-open-job-registry`

Owns in-memory mechanism state:

- scoped job identity;
- exact request binding;
- at-most-one spawn generation;
- accepted, starting, running, terminal and restart-uncertain states;
- output sequence;
- bounded event history;
- attachment IDs;
- stdin-close and kill-request observations.

It cannot spawn a process or authorize a command.

### `trillionnium-owner-open-job-runtime`

Owns local effects:

- durable operation journal;
- pipe and PTY creation;
- input, resize, close and kill;
- output collection;
- process-group lifecycle;
- terminal observation;
- bounded in-memory inspection.

### v7 Host core

`apps/trillionnium-owner-open-host/src/bin/r5_control_host_v7.rs` composes the existing v4 turn core instead of copying it. It uses one input reader and one stdout writer:

- non-job frames are forwarded to the reviewed v4 turn core;
- job frames are handled by `JobManager`;
- core and job output are multiplexed without byte interleaving;
- the selected v5 transport still owns stream windows and persisted delivery.

The old v6 flat-include experiment is retained as unselected history. Cargo automatic binary discovery remains disabled.

## Persistence

The job journal uses the existing append-only durable event-store format in a separate file. If `--job-store` is omitted and `--event-store` is present, the core derives a sibling job-journal path.

Default owner-open behavior permits execution when the journal is unavailable, but marks the lineage `best_effort_unreplayable`. `--require-job-journal` changes only mechanical availability: the Host refuses to begin an effect it cannot first journal. It does not classify command meaning.

## Current source tests

Registry tests cover:

- exact begin idempotency and request drift conflict;
- restart uncertainty and no redispatch;
- bounded history;
- pipe resize rejection;
- input/resize/attachment/close/terminal transitions.

Runtime tests cover:

- pipe input, close, output, terminal and durable records;
- PTY resize and process-group signal;
- completed job replay without a second process effect;
- accepted-without-terminal recovery without process dispatch.

Host tests cover:

- job frames on the same stdio carrier as turn frames;
- provider not started by a job-only request;
- job start/write/close/output/terminal mapping;
- completed job no-redispatch across a new core process.

## Known source holds

- The exact repository has not yet returned Rust 1.93 format/test/clippy evidence.
- The provider JSONL adapter does not yet translate native Codex job tool calls.
- Attach after Host restart is durable inspection, not live file-descriptor reattachment.
- Durable records and live runtime events currently expose separate cursor domains.
- The process runtime is not yet placed into reviewed Root Linux UID/GID, namespaces or cgroups.
- Android abstract-socket admission and AiShell job controls remain W6.
- L5 crash/reboot/power-loss behavior is not qualified.
