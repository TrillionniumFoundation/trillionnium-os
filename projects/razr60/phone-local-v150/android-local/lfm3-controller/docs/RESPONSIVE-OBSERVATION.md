# Responsive observation contract

This standalone Android candidate is outside the active Cargo/G1 source graph.
It affects Android task lifecycle and evidence handling (D3/D5); it does not
activate or change a registered G1 module. The affected interfaces are the
existing service observation callback, task admission and terminal evidence.

## Ownership and bounded work

The service main looper owns the active request, stability gate, publication and
current snapshot. One process-wide executor owns expensive read, copy and file
work. A process-wide busy flag prevents a replacement service from submitting a
second read while an old Binder call remains blocked. Worker inputs retain the
original task, display, generation and deadline; no timeout renews the request.
The worker never chooses or dispatches phone actions.

The worker checks cancellation and identity between traversal and file stages.
The main looper independently checks expiry and cancellation at intervals of at
most 100 ms when it can run. This is a scheduling interval, not a measured
Android response-time guarantee. Target-display events fence sample and
screenshot publication. Screenshot age starts at the original capture request.

The v50 bounds remain 1,536 visited nodes, 128 retained useful nodes and fewer
than 6,144 UTF-16 text units. Statistics belong to the sampled graph that supplies
the published nodes; they are not replaced by statistics from a later recheck.
Existing before/after graph identities and immutable task authorizations remain
required. Event filtering is display-specific where Android exposes that fact;
older APIs conservatively invalidate observations on unknown-display events.

## Failure, cancellation and recovery

Every produced graph, bitmap and unpublished PNG has one cleanup owner. A late
worker result is discarded and cannot complete a retired task. Cleanup of an
unpublished file is best effort and does not authorize deleting unrelated files.
The terminal field `observation_read_worker_pending_at_terminal` reports a busy
read separately from the existing native/action/display cleanup claims. New
task admission and recovery acknowledgement require that read to actually exit.
The service cannot safely force-interrupt an arbitrary Binder or fsync call.

A Stop arriving while the final installed-package identity is being checked is
checked again before a known-cleanup terminal result is published. Unknown
cleanup retains its blocked status. Earlier actions are not retried or undone.

## Compatibility, deployment and rollback

The added terminal field is additive. No model profile, sampler, JNI ABI, tool
scope, network permission or persistent-model migration changes. Install only a
same-signer APK built from the exact reviewed candidate while the phone owner is
idle. Preserve model files, runtime configuration and existing task journals.
A version rollback needs a separately reviewed same-signer/version strategy;
never uninstall to bypass downgrade checks or erase a recovery journal.

## Required evidence

Host checks exercise actual extracted observation methods using explicit fake
Android IO: deadline/Stop during blocked work, stale publication, single-worker
admission across service replacement, resource ownership, target-display events,
v50 collection-statistic preservation and terminal Stop after identity IO.
They must retain the strict Java 8 API gate. Android compilation and physical
phone tests are separate. A device canary must show ordinary UI Start/Stop,
real local inference, actual goal effects and known teardown, then repeat while
the main screen is in independent use. Passing host checks is not phone success.
