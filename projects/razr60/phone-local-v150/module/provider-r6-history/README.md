# Phone-local module source projection

This directory preserves exact reviewed source bytes for two immutable service attempts.
It is a source-review projection, not an installable Magisk module or a reproduction of private runtime state.

- r6-r1: actual startup failed when the provider's embedded dependency pin disagreed with the changed health module. The supervisor recorded exit 74, and later independent observation found all four original groups absent with preserved task/claim/journal state. No new health nonce or task was submitted in that attempt.
- r6-r2: the provider revision closes that dependency pin. Its module source, package, and combination metadata were frozen on the host. At projection creation, no r6-r2 phone startup or health result is asserted.

The scripts retain their exact instance-specific boot, process-group, application, and filesystem bindings so source comparisons remain meaningful. Those values are not portable defaults. Installable inputs require separately reviewed private manifests, real prior-task disposition, and current device observations.

Included: lifecycle source, read-only process census, source diffs, and combination hashes.
Excluded: private binding manifests, hash-check input files, SEALED markers, deployment archives, installers, raw task/UI evidence, credentials or key-content digests, model weights, and SELinux policy binaries. The full policy source is referenced by its exact hash in combination metadata and is maintained by the runtime source package.

A frozen combination is a traceability label. It does not establish model health, business success, daily-use qualification, cold boot, folded/rotated display support, or disconnected operation. The fixed 19-case protocol retains its original cases and limits, and these source snapshots do not add acceptance samples.
