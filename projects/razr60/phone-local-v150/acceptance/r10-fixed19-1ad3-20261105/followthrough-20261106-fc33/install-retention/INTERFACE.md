# Installation retention interface

This is an implementation contract for source review and later actual execution. Actual fields remain unbound in the shipped source. The source constructor can only produce source candidates; actual success comes from complete original verification.

## Fixed file scope

GNU directory: /var/lib/trillionnium/owner-open/phone-local-v150/root-install-v150-r10-r1.

| Phase | Role | Exact basename | Maximum bytes |
| --- | --- | --- | ---: |
| stage | install_intent | INSTALL-INTENT.json | 65536 |
| stage | staged | STAGED.json | 65536 |
| stage | preservation | STAGED-PRESERVATION.original.json | 33554432 |
| start | start_intent | START-INTENT.json | 65536 |
| start | started | STARTED.json | 65536 |

No arbitrary file, directory, task, output stream or resident-child role can be substituted. The start scope additionally binds the original supervisor four-integer generation. Other role/liveness/READY facts remain with the existing exact8 chain.

## 1. Retain and bind the actual phase authority

The phase-authority JSON has exactly:
schema, phase, release_inputs, execution_plan, phases, original_map.

Its schema is hepta.install-original-retention.phase-authority-inputs.v1.
phase is stage or start. phases contains only stage for a stage scope and both stage/start for a start scope.
Each phase has the original install reader's exact process/actor-source/request/intent/baseline/result/phone-stream fields.
The source map is the same explicit namespace/original/retained full9 map family as d1de. The selected reader, protocol, BUILD reader, producer template and every consumed original must be retained under their actual descriptors.

Root uses the exact3 descriptor of that complete actual input as FROZEN_PHASE_AUTHORITY. build_reader_binding.py can construct only that RHS change:
```sh
python3 -I -B build_reader_binding.py \
  --phase-authority-descriptor /absolute/actual-phase-descriptor.json \
  --out /absolute/fresh/phase-bound-source
```
This constructor verifies the unbound source pin and strict descriptor shape, compiles the derived source and proves the full-byte inverse. It does not validate descriptor contents or claim actual phase success. No supplied descriptors are part of this shipped package.

Call the derived reader's:
```python
scope_raw = derive_scope_from_actual_phase(actual_phase_inputs_raw, read_pinned=actual_full9_reader)
```
That public API re-verifies actual BUILD, projected installer/archive, exact plan and original phase executions. It returns canonical scope bytes only after successful full bookends. The phase authority original is also pinned inside the returned scope.

The scope binds actual BUILD result, archive/release manifest, retirement/component/policy inputs, execution plan, actual phase result/CLI stdout, exact installer source process identity, file pins, and the started supervisor generation if any. It does not contain a projected inventory count.

## 2. Derive the first read-only request

The pure producer and host APIs are:
```python
op_raw = capture_protocol.manifest_operation()
expected = expected_operation(
    capture_protocol, reviewed_execution_protocol, reviewed_producer_template_raw,
    scope_raw, op_raw, explicit_operation_identity, actual_install_execution_plan,
)
```
explicit_operation_identity has only label, request_path and idempotency_key. All are actual Root-selected one-use operation identities; this package generates none. The source constructor creates only bytes and expected argv/request data.

expected returns request, its exact original pretty JSON/LF bytes, wrapped shell command, exact configured-pocket4 dispatch, original actor operation directory, wire-byte count and the template/bound-source/bootstrap pins. It uses the unchanged179a actor through the actual execution plan and the reviewed v2 GNU prefix. Root retains and dispatches the original request through the existing actor only when actual authorization and preconditions exist. No function here sends it.

The producer uses FROZEN_SCOPE to check exact scope bytes before parsing or I/O. Its inline bound source is derived by replacing only FROZEN_SCOPE=None with that scope's actual pin, with complete inverse proof. The actual request contains the complete body; the capture reader verifies those complete request bytes against independent derivation.

## 3. Verify the first manifest and derive exact chunks

Retain the original dispatch/start/status/read and private request/intent/baseline/result plus full raw phone stdout/stderr. verify_capture_actor checks that original chain and the exact inline request; capture_protocol.validate_manifest checks the returned canonical manifest.

The first manifest fixes complete original full9 identities and the whole-file bytes/SHA for every selected role.
```python
chunk_ops = capture_protocol.chunk_operations(scope_raw, verified_first_manifest_raw)
```
This produces an exact finite sequence: each phase role in fixed order, then contiguous1MiB chunk indexes starting at0. The manifest's raw bytes are included and hash-bound in every chunk request. The final chunk has the exact derived length and typed EOF. A zero-length, oversized or out-of-range file/slice is rejected.

Root supplies distinct identities for each original capture operation and retains its complete original results. Any actor/phone error, timeout, unknown status, missing EOF, changed source or incomplete stream prevents acceptance; this package has no retry dispatcher or hidden fallback. All chosen identities must be distinct from each other and the actual installation phase identities.

After all chunks, derive and execute one final manifest operation with its own original identity. Its file descriptors and directory full9 must exactly match the first manifest. No PID or liveness claim is inferred from this equality.

## 4. Bind and verify the complete retention input

The retention JSON has exactly:
schema, phase_authority, scope, operations, original_map.

The schema is hepta.install-original-retention.original-inputs.v1.
phase_authority must equal the frozen authority exact3 descriptor.
scope is an exact retained descriptor for the scope bytes rederived from the actual authority.
operations is the ordered first-manifest/chunks/final-manifest list. Each item has exactly identity and originals; originals uses the exact actor-original fields above.
original_map contains explicit retained full-byte/full9 mappings for all consumed inputs, templates and original capture records.

The source constructor can then set both actual descriptor slots:
```sh
python3 -I -B build_reader_binding.py \
  --phase-authority-descriptor /absolute/actual-phase-descriptor.json \
  --retention-inputs-descriptor /absolute/actual-retention-descriptor.json \
  --out /absolute/fresh/retention-bound-source
```
Root calls one of:
```python
verified = verify_retention_inputs(actual_retention_inputs_raw, read_pinned=actual_full9_reader)
retained = retain_installation_originals(
    actual_retention_inputs_raw, absolute_fresh_host_directory,
    read_pinned=actual_full9_reader,
)
```
The second API first performs the complete verification, then writes complete reconstructed originals into the fresh host directory through its held FD and returns an explicit original_map. The original's metadata remains the observed phone metadata; retained metadata is measured on each new host file. RETENTION-RESULT.json is published after all retained file readbacks. Payload-write failure before the terminal step leaves no terminal record. Any publication I/O error, including one after a result filename appears, preserves a failed or unknown host process outcome; a filename alone cannot qualify success.

Private fixture helpers such as capture, reassemble, phase_files and _save_verified do not independently establish actual authority. Their direct use in offline tests is disclosed and cannot replace these public actual-reader gates.

## 5. Integrate the two scopes with existing install verification

The stage scope supplies three original-map rows and the start scope supplies two. Combine those five actual rows with the other actual BUILD/phase/READY/installed-module/claim/bind originals, preserving each exact namespace and retained full9. Feed them to the separately source-bound install reader's existing install_originals fields.

The retention reader's return flag actual_install_or_READY_qualified remains false even after successful actual transport. The existing full install/READY and four-role readers remain responsible for confirming the business-relevant state. The source phase construction here does not infer readiness, worker liveness, parent wait, task closure or rollback.

## Provenance and limits

No source matching the old short359c/523a references was found during the recorded Mac source discovery. This is an independent bounded implementation, with the original d1de/79f2 sources retained as references and exact source pins. No claim of byte reuse from359c/523a is made.

Scope/operation inputs are bounded to32768 bytes, each response to2MiB, slices to1MiB and preservation to32MiB. Other installation originals are at most64KiB. First/final manifest plus all slices is at most36 operations for a stage and4 for a start at these source limits. The unchanged actor JSON result limit,8MiB combined phone stream cap,512MiB original-map envelope and all underlying BUILD/install reader bounds still apply. These source maxima are not an observed budget qualification.

The original phone-root/proc observer is pending actual execution. Current tests use real host file bytes and full9 with explicitly synthetic phone-ownership/process metadata. Actual root guards and actual BUILD/phase positive inputs remain unbound.
