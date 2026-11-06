# Install/start/READY reader: type-check candidate

## Scope

This is an unbound, host-only source candidate. The original Mac a1055 directory is unchanged. Both FROZEN_INPUTS and FROZEN_EXECUTION_PLAN remain None. No actual BUILD, installation, service start, READY qualification, phone call, model request, business acceptance, or fixed19 credit is created here.

The actual reader change is limited to three typed facts: original stream cursors and durable byte counters must be Python integers; log_truncated values must be the boolean False; guard process identity must be five positive Python integers. The execution protocol remains byte-for-byte unchanged. INSTALL-READER-TYPE-CHECKS.patch contains only these checks.

## Baseline defects and preserved behavior

Internally consistent original-shaped synthetic process envelopes reproduced acceptance of False/0.0 as offsets, False/float durable counts, 0/0.0 as truncation flags, and boolean/float fields in source-entry process identities. Bytes, UTF-8 text, stream lengths, and fixture digests remained consistent, so these were semantic type defects. log_synced already used is True and rejected integer 1; it is unchanged.

## Retained validation

The fresh Mac candidate run passed 64 controls: the unchanged original 43 controls plus 21 focused type, exact-LF, Unicode/multiline, and unbound refusal controls. The unchanged phone_rc suite separately passed all three cases, including a consistent nonzero phone_rc under actor exit zero and rejection of boolean False as rc zero. Total unique persisted Mac controls: 67. The four Linux guard execution controls are explicitly skipped on macOS.

Before the scratch execution environment became unavailable, the same candidate reader was also observed passing original 43 + phone_rc 3 + type/LF/guard 25 in Linux. The unmodified guard used a harmless local body with clearly simulated root metadata; actual PID/group/session, timer restoration, pipe backpressure, and cleanup were exercised. Its blocked receipt ended with TimeoutError after approximately 10.0028 seconds and no body execution. These four host-only observations are documented separately; their now-inaccessible scratch JSON is not reconstructed or counted as a retained Mac result.

## Contracts

references/INPUT-CONTRACT.original.json and PRODUCER-RETENTION-CONTRACT.original.json are unchanged baseline references. Their old reader hash is not a candidate authority. CANDIDATE-MANIFEST.json supplies the exact candidate source and evidence hashes. No bound execution plan or formal input identity was generated.

## Reproduce without replacing previous results

Run from a fresh isolated copy. The original phone_rc script deliberately opens its result with xb; never delete or overwrite a previous result to rerun it.

    python3 -I -B - <<'PY'
    from pathlib import Path
    import shutil, subprocess, sys, tempfile
    source = Path.cwd()
    run = Path(tempfile.mkdtemp(prefix='hepta-install-reader-offline-'))
    for name in ('source', 'references', 'validation'):
        shutil.copytree(source/name, run/name,
                        ignore=shutil.ignore_patterns('CONTROLLER-PHONE-RC-RESULT.json'))
    subprocess.run([sys.executable, '-I', '-B',
                    str(run/'validation/run_install_ready_candidate_controls.py'),
                    str(run/'controls')], check=True)
    subprocess.run([sys.executable, '-I', '-B',
                    str(run/'validation/run_controller_phone_rc_controls.py')], check=True)
    print(run)
    PY

On Linux, the candidate runner additionally executes the unchanged guard against only harmless local files in disposable process groups. It simulates root owner fields and never creates a production role identity. On macOS, its result explicitly records the Linux procfs requirement and skips those execution controls. All output remains source-only.
