# Current-source isolated host lifecycle: NEG04/05/07/08/09

This package runs the five original formal host lifecycle cases against the exact current R10 production 15-source set. It does not award a physical layer, aggregate fixed19 PASS, a service/READY qualification, or a future deployment binding. No phone command or real model runs. The actual typed Android command is retained as evidence and is never executed; its mapped dispatch triggers a fresh disposable host counter instead.

## What is preserved and what changed

The original case runner is Git commit `11d427995808c05943ecbf90b4fbd2a74af9247d`, path `projects/razr60/phone-local-v150/acceptance/r7-r3/host-cancel-faults/run_fault_cases.py`, SHA256 `6163449a9c92fd370fb5e27b190461ae46f2bfe11c180ea7ca1987bdb190b178`. The deterministic HTTP fixture and counter are byte-identical originals. `DERIVATION.json` records the current-source pin, namespace deadline, scope labels, retained live `/proc` observations, and four complete before-late original bytes added to the runner. This is a new execution of the current source, not adoption of the old R7 PASS.

The shared child owner calls the exact reviewed `0374a885…` capture implementation. Capture drains both pipes throughout asynchronous work, and success requires actual child wait, both EOFs, reader exit, the original deadline, held-created-inode and full-content checks. Only exact owned process identities receive fixture cleanup signals. Unknown capture/cleanup never becomes success or a reason to redispatch. Per-stream capture stays at 64 MiB; the exported host acceptance tree additionally refuses any original over 4 MiB or an aggregate over 32 MiB.

The fixed current configuration is copied unchanged. Each private fixture changes only `endpoint`, `api_key_file`, and `model`; the credential is freshly generated synthetic data. The current daily provider's optional **no binding** `inspect_single_slot` cleanup path is exercised. This package does not qualify the separate bound server identity/CPU request-drain branch. That branch remains covered by its own actual physical CPU cancellation originals.

## Prepare exact input material

The entry defaults to a zero-input-read preview. Source/input creation is create-only; output reuse is refused.

```sh
python3 -I -B PACKAGE/source/host_lifecycle.py \
  --source-manifest-sha256 SOURCE_MANIFEST_SHA \
  --prepare-inputs-once \
  --production-source-dir CURRENT_15_SOURCE_DIRECTORY \
  --configuration EXACT_LOCAL_CONFIG_JSON \
  --service-inputs EXACT_SERVICE_INPUTS_JSON \
  --out FRESH_INPUT_DIRECTORY
```

The preparation verifies all 15 source SHA256s, configuration `7807549287…`, service `2739a0af53…`, original client `500e270377…`, and original protocol `c573959e59…`. It compiles source bytes without importing production code and emits an exact complete input manifest. Its `host_source_seal` and `host_material_combination` are explicitly host material identities. `deployment_source_seal_sha256` is null; they are not a device release seal or deployment combination.

## Execute once on P4

Stage the package and prepared inputs in separate sibling directories under `/home/alex/razr60-local-model-v150/`. The output must be a fresh sibling, neither inside nor containing an input/source directory. All parent paths must already exist and be canonical. Use P4's existing reviewed route. The host entry calls only the frozen module's local capture methods and never starts its remote or phone helpers.

```sh
/usr/bin/python3 -I -B PACKAGE/source/host_lifecycle.py \
  --source-manifest-sha256 SOURCE_MANIFEST_SHA \
  --inputs PREPARED_INPUT_DIRECTORY \
  --input-manifest-sha256 INPUT_MANIFEST_SHA \
  --out FRESH_ATTEMPT_DIRECTORY \
  --execute-once
```

The launcher requires coherent Linux procfs and `/usr/bin/bwrap`. It unshares user, PID, network, mount, IPC and UTS namespaces; binds only `/usr`, read-only source/input/client, and the fresh writable output; clears environment; drops all capabilities; and verifies the resulting net/mount/PID namespaces really differ. The synthetic fixture is reachable only over the private network namespace's loopback. There is **no namespace-free fallback**.

The suite absolute deadline is 90 seconds; the outer original process/capture deadline is 105 seconds. Give the existing P4 controller at least 120 seconds to retain the original result and failure output. Failure/timeout does not authorize another launch of the same attempt. Inspect the original failure and use a new explicit attempt only if separately needed.

The launcher writes `OUTER-RESULT.json`, the complete `ORIGINAL-FILES.json`, and, only after independent reconstruction succeeds, `HOST-VERIFICATION.json`. Stdout gives exact descriptors. All five cases must be present and each resource/ownership check must pass. The verifier separately reconstructs actual JSONL sequences, semantic claims, intervention phase originals, the one HTTP request, effect counter and original receipt, worker drain, late-result fence, and replacement-stream rejection. The verifier does not accept a claimed `PASS` field alone.

## Read-only recheck

```sh
python3 -I -B PACKAGE/source/host_lifecycle.py \
  --source-manifest-sha256 SOURCE_MANIFEST_SHA \
  --inputs PREPARED_INPUT_DIRECTORY \
  --input-manifest-sha256 INPUT_MANIFEST_SHA \
  --evidence ACTUAL_ATTEMPT_DIRECTORY \
  --original-files-sha256 ORIGINAL_FILES_SHA \
  --verify-originals
```

This performs no case execution or output mutation. Original evidence paths under `/work` are mapped only into the complete retained owned tree. No current PID is signalled during verification.

## Case evidence

| Case | Original intervention | Required retained behavior |
| --- | --- | --- |
| NEG04 | Close the original stream while the original HTTP worker is live, before any typed tool | Explicit unknown terminal, zero effects, consumed semantic identity, original worker cleanup |
| NEG05 | Close after one counter commit, before the original result is available | At most one effect, original result retained separately, unknown wire result, no replay |
| NEG07 | Real 200 ms result deadline while the original delayed counter is live | Unknown result, conservative terminal, later original receipt cannot rewrite four pre-late original files, no second effect |
| NEG08 | One original cancel before first dispatch | One acknowledgement, zero effects, no forced navigation, actual HTTP worker group gone and fixture idle |
| NEG09 | One original cancel after the original effect, receipt and counter join | Only the observed effect, no subsequent dispatch/forced navigation, unresolved phone intent remains conservative |

All cases send a separate explicit negative replacement-stream request for the same semantic identity. That request must be refused before a new HTTP request or tool dispatch. This is a host-only rejection test, never an automatic task replay.

Local preparation and source checks do not count as host case execution. The managed local environment failed the namespace preflight and its original failure is retained in `evidence/local-namespace-preflight01.json`. Actual qualification requires the real P4 run. Each of the five fixed-protocol cases still separately requires its `physical_native_task` layer.
