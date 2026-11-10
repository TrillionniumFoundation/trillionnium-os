# v32 upgrade and runtime selection host tools

This package verifies a specific published Android v32 source/build/APK identity before preparing a v30-to-v32 upgrade or an explicit runtime configuration change. It includes a correction for the legitimate Android runtime basename `libc++_shared.so` and self-contained synthetic host tests. It does not contain an APK, model weights, private phone evidence, signing keys or device identifiers.

## Runtime files and the correction

The deployment runtime is exactly these three files in `package/`:

| File | Responsibility |
| --- | --- |
| `v32_identity.py` | Bind complete source, actual compiler inputs/outputs, original host gates, static acceptance and signed APK payload. |
| `upgrade_v32_once_r1.py` | Prepare or execute one guarded v30-to-v32 APK replacement. |
| `select_runtime_once_v32_r1.py` | Prepare or execute one guarded runtime configuration replacement. |

The only production-code correction from the preceding host runtime adds the literal `+` to `verify_zip`'s library basename character class. This admits `libc++_shared.so`. The full-match requirement, `.so` suffix, duplicate checks, exact ZIP payload set, library byte counts and SHA-256 checks are preserved. The upgrade and selector entry files retain their exact preceding SHA-256 values. `libcxx-runtime-fix.patch` records the complete production delta.

`MANIFEST.json` binds the three runtime files. `TRANSFER-MANIFEST.json` binds that manifest and gives the exact source paths, destination basenames, byte sizes and hashes for deployment. `RELEASE-MANIFEST.json` inventories the complete public package, excluding itself.

## Self-contained host validation

Use Python 3.11 or later. There are no third-party Python dependencies, environment variables or adjacent checkouts required.

From this directory, run:

```sh
python -B tests/run_host_validation.py --output /absolute/new-output
```

The output directory must be new and outside this release. The runner checks the runtime manifests, reconstructs the exact pre-fix verifier by reversing the one-character patch, verifies its original SHA-256 and reproduces its rejection of otherwise valid synthetic ZIP/compiler bytes containing `libc++_shared.so`. It then runs the original 36 methods and six new runtime-name methods: 42 test methods with 58 parameter subtests. A Python audit hook forbids all real socket and child-process creation throughout the test run.

The result is written to `HOST-RESULT.json`, with complete test names, input hashes, counters, the baseline counterexample and log hashes. `host-tests.stdout` and `host-tests.stderr` retain the actual captured output. The runner returns nonzero if tests fail, expected test counts change, a transport is attempted or a test input changes. The committed `validation/` directory contains a run of this same command.

The tests use three byte-identical public producer files from commit `e07c6624b7309b0acf3fe10e31b0605a29e3e72d`: `tools/build_identity.py`, `tools/model_profiles.py` and `tools/run_host_checks.py`. Their provenance and hashes are in `tests/fixtures/producer/SOURCE-MANIFEST.json`; the test module also enforces their SHA-256 values before use. The remaining 1194-file test tree, receipts, compiler outputs, APK ZIPs and phone responses are synthetic. Only test setup chooses this package-relative fixture. All 42 test-method bodies are unchanged from the reviewed suite.

The production helpers have no fixture switch or source-identity override. Host-test success does not establish a real signed-APK plan, installation, accessibility connection, model inference, accelerator use, offline Android task success or production readiness.

## Live identity contract

Both helpers require actual, externally supplied evidence before any phone access:

1. A complete actual `hepta.independent-v32-source-integration.v1` inventory for source commit `e07c6624b7309b0acf3fe10e31b0605a29e3e72d` and tree `81955c2053ba24cab0783c9cb7636a49c0f186de`. Its 1194 entries must match the fixed portable inventory SHA-256 `b9c1355c16658c354550aad818053e9e5d8bb12ce7150d7b861de109a1000b90`. Every file's bytes, SHA-256 and Git blob SHA are checked. Extra importable host drivers are refused.
2. The actual compiler receipt and all 163 current source inputs; the fixed GenieX/llama commits; and a deterministic build identity asset generated from those inputs. The raw asset in the signed APK must be identical.
3. Independently read compiler DEX, base resources and native runner outputs, plus the complete static runtime-library set, with exact lengths and hashes. Duplicate ZIP entries and unlisted payloads are refused.
4. Original host-check records, expected check sequence, integer-zero exit statuses, source-input map and all stdout/stderr hashes. The applicable-gate qualification must agree with these originals and the actual inventory. Historical failures are not rewritten.
5. Actual static acceptance and signed APK evidence for package `org.trillionnium.hepta.local`, version 32 / `0.32.0-local-scoped-tools`, ARM64 and no Android permissions. Host `apksigner` independently verifies the fixed original single certificate. `aapt2` independently verifies package/version/ABI/permissions.

The raw inventory-file SHA-256, the canonical portable inventory SHA-256 and the raw deterministic asset SHA-256 are different identities. Supply each where its flag requires it. The bundled three-file producer fixture is not acceptable as the live source.

## Prepare a host-only plan

Copy only the three listed runtime files into a fresh private helper directory. Verify their sizes, SHA-256 and Git blob SHA against the transfer manifest. Keep that directory free of unlisted Python or bytecode files and invoke Python with `-B`. The verified source modules and selector are compiled directly from checked source bytes.

Get each interface without contacting a phone:

```sh
python -B package/upgrade_v32_once_r1.py --help
python -B package/select_runtime_once_v32_r1.py --help
```

Both entry points require these shared flags:

| Evidence or tool | Flags |
| --- | --- |
| Complete source and inventory | `--source`, `--source-inventory`, `--source-inventory-sha256` |
| Actual build | `--build-receipt`, `--build-receipt-sha256`, `--build-output` |
| Signed package and asset | `--apk`, `--apk-sha256`, `--build-asset-sha256` |
| Static acceptance | `--static-acceptance`, `--static-acceptance-sha256` |
| Original host checks | `--host-checks`, `--host-checks-sha256` |
| Applicable gate qualification | `--host-gate-qualification`, `--host-gate-qualification-sha256` |
| Host inspection executables | `--aapt2`, `--apksigner` |
| Current configuration and fresh output | `--config-sha256`, `--output` |

Use absolute regular file paths and measured full hashes. The upgrade additionally requires `--old-apk`, bound to retained v30 APK SHA-256 `a8c4be595fbd89d79bc1c7693b9f3c7d2b86ac9980fadc324dc10a5718d3c593`. The selector additionally requires `--profile` and `--compute npu|gpu`; explicitly choose `--context-tokens` and `--threads` for the intended run. The current config SHA is required for both; no model is inferred as the current default.

Omit `--execute` to generate a host-only plan. This runs host APK inspection tools, writes `REQUEST.json`, `PLAN.json`, `RESULT.json` and proof captures, and does not initialize ADB. Read the plan and actual host proof before executing. Do not replace missing measured inputs with predicted hashes.

## Explicit phone execution

Execution additionally requires `--execute --exclusive-idle-window` and explicit `--adb`, `--adb-host`, `--adb-port`, `--serial` for the already-running ADB server and selected device. There is no default device selection. These tools do not own a device-global lock or coordinate other operators. The operator must hold an exclusive idle window across verification and mutation, coordinating any other device writers; a common external lock works only when every writer participates.

The upgrade requires the exact installed v30 APK, the pinned ordinary app UID, Android user 0 and SM8750. It checks the complete selected-model hash, idle journals, absence of native workers or pending requests, stable current configuration and accessibility preferences. It records durable intent and issues one `adb install -r -t`. A `Success` acknowledgement alone is insufficient: exact installed APK/version/UID and unchanged private state must be read back before one ordinary MAIN/LAUNCHER start, then checked again before a verified candidate is published. No configuration replacement, scope installation, task start or model inference is part of this flow.

The selector checks the actual v32 identity, target private model hash, repeated idle/configuration/accessibility observations, then issues one force-stop. It creates a private temporary configuration with create-only semantics and performs one same-directory rename guarded by the previous config, journal and scope bytes. It reads back the configuration before one ordinary MAIN/LAUNCHER start, with no task/automatic-run extras. A final identity/config/journal/scope/accessibility/worker readback is required for a verified candidate.

The optional `--restore-observed-accessibility` retains its narrow pinned-list contract: only the original service-list hash and the two known force-stop effects are admitted. It never broadens the list, writes `accessibility_enabled` or force-stops again after restoration. Scope bytes are preserved; this package does not install or qualify a task scope.

## Interrupted outcomes and rollback

Output directories are create-only and mutation intents are retained before issuance. A timeout is an unknown result; neither helper automatically retries, rolls back or deletes residual private files. Reconcile intent, returned result and independent readback before any new mutation. A new output directory is not permission to repeat an uncertain install or config rename.

To revert this host compatibility correction, retain and select the preceding reviewed private helper bundle with identity SHA-256 `480154279eed6d941d1cb240d4faf071088d4646f36f5bd35b926e3001c98e34`; that verifier will again reject `libc++_shared.so`. Do not overwrite an active helper directory, reinterpret an existing plan as belonging to different bytes, or silently migrate bindings. Host-package rollback does not downgrade the APK or restore phone configuration. Any such phone action requires a separate reviewed operation.
