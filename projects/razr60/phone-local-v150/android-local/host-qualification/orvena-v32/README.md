# Scoped Orvena v32 host qualification

This package prepares and verifies an explicitly selected local-model trial for
the Hepta v32 source commit `e07c6624b7309b0acf3fe10e31b0605a29e3e72d`.
It contains the runnable host helper, its frozen dependency manifest and
self-contained host regression fixtures. It does not contain model weights,
a signed APK, a device binding or captured private phone evidence.

The Android application, its `hepta.qualification-scope.v1` schema, the nine
task instructions and the independent goal assertions are unchanged. The host
binding uses `hepta.orvena-scoped-host-binding.v2`: its required device target
contains the exact serial, default display ID, physical display ID and observed
input dimensions. The operator supplies these values when issuing a private
binding. Its full SHA binds those values; later CLI parameters must match them.
There is no device discovery, implicit device selection or parameter override.

## Run the host tests

Use Python 3.11 or later and Pillow. Run from this directory, with a new output
directory outside `candidate/`:

```sh
python -B tests/run_host_validation.py --output /tmp/hepta-orvena-host-checks
```

No environment variables, adjacent checkout, machine-specific source directory,
ADB executable, phone, model or network connection are required for these tests.
The suite executes the actual scope stage, ordinary launch preparation, source
loaders, evidence validators and fixed core-plan code using synthetic transport
and build inputs. The additional device-target tests reject mismatched serials
before transport creation or offline radio setup. A host test pass does not
establish Android installation, inference correctness, task completion, Stop,
background execution or network restoration on a phone.

`tests/fixtures/v32-source-inputs/` is a hash-checked public source subset used
only by host tests. `PUBLIC-SOURCE-FIXTURE.json` records its 23 source files. The
real binding issuer requires all 1194 published source files and actual compiler
and signed-APK receipts; the test subset cannot substitute for them.
`tests/fixtures/legacy-loader-package/` is an anonymized test fixture for the
cached-bytecode regression. Its device identifiers and host paths are synthetic,
and its manifest has been regenerated. It is not an original execution record or
a runnable device qualification package. The upgrade/selector files under
`tests/fixtures/upgrade-select-helpers/` supply the exact source pins required by
host preparation tests; the tests do not execute their phone mutation paths.

## Required real inputs

Real qualification requires the complete pinned application source, its actual
source-integration manifest, actual Mac compiler receipt, exact signed APK,
static acceptance receipt, and an independently verified upgrade and runtime
selection. The model is the fixed Orvena-4B Q4_K_M profile with context 8192 and
four threads. NPU and GPU are separate explicitly selected axes.

The helper is a separate host package. Its manifest does not change the source
identity of an already built APK. Complete signature/static validation precedes
installation; successful installation and configuration readback precede this
package's `prepare` stage. A predicted SHA, incomplete source subset, install
acknowledgement or fixture receipt cannot replace those inputs.

Keep real bindings, role observations, upgrade receipts, selector receipts and
task evidence outside the source tree. Issue the private binding using actual
observed values:

```sh
python -B candidate/prepare_binding.py \
  --source "$HEPTA_SOURCE" --apk "$HEPTA_APK" \
  --mac-build-receipt "$HEPTA_BUILD_RECEIPT" \
  --source-integration-manifest "$HEPTA_SOURCE_INVENTORY" \
  --static-acceptance "$HEPTA_STATIC_RECEIPT" \
  --runtime-config "$HEPTA_RUNTIME_CONFIG" \
  --role-identities "$HEPTA_ROLE_IDENTITIES" \
  --observations "$HEPTA_ROLE_OBSERVATIONS" --app-uid "$HEPTA_APP_UID" \
  --serial "$HEPTA_SERIAL" --logical-display-id 0 \
  --physical-display-id "$HEPTA_PHYSICAL_DISPLAY" \
  --input-width "$HEPTA_WIDTH" --input-height "$HEPTA_HEIGHT" \
  --compute npu --qualification-id "$HEPTA_QUALIFICATION_ID" \
  --output "$HEPTA_NEW_BINDING_DIR"
```

The serial and display values remain in that private binding. The host binding
does not add fields to the Android scope file. Host-only `plan` and `prepare`
require the full package-manifest SHA and private binding SHA. All phone stages
also require an existing absolute ADB executable, an explicit loopback endpoint,
the matching serial, `--execute` and `--exclusive-idle-window`.

```sh
python -B candidate/orvena_qualification.py \
  --package-sha256 "$HEPTA_PACKAGE_SHA" \
  --qualification-binding "$HEPTA_BINDING" \
  --qualification-binding-sha256 "$HEPTA_BINDING_SHA" --axis npu plan

python -B candidate/orvena_qualification.py \
  --package-sha256 "$HEPTA_PACKAGE_SHA" \
  --qualification-binding "$HEPTA_BINDING" \
  --qualification-binding-sha256 "$HEPTA_BINDING_SHA" --axis npu \
  prepare --selection-result "$HEPTA_SELECTION_RESULT" \
  --selection-result-sha256 "$HEPTA_SELECTION_SHA" \
  --upgrade-proof "$HEPTA_UPGRADE_RESULT" --upgrade-proof-sha256 "$HEPTA_UPGRADE_SHA" \
  --upgrade-helper "$HEPTA_UPGRADE_HELPER" --selector-helper "$HEPTA_SELECTOR_HELPER" \
  --output "$HEPTA_NEW_PREPARED_DIR"
```

Obtain `HEPTA_PACKAGE_SHA` by hashing `candidate/PACKAGE-MANIFEST.json`. The
runtime verifies every manifest member and rejects unlisted files. Subsequent
stage arguments are described by
`python -B candidate/orvena_qualification.py --help` and each stage's `--help`.
Every output directory and reservation is create-only. A changed helper,
manifest, binding or target requires a new preparation; existing plans and
receipts are never edited or silently migrated.

## Execution contract

The stage order is `prepare`, `scope-install`, `probe`, `probe-review`, ordinary
prefill/Start/goal/review, explicit `core9`, then `scope-remove` at verified idle.
Each step consumes the exact prior receipt SHA. There is no automatic sequence,
retry, backend fallback, weight import or installation in this package.

During `scope-install`, the initial idle comparison checks the APK, application
UID, parent process, accessibility service, runtime configuration, clean journals
and absence of native workers before requiring the new scope file. An absent
scope is created once. An identical existing scope is verified without a write.
A foreign scope is rejected. Full scope validation is mandatory after creation
and throughout subsequent stages; the caller's scoped plan is never modified.
Any other state change prevents a successful activation receipt.

Offline execution validates the private device binding before any radio setup,
retains a private binding snapshot, and binds its restoration journal to that
snapshot and serial. Restoration uses the original journal and cannot select a
different device. Preserve the exact wrapper and private evidence used by an
interrupted run; a new package does not migrate an older restoration journal.

The exclusive idle window is an operator coordination requirement. These
helpers do not acquire a shared `flock` or a cross-session device owner lock.
Only one operator or orchestration session may run an upgrade, selector, probe,
ordinary task or core suite on the device at a time. Stage reservations and the
application's inference slot do not provide a global host lock. The supervisor
owns only its offline-wrapper child and never infers phone cleanup from host
process exit.

Successful qualification still requires independently verified native execution,
the unchanged goal assertions, known cleanup and radio restoration. No result in
this source package is real phone acceptance evidence.
