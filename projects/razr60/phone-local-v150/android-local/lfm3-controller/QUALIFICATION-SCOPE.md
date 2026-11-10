# Opt-in qualification application scope

This change adds a task-bound application scope for the Settings/Calculator
qualification. Daily use remains unrestricted when
`files/qualification-scope.json` is absent and no expected scope SHA is supplied.
A present file must be valid and explicitly enabled; malformed, missing-required,
or changed configuration never becomes an unrestricted task.

The scope does not change the model prompt, tool grammar, native admission,
context, goal instructions, or semantic oracle. A refusal is a terminal failure
(or cancellation/unknown cleanup where those already dominate), not completion.

## Task and UI binding

A qualification prefill supplies the original `task` and
`expected_scope_sha256` Intent extras. The ordinary **Start** button remains
`user_button`; no automatic trigger is added. The UI binds the expectation to the
exact UTF-8 OWNER hash. Editing that task, replaying a consumed scoped Start, or
restoring inconsistent saved state is rejected. The Intent's task/scope extras
are consumed once and an already-handled Intent cannot clear a pending binding.
Activity recreation restores the pending/consumed binding from saved state.

A genuinely new ordinary launcher Intent or new task prefill clears only the UI
binding. Explicit Stop also ends only that UI binding while requesting the
existing task stop. A scheduled/running task holds a final expectation argument
and a once-bound service scope; later Intents cannot weaken it. The existing
one-use private debug task route passes the same optional expected SHA for core
qualification; its private nonce authorization is unchanged.

Qualification launchers must always supply the expected SHA and must verify both
`expected_scope_sha256` and `actual_scope_sha256` in owner/session/result.
An absent expectation is explicitly JSON `null`, not inferred from the actual
file. A missing expected file is an error. A present scope file still applies to
an ordinary Start without an expectation, so dropping an Intent extra cannot
remove an installed restriction.

## Closed private configuration contract

The file is UTF-8 JSON, at most 16,384 bytes, a single canonical-path, app-owned,
mode-0600 regular file with one link. The parser rejects duplicate/unknown fields,
coercions, invalid UTF-8/surrogates, comments and trailing data. Its fields are:

| Field | Required value |
|---|---|
| `schema` | `hepta.qualification-scope.v1` |
| `enabled` | JSON `true`; remove the file while idle to disable it |
| `qualification_id` | 1–80 ASCII letters/digits/underscore/hyphen, first alphanumeric |
| `build_identity_sha256` | SHA-256 of the exact packaged build identity asset bytes |
| `runtime_config_sha256` | SHA-256 of exact `files/model/runtime-config.json` bytes |
| `hepta_apk_sha256` | Full installed Hepta base APK SHA-256; this contract requires the existing single-APK installation |
| `hepta_version_code` | Positive JSON integer, matching installed package and asset |
| `launcher_component` | Fully expanded PackageManager HOME component, `package/full.class` |
| `<role>_package` | Actual package for each of the four roles below |
| `<role>_uid` | Actual PackageManager application UID, a JSON integer |
| `<role>_version_code` | Actual long version code, a positive JSON integer |
| `<role>_apk_set_sha256` | APK-set digest defined below |
| `<role>_observation_sha256` | Digest of the independently retained original UI/window observation proving that role's package |

Roles are `settings`, `search`, `calculator`, and `launcher`. The first three
are fixed to `com.android.settings`, `com.android.settings.intelligence`, and
`com.motorola.cn.calculator`. Launcher must be a distinct installed package and
match the actual default HOME resolver. No guessed alias is added.
`com.motorola.cn.searchintelligence` is a different launcher-search UI and is
outside this qualification; entering it terminates the test.

The observation hashes bind the operator's independently reviewed original
proof. The app does not claim to re-read external host evidence. The config
issuer must retain those originals, reject a missing/unknown observed package,
and match them to these roles. A model label or reason cannot supply this
configuration or extend its allowlist.

## Installed identity collection and revalidation

For each role use PackageManager's `applicationInfo.uid`, `getLongVersionCode()`,
`applicationInfo.sourceDir`, paired `splitNames`/`splitSourceDirs`, and enabled
state. Hash the complete bytes of the base and every split APK. Define keys
`base` and `split:<splitName>`. Sort the keys lexicographically and hash this
UTF-8 concatenation, including each tab and final newline:

```text
base<TAB><lowercase SHA256 of full base APK><LF>
split:<name><TAB><lowercase SHA256 of that full split APK><LF>
```

There is one `base` row and zero or more sorted split rows. Do not replace the
APK-set digest with the base APK digest. The running app independently streams
these APKs at task admission and verifies the config's UID/version/full APK-set
identity. The scope loader also hashes its own installed APK and verifies the
actual loaded runtime profile/compute/context/thread configuration.

During the task, the captured config and runtime files must keep their identity
and exact bytes. PackageManager UID/version/enabled/path/split membership and
captured APK stat identity must remain unchanged; the APK contents are not
rehashed before every click. Installed package files are read through the
platform's read-only package paths, not model-selected paths. HOME must still
resolve to the configured component. Removal/replacement of a scope file cannot
downgrade its captured task. Creating a scope file during an unrestricted task
also ends that old mode rather than silently changing it.

## Pre-dispatch enforcement

The actual accessibility executor checks the fresh `getRootInActiveWindow()`
root and its own API window before any action. A restricted task requires a
known, visible, active application window on the default display, with matching
root/window IDs and a scoped root package. The package/window must still match
that action's bound observation.

`open` additionally requires a scoped target and an explicit launch component
that resolves to that same package. `click`, `type` and `scroll` require the
actual refreshed node package/window to match the fresh root, visibility and
original node signature; checks occur before the actual `performAction` call.
Unknown identities and coordinate-only clicks are refused in restricted mode.
`wait`, `find_app`, `done`, `back` and `home` do not escape a refusal. Navigation is
allowed only from an already known in-scope window; it is not a recovery action
from an out-of-scope app.

Android does not make a root observation and an effect on another app atomic.
An allowed node may itself navigate to another package. The guard preserves the
one action already dispatched, checks the subsequent actual observation, and
terminates before any interaction in the foreign package. It does not claim to
predict every cross-app side effect of an allowed application's own handler.
Tests must keep any such interruption as failure rather than model completion.

## Evidence

The owner, session and result include expected and actual scope hashes, including
explicit nulls. Task evidence includes `scope-binding.json`, the raw private
`qualification-scope.json`, the exact `build-identity.json` asset, and captured
`scope-runtime-config.json` when available. Each observed frame has a separate
`scope-observation-<id>.json` with the actual observation and scope outcome.
Each action receipt adds `qualification_scope`, containing the task/config/build
binding, fresh root/node IDs, decision and sticky refusal. Original model output,
model-run/action binding, native receipts, completion and cleanup paths remain.
Scope evidence is a restriction/admission proof, not semantic goal evidence.
A future grader may use it only to downgrade an otherwise qualified result.

Action callbacks capture their own Bound before posting to the service thread.
Queued dispatch verifies that exact object is still current. Delayed callbacks
never look up a replacement task's scope; a retired/cancelled callback is rejected
while preserving any effect already dispatched. Delayed text readback skips a
retired/cancelled node and records an unavailable readback without retrying.

After the potentially blocking model `endTask()` returns, the controller checks
the same scope/config again before publishing completion. Scope or runtime
changes during model close therefore cannot retain `model_reported_done`.
Unknown native cleanup still takes precedence and keeps the session/lease
blocked; owner Stop keeps its existing cancellation classification. No previous
task or action is resumed.

## Actual build identity

`tools/build_identity.py::actual_build_identity(root, receipt)` first compares
the complete current `source_inputs(root)` list with the actual Mac compiler
receipt. It then verifies the version-bearing manifest bytes match that list and
emits deterministic UTF-8 `hepta.actual-build-inputs.v1` JSON with version code
and the full source-input map. Assembly packages those exact bytes at
`assets/hepta-build-identity.json`, refuses a preexisting identity asset, verifies
the signed APK's asset bytes, and records the asset SHA in static acceptance.

The covered inputs are exactly the existing `source_inputs` contract: all Java
sources, resource XML, Android manifest/build/assembly/verification/profile
scripts explicitly listed there, native C/H/INC/Python/JSON, and the explicitly
listed pinned visual provenance. The generated asset is excluded to avoid a
hash cycle. The root historical `SOURCE-MANIFEST.json` is neither read nor used
as the current source identity. Pinned subordinate provenance manifests remain
ordinary source inputs and are not a substitute for current Java hashes.

The 255-file ec9 review cache lacks 52 visual provenance inputs from the 157-entry
historical Mac receipt. It is a patch/review baseline, not a complete build tree.
The identity function correctly refuses incomplete input trees. The final v32
asset must be generated from the complete v32 source after the actual v32 Mac
receipt matches it; neither an old v30/v31 manifest nor this host test fixture is
that artifact. Version bump and complete build/deploy belong to final integration.

## Host regression commands and limits

```sh
python3 tests/qualification-scope/run_host_tests.py --source . --output /new/host-output --release8
python3 -m unittest discover -s tools -p test_qualification_scope_build.py -v
```

The regular `tools/run_host_checks.py` gate invokes the scope tests with
`--release8`; it does not weaken the existing Java 8 gate. A developer on a
stripped JDK may explicitly omit that option for syntax/class-target-only host
checks, which must be reported with that limitation.

The harness executes full production `QualificationScope`,
`QualificationScopeConfig`, `MobiMindPrivateFiles` and `LocalTaskController`, and
SHA-binds extracted production service dispatch, UI binding and session methods.
Android IO/effects, PackageManager, synthetic screen and model callbacks are
explicit fixtures. Tests count actual production effect API calls. They cover
zero-dispatch refusals, positive dispatch controls, immutable expected-SHA
transmission, terminal/cleanup handling, actual build-asset function and actual
ZIP assembly block. They prove no Android runtime, native model, acceleration,
phone permissions, phone effects, platform fsync, or physical race guarantee.

After qualification, the operator must stop/await idle with known cleanup,
remove the private scope file, start a fresh ordinary UI session, and verify no
task is active. Do not leave the qualification restriction enabled for daily use.
