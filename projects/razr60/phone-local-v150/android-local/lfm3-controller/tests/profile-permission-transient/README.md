# Permission transient retirement: host contract

This gate compiles the production pure Java ownership policy and permission-chain verifier with Java `--release 8`. It runs sixteen boundary cases against an authored, complete synthetic activity hierarchy. The Android package-manager and task-organizer adapters are not compiled by this gate; the Android build and device qualification remain separate requirements.

## Current product contract

A verified same-user system PermissionController activity is a transient in the already owned task. It does not become the target application's business observation. `observe` and `window` return the explicit `PROFILE_PERMISSION_SETUP_REQUIRED` refusal; they never return a target business window for this activity. No permission grant, denial, input, activity launch, task migration, or main-display repair is authorized by this proof.

Normal retirement may use a fresh in-process proof to remove the exact retained owned-leaf token. The proof requires the original user, root, leaf, actual tokens, base/underlying target and target UID; the root cookie; the complete `REQUEST_PERMISSIONS` caller and `resultTo` chain; and the exact configured system PermissionController package, APEX path, APK digest, signer, UID, version, installed/enabled and system/privileged flags. Production samples package-manager identity and task state on both sides of the existing bounded activity-dump read. Its existing global activity/recents guards and subsequent root/absence checks still apply.

First claim still requires the actual launch cookie and proof that the leaf ID did not exist before launch. After claim, activity cookies may disappear or change as the app navigates; the retained actual Binder plus exact task ID, user, parent and display remain mandatory. The retained leaf is never cleared or replaced, including after disappearance or refusal. A PC-to-business transition may change top activity and activity count without replacing this retained identity. Root-cookie, full-UID, installation, component, unique-child, global-snapshot and recents checks remain required.

This long-lived identity rule does not relax short-lived proof stability. `ProfilePermissionTransient.sameTaskInfo` still compares all fields, including the cookie list, across the two-sided read and before use. A newly acquired proof may start with an empty cookie list on a previously claimed leaf; a cookie-list change during that same proof window is refused. No serialized diagnostic or proof JSON grants authority.

Only a consistent root-and-leaf PC pair can enter the permission-proof path. A PC-named leaf below an ordinary target root retains the upstream `PROFILE_NEW_LEAF_NOT_PROVEN` refusal and its false `top_package_matches` diagnostic. A paired PC with no proof provider returns `PROFILE_PERMISSION_PROOF_UNAVAILABLE`; it does not return setup-required, claim a leaf or remove anything. `PROFILE_PERMISSION_SETUP_REQUIRED` is emitted only after complete typed proof validation.

The upstream `last_leaf_validation` and broker diagnostics are retained. Verified PC validation keeps the actual target-top checks false and adds explicit retirement-only/no-business/no-input fields. A failure before the full leaf validator runs may leave the last diagnostic record unchanged with its older timestamp. That record describes the last completed validation, not a fresh success or authority for the failed operation.

The `permission_transient` retirement evidence, when present, uses `hepta.profile-permission-transient.v1`. Its `business_observation_allowed`, `permission_input_allowed` and `serialized_evidence_is_authority` fields are false. It is optional evidence for this one observed cleanup path, not a new requirement for ordinary target-only retirement and not a durable authority that can be reconstructed from JSON.

The proof expires after 2,000 ms measured from acquisition start, including the reads. Unknown, changed, stale or incomplete evidence is refused; custody is retained when safe cleanup cannot be proved. Host timing does not establish device timing. Device package-manager reflection and the two-sided hashing/dump budget need actual qualification; a slow or failed read must not cause a deadline, identity or ownership rule to be relaxed.

`com.motorola.deviceguard/.permission.activity.ClipboardDialogActivity` on another root or on display 0 is explicitly outside this contract. The negative test retains that activity in the complete hierarchy and rejects it. This change cannot prevent or repair OEM global UI appearing on the main display.

## Finishing records and TaskInfo counts

The complete raw activity chain remains bounded and every record still passes user, task, token, ordinal, package, process-UID, root and foreign-activity checks, including finishing records. The count and base corresponding to TaskInfo are taken only from non-finishing records. This matches Android 16 TaskInfoHelper, which skips finishing activities before counting or selecting baseActivity:
https://github.com/aosp-mirror/platform_frameworks_base/blob/android-16.0.0_r1/services/core/java/com/android/server/wm/ActivityTaskSupervisor.java

Four additional cases retain the original twelve and exercise a synthetic finishing Splash tail below Home and a new PermissionController top; wrong raw-record identities; INITIALIZING or absent permission process; and unchanged observe/window refusal and exact owned retirement. The state and process guards are unchanged. A proof still grants neither business observation nor permission input.

These lifecycle variants and all TaskInfo counts are authored test inputs. A historical broker refusal did not persist its internal numActivities or activity dump; the test does not claim to reproduce those missing historical values. Existing failures remain unchanged, and no permission is granted, denied or automatically handled by this change.

## Two separate evidence classes

`fixtures/synthetic-activities.txt` is hand-authored test data, not a captured device log. Its main display contains only an invented `com.example.viewer` task. Its other display contains invented root/leaf and activity/process tokens. It includes only the fields needed to exercise the production complete-hierarchy verifier; it has no copied main-screen task inventory, private application paths, display configuration, account content or device log tail. Package/component/APEX identity constants intentionally match the narrow production contract.

The default gate always compiles and runs the synthetic positive and boundary cases. The cases cover exact ownership and system identity, caller/action/result-to/user mismatches, mixed or incomplete chains, foreign profile activity on the main display, enumerated finishing/exiting suffixes, token/cookie/freshness binding, explicit business-window refusal, cancellation, and safe owned retirement with negative removal assertions.

An optional `--real-dump` argument adds a second run of the same cases on one previously saved, unchanged actual dump. The runner requires exactly 91,980 bytes and SHA-256 `6e945458e4af25724f189ff477ebb4ab19a58099762d3d6827c3d42728c4d2fb`. That private file must be outside the source tree and is never copied into it. The production verifier receives the original complete text for the initial positive. Only the later coordinator fixtures remap IDs into synthetic `TaskInfo` fixtures. The result labels the dump as actual saved bytes while still marking all `TaskInfo`/clock/framework objects as synthetic. It is a host replay, not a new phone test.

Do not add that private dump, screenshots, raw user/device logs, host result directories or real private paths to the public source manifest. Only the authored fixture, this document, the Java test and Python runner belong in this directory. Actual and synthetic test claims must remain distinct.

## Running the gate

Use a complete JDK containing `javac`; the runner does not substitute a runtime-only compiler or lower the release target.

```sh
python3 tests/profile-permission-transient/run_host.py \
  --source "$SOURCE_ROOT" --java-home "$TEST_JDK" --output "$NEW_RESULT_DIRECTORY"
```

For the additional private replay, append `--real-dump "$PRIVATE_SAVED_DUMP"`. The result directory must be new. A supplied private replay must pass; it cannot substitute for or skip the synthetic gate. `RESULT.json` records SHA-256 for every compiled production/test input, this runner, the synthetic fixture and this document, as well as separate stage output digests and the exact private fixture digest when requested. Changed inputs fail the run.

The normal canonical `tools/run_host_checks.py` path invokes this gate using the public synthetic fixture. Its original stages and the native suites remain required. Five existing profile-suite compile lists also include the new production class. Their original cases, assertions, failure behavior and ordering remain unchanged; none is replaced by this gate.

## Qualification and rollback

Before a phone rollout, preserve the ordinary canonical gates, compile all Android adapters, verify the actual signed APK and source input manifest, and independently qualify ordinary background recovery/retirement with strict main-display invariants. This host gate alone does not qualify permission interaction or any business workflow.

A regression must retain the failed task/cleanup evidence. A rollback, if independently authorized and safe for the current device state, restores the exact prior reviewed artifact and its source manifest through the existing install/recovery flow. It must not clear sessions or leases, rewrite failures, change the current task identity, or bypass a blocked cleanup to make a rollback appear successful.
