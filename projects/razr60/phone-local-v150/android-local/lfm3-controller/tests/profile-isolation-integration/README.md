# Explicit managed-profile Ctrip integration

This candidate adds an explicit managed profile of user 0 and native Ctrip identity path. It does not qualify arbitrary Apps.

The UI reads a privileged profile catalogue without launching an App. The saved target contains user ID/serial, parent/type, full UID, launcher, version, APK hashes and signers. The user 0 controller peer UID stays independent. Changed identities fail closed; there is no personal-copy fallback.

Before launch the dedicated profile must have no activity/recents tasks. An owned root/display and explicit-user launch bind the new leaf using actual parallel child user IDs, live Binder identity and target-user package manager. Accessibility's public parcel task ID is matched against that live broker leaf; parent-rewritten accessibility UIDs are never substituted for full target UIDs. Historical frame provenance is kept separately from fresh per-effect authority.

Only exact owned tasks are retired. Cleanup requires live and recents absence, matching user serial/full UID/token generation and independently observed display absence. Unknown cleanup disables dispatch and retains broker/display custody. Unexpected process or system death may still destroy a VD and remains cleanup unknown.

Legacy v1 keeps 128 receipts; profile v2 keeps 512 with one reserved close slot and no eviction. Historical proof capacity uses the same profile limit without renewing expired live authority.

## Host validation scope

HOST-VALIDATION.json records the necessary gates and original receipt hashes. Cases overlap and are not business success rates. Actual production logic is executed with controlled platform/transport boundaries as stated. The Parcel test is a host serializer test, not Android framework qualification. Complete 154-file Android Java precompile passed before the final two-file quota delta; exact final Android build/signing outputs are recorded separately.

No phone operations or new App business qualification are asserted here. Final profile launch, actual window identity, action, main-display isolation and cleanup require separate phone verification. Native runtime/model files and Android manifest are unchanged; no DPC receiver or INTERNET permission is added.

Portable runners live in tests/profile-identity, tests/profile-broker, tests/profile-observation and tests/background-session. Use their explicit Java home/output arguments; baseline red inputs are optional explicit parameters. Private captures and operator paths are not included.
