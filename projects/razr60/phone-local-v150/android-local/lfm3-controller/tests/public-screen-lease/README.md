# Own-display screen lease

This gate executes the production `PublicOwnGroupScreenLease` with explicit power,
display-census and monotonic-clock ports. The 8-second timeout is a host model of
the observed device policy; it is not a claim that Android power APIs ran here.

The positive path holds the created display beyond that timeout, then releases
its exact token at the original absolute session deadline. The complete census
excludes every physical display from its power group. Multiple virtual displays
may share the group; sharing adds no input, task, or display-cleanup authority.
Negative cases cover physical groups, unknown census values, wrong identity and flags,
an already sleeping display, expiration, attempted renewal, display-id reuse,
and a real concurrent late acquire versus cleanup. Release uncertainty remains
uncertainty and never proves task cleanup or business success.

The runner also pins the exact production lifecycle and three-argument Android
API call sites. Android SDK compilation and real phone qualification remain
separate requirements. Existing scope, ownership, task, physical-display and
cleanup gates retain their assertions.

Initial readiness has a separate case group. It executes automatic UNKNOWN/OFF
to ON transitions through the production policy and extracted direct Binder
census. The deadline expression is extracted from the actual broker and is
frozen before create: the original 3-second create RPC and session expiry still
win over the 5-second upper bound. Only remaining time may be spent waiting.
The original acquire then reads ON again. Identity changes, incomplete census,
dozing, late reads, late acquire, interruption and retirement stay closed.
The updated gate runs 42 lease cases / 85 assertions and 25 initial-readiness
cases / 68 assertions. It covers virtual peers joining during creation and live
operation, truthful complete membership, and independent exact-token release.

Android 16 groups own-display requests by their logical display-group name.
Ordinary virtual displays can have the same null name, so OWN_DISPLAY_GROUP
does not guarantee one display per group. The screen-bright wake lock is
created for the owned display id but Android applies its vote to that group.
It can therefore keep virtual peers awake. The implementation never calls
wakeUp or goToSleep, never adds ACQUIRE_CAUSES_WAKEUP or ON_AFTER_RELEASE, and
releases only the token it created. The physical-display census, frozen owned
display identity, and task/display custody checks remain required.

Framework references (android16-release):
- https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/services/core/java/com/android/server/display/LogicalDisplayMapper.java
- https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/services/core/java/com/android/server/power/PowerManagerService.java
