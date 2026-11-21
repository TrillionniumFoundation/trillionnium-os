# Virtual-display power groups

Android 16 can put separate own-display virtual displays in the same power
group because the framework indexes those groups by their logical group name,
which may be null. A display name or unique id does not make that group unique.

The helper binds its created display id, unique id, group, owner, flags, and
original deadline. Its complete `includeDisabled` census requires physical
displays 0 and 1 to exist in different groups from the created display. All
other displays must be virtual. Multiple virtual displays may share the
selected group, and `group_members` reports the actual validated membership.

A three-argument `newWakeLock` selects the created display, while Android applies
the screen-bright vote to its group. This can keep virtual peers awake. It grants
no input, task, or display-cleanup authority over those peers. The helper never
calls `wakeUp` or `goToSleep`, never requests `ACQUIRE_CAUSES_WAKEUP` or
`ON_AFTER_RELEASE`, and releases only the token it acquired. Physical display,
task, focus, and cleanup checks remain separate requirements.

## Host verification

Use JDK 17 and a fresh output directory:

```sh
mkdir host-classes
javac --release 8 -Xlint:all -Werror -encoding UTF-8 -d host-classes OwnedDisplayPowerLease.java OwnedDisplayPowerLeaseTest.java
java -cp host-classes org.trillionnium.hepta.displayprobe.OwnedDisplayPowerLeaseTest
```

The expected final line is:

```text
RESULT cases=30 checks=122 all_pass=true phone_operations=0
```

Tests cover peers joining and leaving, creation readiness, complete typed
membership, rejection of physical or unknown peers, immutable lifetime identity,
unchanged deadlines, and independent release of two tokens sharing a group.

## Android compilation

Compile `VirtualDisplayProbe.java` and `OwnedDisplayPowerLease.java` with JDK 17,
`--release 8`, and Android SDK 34's `android.jar` as the classpath. Package the
resulting class files in a JAR, then run the SDK build-tools 34.0.0 D8 with
`--release --min-api 30 --lib android.jar`. Keep compiler and D8 output, source
hashes, and the resulting DEX hash. This host build does not launch or qualify
the helper on a phone.

Framework references:

- https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/services/core/java/com/android/server/display/LogicalDisplayMapper.java
- https://android.googlesource.com/platform/frameworks/base/+/refs/heads/android16-release/services/core/java/com/android/server/power/PowerManagerService.java
