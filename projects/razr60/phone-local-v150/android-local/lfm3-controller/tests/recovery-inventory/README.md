# Recovery inventory host fault test

This gate compiles the current production RecoveryProcessInventory.java and
RecoveryQuiescence.java, then executes 20 controlled fault scenarios. It does not
copy or reimplement the census algorithm.

The nine Android API shims are compile-time/runtime fixtures only. The Os shim
always throws for real operating-system reads; the tests inject the production
package-private Proc seam. The main-thread and interrupted-await checks reject
before any procfs call. No test launches a child model, calls ADB, touches a phone,
reads real /proc, or writes production source.

Run the ordinary tools unittest discovery, or:

    python3 -m unittest discover -s tools -p test_recovery_inventory.py -v

JDK 17 is the qualification environment. Compilation always uses
javac --release 8 -Xlint:all -Werror and has no source/target fallback or skip.
HEPTA_TEST_JAVAC and HEPTA_TEST_JAVA may select explicit JDK executable paths.
All compiler output goes to a TemporaryDirectory outside the source tree.

Covered failures include extra same-UID processes, unknown ownership,
unreadable identity, UID/PID/start-ticks/directory changes, incomplete or duplicate
procfs fields, incomplete enumeration, main-thread use and interruption.
A known foreign directory owner is skipped without reading its status/cmdline.

Passing this gate is not proof that Android exposes every same-UID process,
not proof of an old worker's exit, and not a phone recovery qualification.
Actual Android compilation and device visibility/lifecycle checks remain separate.
