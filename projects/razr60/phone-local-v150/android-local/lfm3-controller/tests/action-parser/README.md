# ActionDecision host verification

ActionDecision.java is a Java 8, JDK-only parser. It does not perform an
Android action or access files, shell commands, services, models, or networks.
The controller remains responsible for the exact fresh observation, foreground
package, approved target app, current node, coordinates, and action permission.

Run with an existing JDK 9 or newer, retaining a new evidence directory:

    python3 run_host_tests.py --source /absolute/path/ActionDecision.java --out /absolute/new/result-directory

The runner uses javac with --release 8, or java -m jdk.compiler/com.sun.tools.javac.Main when
the compiler module exists but the javac launcher is absent. It checks class
file version 52 and retains compiler output, test output, Java version and
source hashes. It never installs dependencies or accesses a phone.

The Java test itself can also be compiled and run with only the JDK:

    javac --release 8 -encoding UTF-8 -Xlint:all -Werror -d classes ActionDecision.java ActionDecisionHostTest.java
    java -cp classes ActionDecisionHostTest

The tests cover all nine actions, including bounded read-only `find_app`, both click forms, all scroll directions and
terminal statuses, Chinese/emoji/newline preservation, unused-field defaults,
exact byte and code-point boundaries, escaped surrogate pairs, duplicate decoded
keys, mixed click forms, missing/extra fields, malformed/trailing JSON, forbidden
value types, canonical integer limits, incomplete output, and 256 deterministic
malformed inputs. Long package segments are included because recursive regex
matching can overflow its stack even within the allowed JSON byte bound; the
implementation validates the equivalent package pattern by a bounded loop.

String "characters" in the reason/summary limits means Unicode code points,
while text and complete-output limits use UTF-8 bytes. Observation hex may use
either case and is preserved exactly; the controller compares it with its
actual snapshot. Package names match the following pattern:

    [A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+

Node IDs match n followed by 1..5 ASCII digits. Empty type replacement is
allowed; NUL in type text is rejected. Parse success alone never proves task
success.

`find_app` requires `query` and `offset`. Empty query browses installed apps;
the query is at most 64 Unicode scalar values with no NUL, and offset is a
canonical integer in 0..4095. It rejects action fields such as node_id, Intent,
coordinates or type text. `tests/AppCatalogueHostTest.java` separately exercises
the installed snapshot, ranking/paging and parser/policy/grammar transition from
an omitted app to an observed launchable result.
