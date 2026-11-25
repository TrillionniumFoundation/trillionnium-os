# Current profile installation checks during native tasks

This focused host test executes the actual controller's installed-verifier callback, captured bindings, post-observation branch, and post-cleanup branch. It also executes the complete production CompletionInstalledIdentity, ProfileTarget and ProfileIdentity, plus the original BackgroundSession.verifyProfileInstallation and verifyRemote methods.

The 22 cases distinguish live and post-cleanup checks, reject a missing or different native task/authorization/background, retain the complete selected profile identity comparison, and propagate transport/response/retirement failures without a catalogue fallback. The original ordinary installed check and the full catalogue check after cleanup remain exercised.

Android Context, ordinary PackageManager/APK access, catalogue I/O, broker transport/response authentication, and active-session state are explicit host ports. This test does not execute Android, authenticate an actual broker, measure device latency, prove a date selection, or qualify the two-second screenshot limit. The actual broker's unchanged identity and response checks still require Android integration testing.

Run with a complete JDK supporting --release 8:

```sh
python3 -B tests/native-profile-live-verifier/run_host.py --source /absolute/source --output /absolute/fresh-output --java-home /absolute/jdk
```

For an isolated production draft, --controller can explicitly name that one LocalTaskController.java. The result lists the real compiled files and exact verbatim fragments, source/tool hashes before and after, each process exit code, and all case results. No source or earlier output is modified. A baseline failure returns a nonzero exit and preserves the original output.
