# Scoped application catalogue

The v34 phone traces exposed a mismatch between planning and dispatch. A scoped task could see unrelated installed applications in its initial catalogue, select them through the constrained `open` grammar, and then be rejected by the independent scope gate. The ordered navigation case had already reached its requested final Settings page before the model chose an unrelated application.

`HeptaAccessibilityService.appCatalogue` now captures the task-bound scope and filters the installed launcher snapshot before owner ranking, fingerprinting and pagination. Both the initial catalogue and subsequent `find_app` pages use that same immutable snapshot. The controller derives model-visible labels, `open_allowed_packages` and its existing grammar from those pages, so they share the permitted domain. A task without a qualification scope retains its full installed-app catalogue.

The snapshot is published only while the same scope lease is current. Missing, changed or retired scope bindings fail before publication. The existing fresh dispatch checks, package and window checks, sticky refusals, model format checks and business-goal assertions remain in place. A producer that ignores the constrained grammar is still rejected before dispatch.

## Verification

The qualification fixture now extracts the actual production catalogue method instead of substituting a test implementation. Six added regression cases cover filtering before ranking and pagination; excluded queries and labels; immutable search results; unrestricted pagination; invalid scope bindings; and both rounds of the actual controller prompt/grammar around an empty `find_app` result.

The compiled unpatched service fails the new first-page test. With the patch, the Java 8 API release gate and all 131 scope tests pass on JDK 17: 77 production scope/controller cases, 28 private-root cases and 26 APK split cases. The preexisting adversarial-output test now explicitly injects an installed but out-of-domain app label and checks bounded rejection with no dispatched effects.

Run from the controller source directory:

```sh
python3 tests/qualification-scope/run_host_tests.py --source . --output /absolute/new/output --release8
```

These are host checks with explicit Android IO and model fakes. They do not qualify model accuracy, Android device behavior, background-display isolation or a release. No APK version, runtime/model selection or phone state changes are part of this patch.
