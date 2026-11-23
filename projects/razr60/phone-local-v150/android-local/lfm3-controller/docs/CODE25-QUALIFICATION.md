# Code25: private GPU kernel cache and observed search navigation

## Changes

For an explicit GPU request, LocalModelEngine configures GGML_OPENCL_KERNEL_CACHE_DIR in the native child's environment to the fixed hepta-opencl-kernels directory under Context.getCacheDir(). The path must remain a canonical direct child of the app cache. The existing private-directory helper checks canonical identity, directory type and app ownership and creates or changes the directory to mode 0700. The request receipt records opencl_kernel_cache_directory.

NPU requests do not enter this cache setup. HOME, TMPDIR, the application process environment and the native runtime binaries are unchanged. Directory setup failure is a preflight failure; it does not silently select a different backend. A recorded path establishes configuration only. A second real GPU request must independently demonstrate a cache hit before cache effectiveness or a speedup can be claimed. Android may evict cache contents, so every GPU request prepares the same bounded directory again.

The controller also receives one general instruction: matching text in a page's search field or result list does not prove that the target page has been entered; when entry is required, select the corresponding result and observe the resulting page. This rule contains no application, package or test-case identifier. Existing action validation and independent goal assertions still decide what was actually achieved.

## Preserved boundaries

The package remains org.trillionnium.hepta.local, with versionCode 25 and versionName 0.25.0-local-gpu-cache-verified-navigation. Code24's readable recorded action history and consistent eligible action domain are retained. The configured local model, native runtime, model integrity checks, no-network permission boundary, cancellation, process ownership, recovery, observation freshness and strict action parsing are retained. Installation does not change the selected model or import weights. Separate visual diagnostics remain model-only.

This change does not implement a persistent worker, reuse a model handle or retain KV state between requests. Model-reported completion remains separate from independently verified phone-task completion. Raw device evidence and credentials are excluded from this source snapshot.

## Qualification and evidence identities

The prior exact public Code24 source passed 70 host checks and Android compilation. Code24 was not installed for phone testing and has no phone qualification. Its source, host report and build artifacts remain separate historical evidence; they do not qualify Code25.

At this Code25 source freeze, fresh exact-source host checks, Android compilation/assembly, exact installed APK identity, real backend evidence, a second GPU cache-hit observation, independent phone-task predicates and lifecycle/thermal testing are pending. Historical HOST-CHECKS.json and host-evidence members are preserved unchanged. No host assertion, phone goal predicate or result flag is weakened to accept this candidate.
