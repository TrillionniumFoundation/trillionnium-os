# Product Profile Status

<!-- GENERATED. DO NOT EDIT. -->

- Default profile: `owner-open-core`

| Profile | Status | Default | Activation | Modules | Cargo components | Offered capabilities | Blocked capabilities | Claim ceiling |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `owner-open-core` | `ACTIVE_DEFAULT` | `true` | `true` | MOD-PROTOCOL, MOD-BROKER, MOD-TRANSPORT, MOD-EXECUTION-CORE, MOD-PROVIDER, MOD-TURN-ENGINE, MOD-TOOL-RUNTIME, MOD-JOB-RUNTIME, MOD-EVENT-STORE, MOD-STREAM, MOD-ROOTLINUX, MOD-ANDROID, MOD-ADB, MOD-EVIDENCE | apps/trillionnium-owner-open-host, crates/trillionnium-owner-open-call-registry, crates/trillionnium-owner-open-event-store, crates/trillionnium-owner-open-job-registry, crates/trillionnium-owner-open-job-runtime, crates/trillionnium-owner-open-provider-jsonl, crates/trillionnium-owner-open-stream-window, crates/trillionnium-owner-open-tool-bridge, crates/trillionnium-owner-open-turn-loop, crates/trillionnium-owner-open-types, crates/trillionnium-owner-open-runtime | shell.exec, adb.exec, job.pipe, job.pty, stream.resume, event.replay | none | SOURCE_PROFILE_SELECTION_ONLY_UNTIL_L2_L4_EVIDENCE |
| `sealed-typed-android-extensions` | `SEALED_OPTIONAL` | `false` | `false` | none | none | none | system-api.open-uri, system-api.launch-package, accessibility.snapshot, accessibility.mutate | RETAINED_HISTORY_AND_SOURCE_ARCHAEOLOGY_ONLY |

## Selected source dependencies and explicit planned edges

This graph is a source-selection projection, not an installed service graph.
Every selected module dependency is either selected or explicitly deferred.
Deferral never supplies an optional runtime dependency, lease substitute or
controller activation; its named target-qualification gap must remain unresolved.

| Profile | Source module | Dependency | Selection | Blocking gap |
| --- | --- | --- | --- | --- |
| `owner-open-core` | `MOD-ADB` | `MOD-ROOTLINUX` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-ADB` | `MOD-TOOL-RUNTIME` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-ANDROID` | `MOD-BROKER` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-ANDROID` | `MOD-ROOTLINUX` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-ANDROID` | `MOD-TRANSPORT` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-BROKER` | `MOD-PROTOCOL` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-EVENT-STORE` | `MOD-PROTOCOL` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-EVIDENCE` | `MOD-PROTOCOL` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-EXECUTION-CORE` | `MOD-EVENT-STORE` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-EXECUTION-CORE` | `MOD-JOB-RUNTIME` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-EXECUTION-CORE` | `MOD-PROTOCOL` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-EXECUTION-CORE` | `MOD-TURN-ENGINE` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-JOB-RUNTIME` | `MOD-EVENT-STORE` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-JOB-RUNTIME` | `MOD-PROTOCOL` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-PROVIDER` | `MOD-PROTOCOL` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-PROVIDER` | `MOD-TOOL-RUNTIME` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-PROVIDER` | `MOD-TURN-ENGINE` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-ROOTLINUX` | `MOD-EXECUTION-CORE` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-ROOTLINUX` | `MOD-GLOBAL-CONTROL` | `PLANNED_ONLY` | `GAP-ROOTLINUX-PLACEMENT-001` |
| `owner-open-core` | `MOD-ROOTLINUX` | `MOD-PROVIDER` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-STREAM` | `MOD-PROTOCOL` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-TOOL-RUNTIME` | `MOD-PROTOCOL` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-TRANSPORT` | `MOD-PROTOCOL` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-TRANSPORT` | `MOD-STREAM` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-TURN-ENGINE` | `MOD-PROTOCOL` | `SELECTED_SOURCE` | `none` |
| `owner-open-core` | `MOD-TURN-ENGINE` | `MOD-TOOL-RUNTIME` | `SELECTED_SOURCE` | `none` |

A sealed profile contributes no current product capability. Source presence or
a successful build cannot activate it without a reviewed catalog transition and
the evidence named by its blockers.
