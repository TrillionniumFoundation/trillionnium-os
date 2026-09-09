# Product Profile Status

<!-- GENERATED. DO NOT EDIT. -->

- Default profile: `owner-open-core`

| Profile | Status | Default | Activation | Modules | Cargo components | Offered capabilities | Blocked capabilities | Claim ceiling |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `owner-open-core` | `ACTIVE_DEFAULT` | `true` | `true` | MOD-PROTOCOL, MOD-BROKER, MOD-TRANSPORT, MOD-EXECUTION-CORE, MOD-PROVIDER, MOD-TURN-ENGINE, MOD-TOOL-RUNTIME, MOD-JOB-RUNTIME, MOD-EVENT-STORE, MOD-STREAM, MOD-ROOTLINUX, MOD-ANDROID, MOD-ADB, MOD-EVIDENCE | apps/trillionnium-owner-open-host, crates/trillionnium-owner-open-call-registry, crates/trillionnium-owner-open-event-store, crates/trillionnium-owner-open-job-registry, crates/trillionnium-owner-open-job-runtime, crates/trillionnium-owner-open-provider-jsonl, crates/trillionnium-owner-open-stream-window, crates/trillionnium-owner-open-tool-bridge, crates/trillionnium-owner-open-turn-loop, crates/trillionnium-owner-open-types, crates/trillionnium-owner-open-runtime | shell.exec, adb.exec, job.pipe, job.pty, stream.resume, event.replay | none | SOURCE_PROFILE_SELECTION_ONLY_UNTIL_L2_L4_EVIDENCE |
| `sealed-typed-android-extensions` | `SEALED_OPTIONAL` | `false` | `false` | none | none | none | system-api.open-uri, system-api.launch-package, accessibility.snapshot, accessibility.mutate | RETAINED_HISTORY_AND_SOURCE_ARCHAEOLOGY_ONLY |

A sealed profile contributes no current product capability. Source presence or
a successful build cannot activate it without a reviewed catalog transition and
the evidence named by its blockers.
