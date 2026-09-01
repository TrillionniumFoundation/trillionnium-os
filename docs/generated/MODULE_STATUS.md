# Module Status

<!-- GENERATED. DO NOT EDIT. -->

| Module | Name | Plane | Primary | Backup | Maturity | Dependencies | State owned |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `MOD-PROTOCOL` | protocol and identity | `shared-contract` | `team-protocol` | `team-architecture` | `L1_SOURCE` | none | none |
| `MOD-BROKER` | connection broker and ingress | `execution` | `team-broker` | `team-transport` | `SOURCE_MUX_PENDING_EVIDENCE` | MOD-PROTOCOL | broker request audit |
| `MOD-TRANSPORT` | bounded transport carrier | `execution` | `team-transport` | `team-execution-core` | `SOURCE_BOUNDED_SEGMENTED_PENDING_EVIDENCE` | MOD-PROTOCOL, MOD-STREAM | transport delivery journal |
| `MOD-EXECUTION-CORE` | execution core | `execution` | `team-execution-core` | `team-runtime` | `L1_SOURCE` | MOD-PROTOCOL, MOD-TURN-ENGINE, MOD-JOB-RUNTIME, MOD-EVENT-STORE | host correlation state |
| `MOD-PROVIDER` | provider process and session | `semantic-adapter` | `team-provider` | `team-turn-engine` | `L1_SOURCE` | MOD-PROTOCOL, MOD-TURN-ENGINE, MOD-TOOL-RUNTIME | provider session epoch |
| `MOD-TURN-ENGINE` | same-turn engine | `semantic-adapter` | `team-turn-engine` | `team-provider` | `SOURCE_EVENT_DRIVEN_CANCEL_PENDING_EVIDENCE` | MOD-PROTOCOL, MOD-TOOL-RUNTIME | live turn state |
| `MOD-TOOL-RUNTIME` | direct tool and process runtime | `execution` | `team-runtime` | `team-job-runtime` | `L1_SOURCE` | MOD-PROTOCOL | live direct-call handles |
| `MOD-JOB-RUNTIME` | durable long-running jobs | `execution` | `team-job-runtime` | `team-runtime` | `SOURCE_SHARDED_START_PENDING_EVIDENCE` | MOD-PROTOCOL, MOD-EVENT-STORE | job registry; job operation journal; live job handles |
| `MOD-EVENT-STORE` | event durability and replay | `state` | `team-state-recovery` | `team-job-runtime` | `SOURCE_SEGMENTED_INDEXED_PENDING_EVIDENCE` | MOD-PROTOCOL | turn event log; event indexes; record hash chain |
| `MOD-STREAM` | stream flow control | `execution` | `team-stream` | `team-transport` | `L1_SOURCE` | MOD-PROTOCOL | delivery window state |
| `MOD-GLOBAL-CONTROL` | global mechanical control plane | `control` | `team-global-control` | `team-architecture` | `PLANNED_SHADOW_SOURCE_COMPLETE_PENDING_CI` | MOD-PROTOCOL, MOD-TELEMETRY | control epoch; module leases; placement plan |
| `MOD-TELEMETRY` | telemetry and objective projection | `state` | `team-telemetry` | `team-performance` | `PLANNED_READ_MODEL_COST_CURVE_SOURCE_COMPLETE_PENDING_CI` | MOD-PROTOCOL | metric windows; objective projections |
| `MOD-ROOTLINUX` | Root Linux integration | `platform` | `team-rootlinux` | `team-android` | `SOURCE_PROFILE_L2_PENDING` | MOD-EXECUTION-CORE, MOD-PROVIDER, MOD-GLOBAL-CONTROL | install manifest projection; service runtime state |
| `MOD-ANDROID` | Android product and SELinux integration | `platform` | `team-android` | `team-rootlinux` | `SOURCE_OVERLAY_L3_PENDING` | MOD-ROOTLINUX, MOD-BROKER, MOD-TRANSPORT | Android service graph; SELinux policy projection |
| `MOD-ADB` | ordinary ADB transport | `platform` | `team-adb` | `team-runtime` | `L1_SOURCE_L4_PENDING` | MOD-TOOL-RUNTIME, MOD-ROOTLINUX | ADB relay epoch; transport observations |
| `MOD-EVIDENCE` | qualification and release evidence | `evidence` | `team-evidence` | `team-security-release` | `L1_SOURCE` | MOD-PROTOCOL | evidence index; promotion records |
