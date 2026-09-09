# Effect Lifecycle

<!-- GENERATED. DO NOT EDIT. -->

- Schema: `org.trillionnium.effect-lifecycle.v1`
- Status: `SOURCE_MODEL_PENDING_TARGET_EVIDENCE`
- Claim ceiling: `L1_MACHINE_MODEL_ONLY_NO_INSTALLED_TARGET_DEVICE_FAULT_OR_RELEASE_CLAIM`
- Automatic redispatch: `false`
- States: `15`
- Transitions: `27`
- Crash cuts: `13`

## States

| State | Phase | Durable | Effect may have started | Outcome | New effect permitted | Meaning |
| --- | --- | --- | --- | --- | --- | --- |
| `RECEIVED` | `ingress` | `false` | `false` | `none` | `false` | A bounded request envelope was received; no semantic or effect claim exists. |
| `VALIDATED` | `admission` | `false` | `false` | `none` | `false` | Mechanical shape, identity domains and fixed limits passed validation. |
| `CAPACITY_RESERVED` | `admission` | `false` | `false` | `none` | `false` | Finite capacity is exclusively reserved for this ordering key. |
| `ACCEPTED_DURABLE` | `admission` | `true` | `false` | `none` | `true` | Exact request identity and acceptance are durably committed before effect. |
| `EFFECT_ATTEMPTING` | `effect` | `false` | `true` | `none` | `false` | The effect boundary was crossed; absence of later data cannot prove no start. |
| `EFFECT_STARTED_OBSERVED` | `effect` | `false` | `true` | `none` | `false` | Spawn, write, forward or remote start was positively observed. |
| `TERMINAL_OBSERVED` | `terminal` | `false` | `true` | `definitive` | `false` | A definitive effect outcome was observed but is not yet durable. |
| `TERMINAL_DURABLE` | `terminal` | `true` | `true` | `definitive` | `false` | The exact terminal bytes and identity are durably committed. |
| `DELIVERY_PENDING` | `delivery` | `true` | `true` | `definitive` | `false` | Only caller delivery remains; effect execution must never be repeated. |
| `DELIVERED` | `delivery` | `true` | `true` | `definitive` | `false` | Exact terminal bytes were written to the selected caller channel. |
| `ACKNOWLEDGED` | `delivery` | `true` | `true` | `definitive` | `false` | The caller acknowledged the exact terminal identity and bytes. |
| `REJECTED_BEFORE_EFFECT` | `terminal` | `false` | `false` | `definitive` | `false` | Validation, conflict, capacity or definitive acceptance failure rejected before effect. |
| `UNKNOWN_RECONCILIATION_REQUIRED` | `uncertainty` | `false` | `true` | `uncertain` | `false` | An effect may have occurred; external reality must be reconciled before new semantic action. |
| `FENCED` | `uncertainty` | `false` | `true` | `uncertain` | `false` | The ordering key or writer epoch is blocked from new authoritative work. |
| `CLOSED` | `closed` | `true` | `true` | `closed` | `false` | The lifecycle is closed after acknowledgement, pre-effect rejection or an explicit fenced close. |

## Transitions

| ID | From | To | Trigger | Effect boundary | Durable acceptance required |
| --- | --- | --- | --- | --- | --- |
| `TR-01` | `RECEIVED` | `VALIDATED` | `mechanical_validation_passed` | `false` | `false` |
| `TR-02` | `RECEIVED` | `REJECTED_BEFORE_EFFECT` | `malformed_or_unsupported_input` | `false` | `false` |
| `TR-03` | `VALIDATED` | `CAPACITY_RESERVED` | `finite_capacity_reserved` | `false` | `false` |
| `TR-04` | `VALIDATED` | `REJECTED_BEFORE_EFFECT` | `identity_conflict_or_capacity_rejection` | `false` | `false` |
| `TR-05` | `CAPACITY_RESERVED` | `ACCEPTED_DURABLE` | `acceptance_commit_confirmed` | `false` | `false` |
| `TR-06` | `CAPACITY_RESERVED` | `REJECTED_BEFORE_EFFECT` | `acceptance_definitively_failed_before_effect` | `false` | `false` |
| `TR-07` | `CAPACITY_RESERVED` | `FENCED` | `acceptance_durability_or_writer_epoch_ambiguous` | `false` | `false` |
| `TR-08` | `ACCEPTED_DURABLE` | `EFFECT_ATTEMPTING` | `effect_boundary_crossed` | `true` | `true` |
| `TR-09` | `ACCEPTED_DURABLE` | `TERMINAL_OBSERVED` | `cancel_or_no_effect_terminal_linearized_before_attempt` | `false` | `false` |
| `TR-10` | `ACCEPTED_DURABLE` | `FENCED` | `writer_epoch_or_fencing_token_lost_before_attempt` | `false` | `false` |
| `TR-11` | `EFFECT_ATTEMPTING` | `EFFECT_STARTED_OBSERVED` | `spawn_write_forward_or_remote_start_observed` | `false` | `true` |
| `TR-12` | `EFFECT_ATTEMPTING` | `TERMINAL_OBSERVED` | `definitive_terminal_observed_without_separate_start` | `false` | `true` |
| `TR-13` | `EFFECT_ATTEMPTING` | `UNKNOWN_RECONCILIATION_REQUIRED` | `timeout_eof_disconnect_or_crash_after_attempt` | `false` | `true` |
| `TR-14` | `EFFECT_STARTED_OBSERVED` | `TERMINAL_OBSERVED` | `definitive_terminal_observed` | `false` | `true` |
| `TR-15` | `EFFECT_STARTED_OBSERVED` | `UNKNOWN_RECONCILIATION_REQUIRED` | `terminal_proof_missing_after_observed_start` | `false` | `true` |
| `TR-16` | `TERMINAL_OBSERVED` | `TERMINAL_DURABLE` | `terminal_commit_confirmed` | `false` | `true` |
| `TR-17` | `TERMINAL_OBSERVED` | `UNKNOWN_RECONCILIATION_REQUIRED` | `terminal_commit_failed_or_ambiguous` | `false` | `true` |
| `TR-18` | `TERMINAL_DURABLE` | `DELIVERY_PENDING` | `caller_delivery_enqueued` | `false` | `true` |
| `TR-19` | `DELIVERY_PENDING` | `DELIVERED` | `exact_terminal_bytes_written` | `false` | `true` |
| `TR-20` | `DELIVERY_PENDING` | `DELIVERY_PENDING` | `backpressure_or_disconnect_defers_delivery_only` | `false` | `true` |
| `TR-21` | `DELIVERED` | `ACKNOWLEDGED` | `exact_terminal_ack_received` | `false` | `true` |
| `TR-22` | `DELIVERED` | `DELIVERY_PENDING` | `ack_missing_or_connection_lost` | `false` | `true` |
| `TR-23` | `ACKNOWLEDGED` | `CLOSED` | `acknowledged_lifecycle_closed` | `false` | `true` |
| `TR-24` | `REJECTED_BEFORE_EFFECT` | `CLOSED` | `pre_effect_rejection_closed` | `false` | `false` |
| `TR-25` | `UNKNOWN_RECONCILIATION_REQUIRED` | `TERMINAL_OBSERVED` | `external_reconciliation_proves_definitive_terminal` | `false` | `true` |
| `TR-26` | `UNKNOWN_RECONCILIATION_REQUIRED` | `FENCED` | `reconciliation_incomplete_or_operator_fence` | `false` | `true` |
| `TR-27` | `FENCED` | `CLOSED` | `explicit_fenced_close_without_redispatch` | `false` | `true` |

## Invariants

- `INV-01` / `effect_requires_durable_acceptance` — An effect attempt is reachable only from durable acceptance.
- `INV-02` / `ambiguous_observation_requires_unknown` — Timeout, EOF, disconnect and crash after attempt produce uncertainty, never proof of cancellation or no start.
- `INV-03` / `terminal_delivery_order_is_strict` — Terminal observation, terminal durability, delivery and acknowledgement are distinct ordered states.
- `INV-04` / `duplicate_policy_is_closed` — Exact duplicates attach or replay known bytes; changed content conflicts before effect.
- `INV-05` / `race_policy_has_one_linearization_point` — Cancel versus terminal uses one per-ordering-key linearization sequence.
- `INV-06` / `fenced_states_have_no_effect_path` — Stale writers and fencing violations cannot reach the effect boundary.
- `INV-07` / `cleanup_preserves_primary_outcome` — Cleanup errors remain secondary and cannot overwrite a definitive effect result.
- `INV-08` / `crash_cuts_forbid_false_no_start` — Recovery never infers not-started from missing post-acceptance data.
- `INV-09` / `automatic_redispatch_is_globally_false` — Automatic redispatch is false in every state transition and recovery cut.
- `INV-10` / `implementation_mapping_is_total` — Every active transition is mapped to source and deterministic tests.

## Crash cuts

| Cut | After | Legal recovery | Forbidden inference | Automatic redispatch |
| --- | --- | --- | --- | --- |
| `CUT-01` | `RECEIVED` | RECEIVED, REJECTED_BEFORE_EFFECT | effect_started, safe_automatic_dispatch | `false` |
| `CUT-02` | `VALIDATED` | RECEIVED, VALIDATED, REJECTED_BEFORE_EFFECT | effect_started, safe_automatic_dispatch | `false` |
| `CUT-03` | `CAPACITY_RESERVED` | REJECTED_BEFORE_EFFECT, FENCED | effect_started, durable_acceptance | `false` |
| `CUT-04` | `ACCEPTED_DURABLE` | ACCEPTED_DURABLE, FENCED | not_started_from_missing_attempt_data, safe_automatic_dispatch | `false` |
| `CUT-05` | `EFFECT_ATTEMPTING` | UNKNOWN_RECONCILIATION_REQUIRED, FENCED | not_started, cancelled, safe_retry | `false` |
| `CUT-06` | `EFFECT_STARTED_OBSERVED` | UNKNOWN_RECONCILIATION_REQUIRED, FENCED | not_started, cancelled, safe_retry | `false` |
| `CUT-07` | `TERMINAL_OBSERVED` | TERMINAL_DURABLE, UNKNOWN_RECONCILIATION_REQUIRED, FENCED | terminal_durable_from_memory_only_observation, safe_effect_retry | `false` |
| `CUT-08` | `TERMINAL_DURABLE` | TERMINAL_DURABLE, DELIVERY_PENDING | effect_must_repeat_for_delivery | `false` |
| `CUT-09` | `DELIVERY_PENDING` | DELIVERY_PENDING, DELIVERED | effect_must_repeat_for_delivery | `false` |
| `CUT-10` | `DELIVERED` | DELIVERY_PENDING, DELIVERED, ACKNOWLEDGED | effect_must_repeat_for_ack | `false` |
| `CUT-11` | `ACKNOWLEDGED` | ACKNOWLEDGED, CLOSED | effect_must_repeat | `false` |
| `CUT-12` | `UNKNOWN_RECONCILIATION_REQUIRED` | UNKNOWN_RECONCILIATION_REQUIRED, FENCED | not_started, safe_retry, cancelled_without_proof | `false` |
| `CUT-13` | `FENCED` | FENCED, CLOSED | safe_automatic_dispatch | `false` |

## Implementation bindings

| Binding | Modules | Source symbol | Transitions | Tests |
| --- | --- | --- | --- | --- |
| `BIND-INGRESS` | MOD-PROTOCOL, MOD-BROKER | `crates/trillionnium-owner-open-types/src/lib.rs::pub fn validate` | TR-01, TR-02, TR-03, TR-04 | crates/trillionnium-owner-open-types/src/lib.rs, tools/tests/test_owner_open_ingress_contract.py |
| `BIND-HOST-DURABILITY` | MOD-EXECUTION-CORE, MOD-EVENT-STORE | `apps/trillionnium-owner-open-host/src/r5_persistence.rs::pub fn append_frame` | TR-05, TR-06, TR-07, TR-16, TR-17 | apps/trillionnium-owner-open-host/tests/r5_effect_admission.rs, apps/trillionnium-owner-open-host/tests/r5_terminal_receipt.rs |
| `BIND-DIRECT-RUNTIME` | MOD-TOOL-RUNTIME | `crates/trillionnium-owner-open-runtime/src/process.rs::execute_process` | TR-08, TR-11, TR-12, TR-13, TR-14, TR-15 | crates/trillionnium-owner-open-runtime/tests/runtime.rs, crates/trillionnium-owner-open-runtime/tests/retirement.rs |
| `BIND-TURN-LINEARIZATION` | MOD-TURN-ENGINE, MOD-PROVIDER | `crates/trillionnium-owner-open-turn-loop/src/lib.rs::run_with_sink_and_cancellation` | TR-09, TR-12, TR-14 | crates/trillionnium-owner-open-turn-loop/tests/streaming_and_cancel.rs, crates/trillionnium-owner-open-provider-jsonl/tests/cancellation.rs |
| `BIND-JOB-LIFECYCLE` | MOD-JOB-RUNTIME | `crates/trillionnium-owner-open-job-runtime/src/manager.rs::pub fn start` | TR-03, TR-05, TR-07, TR-08, TR-11, TR-13, TR-15, TR-25, TR-26 | crates/trillionnium-owner-open-job-runtime/tests/runtime.rs, apps/trillionnium-owner-open-host/tests/r5_jobs.rs |
| `BIND-STORE-REPLAY` | MOD-EVENT-STORE | `crates/trillionnium-owner-open-event-store/src/lib.rs::pub fn append_durable` | TR-05, TR-16, TR-17, TR-25 | crates/trillionnium-owner-open-event-store/tests/durable.rs, crates/trillionnium-owner-open-event-store/tests/segmented.rs |
| `BIND-CALLER-DELIVERY` | MOD-TRANSPORT, MOD-STREAM | `apps/trillionnium-owner-open-host/src/bin/r5_control_host_v7/process.rs::deliver_raw_line` | TR-18, TR-19, TR-20, TR-21, TR-22, TR-23 | apps/trillionnium-owner-open-host/tests/r5_stream_flow_control.rs, apps/trillionnium-owner-open-host/tests/r5_transport_core_drain.rs |
| `BIND-PRE-EFFECT-CLOSE` | MOD-EXECUTION-CORE | `apps/trillionnium-owner-open-host/src/lib.rs::handle_turn_cancel` | TR-06, TR-09, TR-10, TR-24 | apps/trillionnium-owner-open-host/tests/r5_active_controls.rs, apps/trillionnium-owner-open-host/tests/r5_client_disconnect.rs |
| `BIND-BROKER-FENCE` | MOD-BROKER, MOD-TRANSPORT | `tools/owner-open/owner_open_broker_mux.py::def fence_active` | TR-10, TR-13, TR-15, TR-26, TR-27 | tools/tests/test_owner_open_broker_mux.py, tools/tests/test_owner_open_broker_mux_integration.py |

The generated view is descriptive. The executable verifier and finite model
checker remain the authority for legal transitions. Passing them is L1 source
evidence only and cannot substitute for installed-target or destructive-fault proof.
