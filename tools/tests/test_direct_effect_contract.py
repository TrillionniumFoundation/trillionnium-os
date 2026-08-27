#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = (
    ROOT / "crates/trillionnium-os-types/contracts/direct-effect-v1.json"
)
RUST_PATH = ROOT / "crates/trillionnium-os-types/src/direct_effect.rs"
LIB_PATH = ROOT / "crates/trillionnium-os-types/src/lib.rs"

CONTRACT_SHA256 = "5c4fe8ac528d2da54d7eecb28b7c50107f1bd9971196bdabd6b55e5f483d2266"
MODEL_ARGUMENTS_GOLDEN_SHA256 = (
    "4ffd9c4f2668e8af40b2d9c267769ce91db72d52b6fc5e2f508fe06dd577993d"
)


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate direct-effect key: {key}")
        value[key] = item
    return value


def reject_nonfinite(token: str) -> object:
    raise ValueError(f"non-finite direct-effect number: {token}")


def load_strict(path: Path) -> dict[str, object]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=reject_nonfinite,
    )
    if not isinstance(value, dict):
        raise ValueError("direct-effect contract root must be an object")
    return value


def hash_field(hasher: object, name: str, value: bytes) -> None:
    encoded_name = name.encode("utf-8")
    hasher.update(len(encoded_name).to_bytes(8, "big"))
    hasher.update(encoded_name)
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def model_arguments_golden_sha256() -> str:
    domain = b"trillionnium.direct-effect-model-arguments.v1"
    hasher = hashlib.sha256()
    hasher.update(len(domain).to_bytes(8, "big"))
    hasher.update(domain)
    hash_field(hasher, "argv_count", (4).to_bytes(8, "big"))
    for argument in ("/usr/bin/printf", "%s:%s", "", "value"):
        hash_field(hasher, "argv", argument.encode("utf-8"))
    hash_field(hasher, "cwd_present", b"\x01")
    hash_field(hasher, "cwd_scope", b"workspace")
    hash_field(hasher, "cwd_relative", b"project/subdir")
    hash_field(hasher, "timeout_ms", (10_000).to_bytes(8, "big"))
    hash_field(hasher, "stdout_limit_bytes", (65_536).to_bytes(8, "big"))
    hash_field(hasher, "stderr_limit_bytes", (32_768).to_bytes(8, "big"))
    hash_field(hasher, "total_output_limit_bytes", (65_536).to_bytes(8, "big"))
    hash_field(hasher, "requested_profile", b"standard")
    return hasher.hexdigest()


class DirectEffectContractTest(unittest.TestCase):
    def setUp(self) -> None:
        self.contract = load_strict(CONTRACT_PATH)

    def assert_semantics(self, contract: dict[str, object]) -> None:
        self.assertEqual(
            set(contract),
            {
                "schema",
                "contract_id",
                "revision",
                "status",
                "effect_authority",
                "product_listener_wired",
                "product_backend_wired",
                "scope",
                "tools",
                "model_arguments",
                "os_owned_envelope",
                "canonical_hash",
                "durable_state_machine",
                "binary_output",
                "terminal_response",
                "terminal_observation",
                "indeterminate_reasons",
                "promotion_holds",
            },
        )
        self.assertEqual(
            contract["schema"], "org.trillionnium.direct-effect.contract.v1"
        )
        self.assertEqual(contract["contract_id"], "trillionnium-direct-effect-v1")
        self.assertEqual(contract["revision"], 3)
        self.assertEqual(
            contract["status"],
            "source_listener_and_root_linux_backend_wired_device_authority_pending",
        )
        self.assertIs(contract["effect_authority"], False)
        self.assertIs(contract["product_listener_wired"], True)
        self.assertIs(contract["product_backend_wired"], True)

        scope = contract["scope"]
        self.assertEqual(
            scope,
            {
                "agent": "codex_only",
                "phone_local_llm": False,
                "codex_invokes_tools_directly": True,
                "os_owns_transport_credentials_policy_and_receipts": True,
                "first_real_backend_order": [
                    "root_linux_shell_exec_standard",
                    "android_local_adb_shell_equivalent",
                ],
            },
        )

        tools = contract["tools"]
        self.assertEqual(set(tools), {"shell_exec_v1", "adb_shell_local_v1"})
        self.assertEqual(tools["shell_exec_v1"]["wire_name"], "shell.exec.v1")
        self.assertEqual(tools["shell_exec_v1"]["target"], "root_linux")
        self.assertEqual(
            tools["shell_exec_v1"]["command_string_mode"], "not_in_v1"
        )
        self.assertEqual(
            tools["shell_exec_v1"]["source_policy_floor"],
            {
                "authority": "defense_in_depth_only",
                "denied_interpreter_basenames": [
                    "sh",
                    "ash",
                    "bash",
                    "dash",
                    "ksh",
                    "mksh",
                    "zsh",
                ],
                "denied_command_flags": [
                    "-c",
                    "combined_short_option_containing_c",
                    "--command",
                ],
                "env_and_busybox_launchers_denied": True,
                "absolute_normalized_argv0_required": True,
                "renamed_or_symlinked_interpreter_closure": False,
            },
        )
        self.assertEqual(
            tools["shell_exec_v1"]["first_slice_limits"],
            {
                "timeout_maximum_ms": 60_000,
                "stdout_maximum_bytes": 65_536,
                "stderr_maximum_bytes": 65_536,
                "combined_output_maximum_bytes": 65_536,
                "transport_request_packet_maximum_bytes": 131_072,
                "transport_response_packet_maximum_bytes": 262_144,
                "single_seqpacket_record_each_direction": True,
                "exact_coupled_response_budget_before_dispatch": True,
                "worst_case_terminal_capacity_admission_before_dispatch": True,
            },
        )
        self.assertEqual(
            tools["shell_exec_v1"][
                "product_promotion_requires_measured_executable_policy"
            ],
            {
                "required": True,
                "resolution": "openat_component_walk_retained_dirfd_nofollow_same_device_v1",
                "decision": "opened_executable_digest_must_be_in_v1_allowlist",
                "shell_and_inline_interpreter_digests_allowed": False,
            },
        )
        self.assertEqual(
            tools["adb_shell_local_v1"]["wire_name"], "adb.shell.local.v1"
        )
        self.assertEqual(
            tools["adb_shell_local_v1"]["target"], "self_device_only"
        )
        self.assertIs(
            tools["adb_shell_local_v1"]["caller_target_selection"], False
        )

        model = contract["model_arguments"]
        expected_model_fields = [
            "argv",
            "cwd",
            "timeout_ms",
            "stdout_limit_bytes",
            "stderr_limit_bytes",
            "total_output_limit_bytes",
            "requested_profile",
        ]
        self.assertEqual(model["closed_fields"], expected_model_fields)
        self.assertEqual(
            set(model),
            {
                "closed_fields",
                "argv",
                "cwd",
                "timeout_ms",
                "output_limits",
                "requested_profiles",
                "forbidden_os_owned_fields",
            },
        )
        self.assertEqual(model["argv"]["minimum_count"], 1)
        self.assertEqual(model["argv"]["maximum_count"], 256)
        self.assertEqual(model["argv"]["maximum_argument_bytes"], 16_384)
        self.assertEqual(model["argv"]["maximum_total_bytes"], 65_536)
        self.assertIs(model["argv"]["nul_allowed"], False)
        self.assertIs(model["argv"]["empty_argv0_allowed"], False)
        self.assertIs(model["argv"]["empty_nonzero_arguments_preserved"], True)
        self.assertIs(model["argv"]["shell_parsing"], False)
        self.assertIs(
            model["argv"]["arbitrary_linux_byte_argv_supported"], False
        )
        self.assertEqual(model["cwd"]["closed_fields"], ["scope", "relative"])
        self.assertEqual(model["cwd"]["scopes"], ["workspace"])
        self.assertEqual(
            model["requested_profiles"],
            ["standard", "elevated", "developer_recovery"],
        )

        envelope = contract["os_owned_envelope"]
        envelope_fields = [
            "schema",
            "contract_sha256",
            "provider_id",
            "agent_id",
            "direct_binding_sha256",
            "invocation_id",
            "delivery_provider_attempt_id",
            "os_tool_call_id",
            "adapter_effect_ordinal",
            "effect_id",
            "allocation_record_sha256",
            "kernel_launch_custody_sha256",
            "boot_id_sha256",
            "tool",
            "arguments",
            "absolute_deadline_boottime_ms",
            "effective_profile",
            "risk_class",
            "confirmation_lease_receipt_sha256",
            "policy_sha256",
            "backend_identity_sha256",
            "request_sha256",
        ]
        self.assertEqual(envelope["closed_fields"], envelope_fields)
        self.assertEqual(
            envelope["schema"], "org.trillionnium.direct-effect.request.v1"
        )
        self.assertEqual(
            envelope["principal"]["provider_id"], "openai-codex"
        )
        self.assertEqual(
            envelope["principal"]["agent_id"], "agent-codex-direct-v1"
        )
        self.assertIs(
            envelope["principal"]["caller_declared_identity_authoritative"], False
        )
        self.assertEqual(envelope["deadline_clock"], "clock_boottime")
        self.assertIs(
            envelope["effective_profile_must_equal_requested_profile"], True
        )
        self.assertEqual(
            envelope["risk_classes"], ["standard", "elevated", "destructive"]
        )
        self.assertIs(envelope["confirmation_lease"]["model_may_supply"], False)

        forbidden = set(model["forbidden_os_owned_fields"])
        self.assertTrue(
            {
                "provider_id",
                "agent_id",
                "direct_binding_sha256",
                "invocation_id",
                "delivery_provider_attempt_id",
                "os_tool_call_id",
                "adapter_effect_ordinal",
                "effect_id",
                "absolute_deadline_boottime_ms",
                "effective_profile",
                "risk_class",
                "confirmation_lease_receipt_sha256",
                "policy_sha256",
                "backend_identity_sha256",
                "request_sha256",
                "serial",
                "host",
                "port",
                "build_type",
                "enable_token",
            }.issubset(forbidden)
        )
        self.assertTrue(set(expected_model_fields).isdisjoint(forbidden))

        canonical = contract["canonical_hash"]
        self.assertEqual(canonical["digest"], "sha256")
        self.assertEqual(canonical["integer_encoding"], "unsigned_u64_big_endian")
        self.assertEqual(
            canonical["model_arguments_domain"],
            "trillionnium.direct-effect-model-arguments.v1",
        )
        self.assertEqual(
            canonical["model_argument_field_order"],
            [
                "argv_count",
                "argv_repeated_in_order",
                "cwd_present",
                "cwd_scope_if_present",
                "cwd_relative_if_present",
                "timeout_ms",
                "stdout_limit_bytes",
                "stderr_limit_bytes",
                "total_output_limit_bytes",
                "requested_profile",
            ],
        )
        self.assertEqual(
            canonical["request_field_order"],
            [field for field in envelope_fields if field not in {"tool", "arguments", "request_sha256"}][
                :13
            ]
            + [
                "tool",
                "model_arguments_sha256",
                "absolute_deadline_boottime_ms",
                "effective_profile",
                "risk_class",
                "confirmation_lease_receipt_sha256",
                "policy_sha256",
                "backend_identity_sha256",
            ],
        )

        state = contract["durable_state_machine"]
        self.assertEqual(state["initial_state"], "not_dispatched")
        self.assertIs(state["dispatch_occurred_is_explicit"], True)
        self.assertEqual(
            state["transitions"],
            {
                "not_dispatched": ["dispatched", "terminal"],
                "dispatched": ["terminal", "indeterminate"],
                "terminal": [],
                "indeterminate": [],
            },
        )
        self.assertEqual(
            state["generations"],
            {
                "not_dispatched": 1,
                "dispatched": 2,
                "terminal_before_dispatch": 2,
                "terminal_after_dispatch": 3,
                "indeterminate": 3,
            },
        )
        self.assertEqual(
            state["recovery"],
            {
                "not_dispatched": (
                    "await_same_authenticated_effect_retry_never_automatic_dispatch"
                ),
                "dispatched": "persist_indeterminate_without_retry",
                "terminal": "replay_exact_terminal_response",
                "indeterminate": "hold_without_retry",
            },
        )
        self.assertEqual(
            state["dispatch_marker_rule"],
            "dispatched_must_be_durable_before_worker_ipc_fork_clone_or_backend_contact",
        )
        self.assertEqual(
            state["restart_rule"],
            "broker_restart_never_auto_dispatches_not_dispatched_or_any_other_state",
        )
        self.assertEqual(
            state["boot_epoch_rule"],
            {
                "ledger_records_request_boot_id_sha256": True,
                "not_dispatched_from_prior_boot_must_not_dispatch": True,
                "dispatched_from_prior_boot_becomes_restart_indeterminate": True,
                "new_clock_boottime_may_be_lower_than_old_dispatch_start": True,
            },
        )
        self.assertEqual(
            state["post_dispatch_persistence_failure_public_outcome"],
            "indeterminate",
        )
        self.assertEqual(
            state["terminal_before_dispatch"],
            [
                "cancelled_before_dispatch",
                "deadline_before_dispatch",
                "policy_rejected_before_dispatch",
            ],
        )
        self.assertIs(state["blind_retry_after_dispatch"], False)
        self.assertIs(state["terminal_response_rederived_on_replay"], False)

        binary = contract["binary_output"]
        self.assertEqual(
            set(binary),
            {
                "closed_fields",
                "encoding",
                "byte_count_and_sha256_bind_decoded_bytes",
                "complete_required_for_terminal",
                "nul_and_non_utf8_preserved",
                "lossy_utf8_forbidden",
            },
        )
        self.assertEqual(
            binary["closed_fields"],
            ["encoding", "bytes", "sha256", "data", "complete"],
        )
        self.assertEqual(binary["encoding"], "base64_standard_rfc4648")
        self.assertIs(binary["nul_and_non_utf8_preserved"], True)
        self.assertIs(binary["lossy_utf8_forbidden"], True)

        response = contract["terminal_response"]
        self.assertEqual(
            response["schema"],
            "org.trillionnium.direct-effect.terminal-response.v1",
        )
        self.assertEqual(
            response["canonical_encoding"], "compact_json_serde_json_to_vec"
        )
        self.assertIs(
            response[
                "exact_serialized_bytes_sha256_is_terminal_observation_response_sha256"
            ],
            True,
        )
        self.assertIs(response["replay_requires_exact_serialized_bytes"], True)

        terminal = contract["terminal_observation"]
        self.assertEqual(
            terminal["schema"],
            "org.trillionnium.direct-effect.terminal-observation.v1",
        )
        self.assertEqual(
            terminal["kinds"],
            [
                "exited",
                "signaled",
                "launch_rejected",
                "cancelled_before_dispatch",
                "deadline_before_dispatch",
                "policy_rejected_before_dispatch",
            ],
        )
        self.assertIs(terminal["binary_safe_output_required"], True)
        self.assertIs(terminal["lossy_utf8_output_forbidden"], True)

        self.assertEqual(
            contract["indeterminate_reasons"],
            [
                "deadline_after_dispatch",
                "cancelled_after_dispatch",
                "output_limit_after_dispatch",
                "broker_restart_after_dispatch",
                "backend_lost_after_dispatch",
            ],
        )
        self.assertEqual(
            set(contract["promotion_holds"]),
            {
                "source_wired_listener_and_accept_loop_not_current_bom_artifact_or_device_proven",
                "source_wired_root_linux_exec_backend_not_current_bom_artifact_or_device_proven",
                "no_adb_transport_or_equivalent_backend",
                "no_os_key_custody",
                "source_wired_os_owned_active_invocation_registration_and_replay_token_not_current_bom_artifact_or_device_proven",
                "source_wired_broker_peercred_peersec_and_client_peer_authentication_not_current_bom_artifact_or_device_proven",
                "source_wired_peer_disconnect_cancellation_binding_not_current_bom_device_proven",
                "source_wired_measured_root_linux_chroot_worker_not_current_bom_artifact_or_device_proven",
                "source_wired_daemon_and_android_soong_init_selinux_not_current_bom_target_files_or_device_proven",
                "current_bom_aarch64_shell_artifact_set_v9_rootfs_and_receipt_stage_not_issued",
                "current_bom_userdebug_target_files_not_built",
                "current_bom_physical_shell_exec_effect_and_receipt_evidence_not_collected",
                "no_product_effect_authority",
            },
        )

    def test_contract_bytes_and_independent_model_hash_are_exact(self) -> None:
        self.assertEqual(
            hashlib.sha256(CONTRACT_PATH.read_bytes()).hexdigest(), CONTRACT_SHA256
        )
        self.assertEqual(model_arguments_golden_sha256(), MODEL_ARGUMENTS_GOLDEN_SHA256)

    def test_contract_is_closed_and_source_only(self) -> None:
        self.assert_semantics(self.contract)

    def test_security_semantic_mutations_are_rejected(self) -> None:
        mutations: list[dict[str, object]] = []

        value = copy.deepcopy(self.contract)
        value["unknown_top_level"] = True
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["effect_authority"] = True
        mutations.append(value)
        for field in ("product_listener_wired", "product_backend_wired"):
            value = copy.deepcopy(self.contract)
            value[field] = False
            mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["tools"]["shell_exec_v1"]["command_string_mode"] = "allowed"
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["tools"]["shell_exec_v1"][
            "product_promotion_requires_measured_executable_policy"
        ]["required"] = False
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["model_arguments"]["closed_fields"].append("serial")
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["model_arguments"]["forbidden_os_owned_fields"].remove("risk_class")
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["os_owned_envelope"]["principal"][
            "caller_declared_identity_authoritative"
        ] = True
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["durable_state_machine"]["transitions"]["not_dispatched"].append(
            "indeterminate"
        )
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["durable_state_machine"]["recovery"][
            "dispatched"
        ] = "retry_backend"
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["durable_state_machine"]["blind_retry_after_dispatch"] = True
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["terminal_observation"]["lossy_utf8_output_forbidden"] = False
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["binary_output"]["encoding"] = "utf8_lossy"
        mutations.append(value)
        value = copy.deepcopy(self.contract)
        value["terminal_response"]["replay_requires_exact_serialized_bytes"] = False
        mutations.append(value)

        for mutation in mutations:
            with self.assertRaises(AssertionError):
                self.assert_semantics(mutation)

    def test_rust_binding_is_closed_and_has_no_effect_backend(self) -> None:
        source = RUST_PATH.read_text(encoding="utf-8")
        library = LIB_PATH.read_text(encoding="utf-8")
        self.assertIn(f'pub const CONTRACT_SCHEMA: &str = "{self.contract["schema"]}";', source)
        self.assertIn(f'"{CONTRACT_SHA256}";', source)
        self.assertIn('include_bytes!("../contracts/direct-effect-v1.json")', source)
        self.assertGreaterEqual(source.count("#[serde(deny_unknown_fields)]"), 5)
        self.assertIn("pub mod direct_effect;", library)
        for forbidden in (
            "std::process::Command",
            "std::net::",
            "UnixListener",
            "execve(",
            "execveat(",
            "adb_wire",
            "supervised_codex",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("pub const PRODUCT_LISTENER_WIRED: bool = true;", source)
        self.assertIn("pub const PRODUCT_BACKEND_WIRED: bool = true;", source)
        self.assertIn("pub const CONFERS_EFFECT_AUTHORITY: bool = false;", source)


if __name__ == "__main__":
    unittest.main()
