#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
MODEL_PATH = (
    ROOT
    / "crates/trillionnium-os-types/contracts/agent-direct-permission-model-v1.json"
)
CATALOG_PATH = (
    ROOT
    / "crates/trillionnium-os-types/contracts/agent-typed-operation-catalog-v1.json"
)
STABLE_PRINCIPAL_REGISTRY_PATH = (
    ROOT
    / "crates/trillionnium-os-types/contracts/agent-principal-registry-v2.json"
)
HOST_ABI_PATH = (
    ROOT / "crates/trillionnium-os-types/contracts/direct-agent-host-abi-v1.json"
)
BOUNDARY_PATH = ROOT / "docs/contracts/agent-exec-adb-windows-product-boundary-v2.json"
RUST_MODEL_PATH = (
    ROOT / "crates/trillionnium-os-types/src/agent_direct_permission_model.rs"
)
RISK_GUARD_PATH = (
    ROOT / "crates/trillionnium-agent-direct-tools/src/risk_guard.rs"
)
TYPED_RUST_PATH = (
    ROOT / "crates/trillionnium-os-types/src/typed_operation_catalog.rs"
)
CODEX_PATH = ROOT / "crates/trillionnium-tool-runtime/src/supervised_codex.rs"
ACTION_WORKFLOW_PATH = ROOT / "apps/trillionniumd/src/action_workflow.rs"

MODEL_SHA256 = "9399b1375d267e2672d3de28519d9f001e5c50ff83d056dd20fe08383613613d"
CATALOG_SHA256 = "c4efd224e75bc21ab95753eac4f183732c447e315ac89d4369bc5185a4997453"
STABLE_PRINCIPAL_PROJECTION_SHA256 = (
    "a9c224116123deb49908beda3ab047fc98d6917cfeb62d60364033858cc57153"
)
HOST_ABI_SHA256 = "d538ef22f6ff1fcc5cf2ff15a158a8227631991bf83c3676ab19a66fce162c11"


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate permission-model key: {key}")
        value[key] = item
    return value


def reject_nonfinite(token: str) -> object:
    raise ValueError(f"non-finite permission-model number: {token}")


def load_strict(path: Path) -> dict[str, object]:
    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=reject_nonfinite,
    )
    if not isinstance(value, dict):
        raise ValueError("permission-model root must be an object")
    return value


class AgentDirectPermissionModelTest(unittest.TestCase):
    def setUp(self) -> None:
        self.model = load_strict(MODEL_PATH)

    def assert_semantics(self, model: dict[str, object]) -> None:
        self.assertEqual(
            set(model),
            {
                "schema",
                "policy_id",
                "revision",
                "status",
                "superseded_by",
                "scope",
                "effect_authority",
                "current_product_effects_enabled",
                "bindings",
                "principal_profile",
                "variant_tool_sets",
                "dispositions",
                "permissions",
                "launch_package_adapter_selection",
                "common_product_effect_custody",
                "default_rules",
                "promotion_gates",
                "windows_productization",
            },
        )
        self.assertEqual(
            model["schema"], "org.trillionnium.agent-direct-permission-model.v1"
        )
        self.assertEqual(model["revision"], 3)
        self.assertEqual(model["status"], "superseded_typed_candidate_model_hold")
        self.assertEqual(
            model["superseded_by"],
            "org.trillionnium.agent-exec-adb-windows-product-boundary.v2",
        )
        self.assertEqual(
            model["scope"],
            {
                "contract_role": "implemented_direct_system_api_accessibility_and_typed_candidate_only",
                "current_product_boundary": False,
                "direct_shell_status": "not_modeled_here_superseded_by_product_boundary_v2",
                "direct_adb_status": "planned_not_implemented_hold",
                "direct_shell_and_adb_effect_authority": False,
            },
        )
        self.assertIs(model["effect_authority"], False)
        self.assertIs(model["current_product_effects_enabled"], False)

        self.assertEqual(
            model["bindings"],
            {
                "agent_stable_principal_projection_sha256": STABLE_PRINCIPAL_PROJECTION_SHA256,
                "direct_agent_host_abi_sha256": HOST_ABI_SHA256,
                "typed_operation_catalog_sha256": CATALOG_SHA256,
                "risk_guard_policy_version": "org.trillionnium.agent-risk-guard.v1",
            },
        )
        stable_contract = load_strict(STABLE_PRINCIPAL_REGISTRY_PATH)
        stable_projection = {
            "schema": stable_contract["registry_schema"],
            "endpoints": [
                {
                    "symbol": endpoint["symbol"],
                    "tool_selinux_domain": endpoint["tool_selinux_domain"],
                    "operation_replay_sync_selinux_domain": endpoint[
                        "operation_replay_sync_selinux_domain"
                    ],
                }
                for endpoint in stable_contract["endpoints"]
            ],
            "principals": [
                {
                    "schema": stable_contract["principal_schema"],
                    "provider_id": principal["provider_id"],
                    "agent_id": principal["agent_id"],
                    "replay_namespace": principal["replay_namespace"],
                    "uid": principal["uid"],
                    "gid": principal["gid"],
                    "agent_selinux_domain": principal["agent_selinux_domain"],
                    "runtime_adapter": principal["runtime_adapter"],
                }
                for principal in stable_contract["principals"]
            ],
        }
        stable_projection_sha256 = hashlib.sha256(
            json.dumps(
                stable_projection, ensure_ascii=True, separators=(",", ":")
            ).encode("utf-8")
        ).hexdigest()
        self.assertEqual(
            stable_projection_sha256, STABLE_PRINCIPAL_PROJECTION_SHA256
        )
        for path, expected in (
            (HOST_ABI_PATH, HOST_ABI_SHA256),
            (CATALOG_PATH, CATALOG_SHA256),
        ):
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), expected)

        profile = model["principal_profile"]
        self.assertEqual(
            profile["profile_id"], "builtin-direct-stable-principal-v1"
        )
        self.assertIs(profile["wildcard_principals"], False)
        self.assertEqual(profile["unknown_principal"], "deny")
        self.assertIs(
            profile["principal_declared_identity_is_authoritative"], False
        )
        self.assertIs(
            profile["executable_identity_is_preliminary_permission_input"], False
        )
        self.assertEqual(
            profile["active_launcher_identity_authority"],
            {
                "required": "daemon_broker_authenticated_runtime_custody",
                "current_available": False,
            },
        )
        self.assertIs(profile["principal_permission_sets_are_identical"], True)
        self.assertEqual(
            profile["principals"],
            [
                {
                    "provider_id": "openai-codex",
                    "agent_id": "agent-codex-direct-v1",
                    "replay_namespace": "agent-codex-v1",
                    "uid": 5901,
                    "gid": 5901,
                    "selinux_domain": "u:r:trillionnium_codex_agent:s0",
                    "runtime_adapter": "supervised-codex-cli",
                }
            ],
        )
        self.assertEqual(
            set(profile["registration_authenticated_identity_factors"]),
            {
                "agent_id",
                "runtime_adapter",
                "uid",
                "gid",
                "selinux_domain",
                "enabled_ready_registration",
            },
        )
        self.assertEqual(
            set(profile["closed_registry_derived_identity_factors"]),
            {"provider_id", "replay_namespace"},
        )

        direct_tools = [
            "trillionnium_system_api",
            "trillionnium_accessibility",
        ]
        variant_tools = model["variant_tool_sets"]
        self.assertEqual(set(variant_tools), {"user", "userdebug", "eng", "recovery"})
        expected_typed = {
            "user": [
                "exec.launch_package.settings.v1",
                "adb.launch_package.settings.user.v1",
            ],
            "userdebug": [
                "exec.launch_package.settings.v1",
                "adb.launch_package.settings.engineering-recovery.v1",
            ],
            "eng": [
                "exec.launch_package.settings.v1",
                "adb.launch_package.settings.engineering-recovery.v1",
            ],
            "recovery": [
                "exec.launch_package.settings.v1",
                "adb.launch_package.settings.engineering-recovery.v1",
            ],
        }
        for variant, candidates in expected_typed.items():
            self.assertEqual(variant_tools[variant]["direct_mcp_tools"], direct_tools)
            self.assertEqual(
                variant_tools[variant]["typed_source_candidates"], candidates
            )
            self.assertEqual(
                set(variant_tools[variant]),
                {"direct_mcp_tools", "typed_source_candidates"},
            )

        expected_rules = {
            ("direct_system_api", "launch_package"): (
                "low_navigation",
                "policy_allow_requires_effect_custody",
            ),
            ("direct_system_api", "open_uri"): (
                "critical_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "snapshot_metadata_only"): (
                "observe",
                "policy_allow_requires_effect_custody",
            ),
            ("direct_accessibility", "snapshot_full_text"): (
                "sensitive_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "scroll"): (
                "low_navigation",
                "policy_allow_requires_effect_custody",
            ),
            ("direct_accessibility", "global_back"): (
                "low_navigation",
                "policy_allow_requires_effect_custody",
            ),
            ("direct_accessibility", "global_home"): (
                "low_navigation",
                "policy_allow_requires_effect_custody",
            ),
            ("direct_accessibility", "click"): (
                "sensitive_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "set_text"): (
                "sensitive_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "gesture"): (
                "sensitive_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "global_recents"): (
                "sensitive_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "global_notifications"): (
                "sensitive_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "global_quick_settings"): (
                "sensitive_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "global_power_dialog"): (
                "critical_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "global_lock_screen"): (
                "critical_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "global_take_screenshot"): (
                "critical_effect",
                "os_session_lease_required",
            ),
            ("direct_accessibility", "batch"): (
                "derived_max_child",
                "conditional_every_batch_member",
            ),
            ("typed_exec", "exec.launch_package.settings.v1"): (
                "low_navigation",
                "source_candidate_hold",
            ),
            ("typed_adb", "adb.launch_package.settings.user.v1"): (
                "low_navigation",
                "source_candidate_hold",
            ),
            (
                "typed_adb",
                "adb.launch_package.settings.engineering-recovery.v1",
            ): ("low_navigation", "source_candidate_hold"),
        }
        actual_rules = {
            (row["surface"], row["action"]): (
                row["risk_tier"],
                row["disposition"],
            )
            for row in model["permissions"]
        }
        self.assertEqual(actual_rules, expected_rules)
        self.assertEqual(len(model["permissions"]), len(expected_rules))

        selection = model["launch_package_adapter_selection"]
        self.assertEqual(selection["selection_owner"], "os_policy_before_prepared")
        self.assertIs(selection["model_or_agent_selects_adapter"], False)
        self.assertIs(selection["selected_adapter_bound_in_prepared_record"], True)
        self.assertIs(selection["cross_adapter_retry_after_prepared"], False)
        self.assertEqual(
            selection["indeterminate_or_unknown_outcome"],
            "permanent_hold_without_blind_retry",
        )
        self.assertIn(
            "os_selected_variant_specific_user_or_engineering_recovery_descriptor",
            selection["typed_adb_requires"],
        )

        custody = model["common_product_effect_custody"]
        self.assertIs(custody["all_currently_satisfied_in_product"], False)
        self.assertEqual(custody["missing_or_ambiguous_gate"], "deny_before_backend")
        self.assertEqual(
            set(custody["required"]),
            {
                "kernel_and_stable_principal_authentication",
                "active_launcher_executable_authenticated_by_daemon_broker_custody",
                "product_signed_permission_model_and_operation_catalog",
                "avb_bound_runtime_tool_and_backend_measurements",
                "canonical_request_action_and_adapter_binding",
                "risk_policy_and_single_use_lease_when_required",
                "rollback_resistant_epoch_and_allocation",
                "durable_prepared_before_effect",
                "single_delivery_attempt",
                "durable_terminal_result_before_return",
                "exact_terminal_response_replay",
                "durable_outer_ack_before_reclamation",
                "restart_replay_and_zero_survivor_evidence",
            },
        )
        self.assertEqual(
            set(model["promotion_gates"]),
            {
                "permission_model_product_signed_and_avb_bound",
                "direct_product_custody_complete",
                "typed_exec_product_backend_complete",
                "typed_adb_product_backend_complete",
                "direct_shell_product_backend_complete",
                "direct_adb_product_backend_complete",
                "durable_restart_replay_and_outer_ack_complete",
                "physical_codex_launch_effect_evidence_complete",
                "locked_user_device_evidence_complete",
            },
        )
        self.assertTrue(all(value is False for value in model["promotion_gates"].values()))
        self.assertEqual(
            model["windows_productization"],
            {
                "paused_until_android_main_loop_complete": True,
                "current_permission": "deny",
            },
        )

    def test_canonical_model_is_strict_measured_and_closed(self) -> None:
        self.assertEqual(hashlib.sha256(MODEL_PATH.read_bytes()).hexdigest(), MODEL_SHA256)
        self.assertEqual(
            MODEL_PATH.read_text(encoding="utf-8"),
            json.dumps(self.model, indent=2, ensure_ascii=True) + "\n",
        )
        self.assert_semantics(self.model)

    def test_duplicate_key_and_silent_authority_widening_fail(self) -> None:
        duplicate = MODEL_PATH.read_text(encoding="utf-8").replace(
            '  "effect_authority": false,\n',
            '  "effect_authority": false,\n  "effect_authority": true,\n',
            1,
        )
        duplicate_path = self.id()
        with self.assertRaisesRegex(ValueError, "duplicate permission-model key"):
            json.loads(duplicate, object_pairs_hook=reject_duplicate_pairs)
        self.assertTrue(duplicate_path)

        for field in (
            "effect_authority",
            "current_product_effects_enabled",
        ):
            mutated = copy.deepcopy(self.model)
            mutated[field] = True
            with self.assertRaises(AssertionError):
                self.assert_semantics(mutated)

    @unittest.skipUnless(
        BOUNDARY_PATH.is_file(),
        "G1 retired the historical product-boundary document; this legacy binding check is not active evidence",
    )
    def test_superseded_model_stays_bound_only_to_typed_policy_surfaces(self) -> None:
        rust_model = RUST_MODEL_PATH.read_text(encoding="utf-8")
        rust_model_product = rust_model.split("\n#[cfg(test)]\nmod tests", 1)[0]
        risk_guard = RISK_GUARD_PATH.read_text(encoding="utf-8")
        typed_rust = TYPED_RUST_PATH.read_text(encoding="utf-8")
        codex = CODEX_PATH.read_text(encoding="utf-8")
        action_workflow = ACTION_WORKFLOW_PATH.read_text(encoding="utf-8")

        self.assertIn(MODEL_SHA256, rust_model)
        self.assertIn("agent_principal_registry", rust_model_product)
        self.assertIn("from_registration_fields", rust_model_product)
        self.assertNotIn("agent_descriptor_registry", rust_model_product)
        self.assertNotIn("identity_key_sha256", rust_model_product)
        self.assertIn("permission_disposition(", risk_guard)
        self.assertIn("PermissionModelDenied", risk_guard)
        self.assertIn("pub permission_model_sha256: String", risk_guard)
        self.assertIn("PERMISSION_MODEL_SHA256.as_bytes()", risk_guard)
        self.assertIn("PermissionModelDenied", typed_rust)
        self.assertIn("pub permission_model_sha256: &'static str", typed_rust)
        self.assertIn(
            '"permission_model_sha256": agent_direct_permission_model::PERMISSION_MODEL_SHA256',
            typed_rust,
        )
        self.assertIn("CODEX_DIRECT_MCP_IDENTITY_SET_SCHEMA", codex)
        self.assertIn("direct_mcp_identity_set_sha256", codex)
        self.assertNotIn("CODEX_DIRECT_PERMISSION_MODEL_SHA256", codex)
        codex_mcp_closure = codex.split(
            "fn configure_codex_direct_mcp", 1
        )[1].split("fn configure_codex_stdio_mcp", 1)[0]
        self.assertNotIn("trillionnium_adb", codex_mcp_closure)
        action_workflow_product = action_workflow.split(
            "\n#[cfg(test)]\nmod tests", 1
        )[0]
        self.assertIn("codex_direct_mcp_identity_is_authorized", action_workflow_product)
        self.assertIn("CODEX_DIRECT_MCP_TOOL_NAMES.len()", action_workflow_product)
        self.assertNotIn("direct_agent_tool_name_is_allowed", action_workflow_product)
        self.assertNotIn("trillionnium_adb", action_workflow_product)

        retired_name = "open" + "claw"
        active_rust = "\n".join(
            path.read_text(encoding="utf-8")
            for root in (ROOT / "apps", ROOT / "crates", ROOT / "foundations")
            if root.exists()
            for path in root.rglob("*.rs")
        )
        self.assertNotIn(retired_name, active_rust.lower())

        boundary = load_strict(BOUNDARY_PATH)
        self.assertEqual(
            boundary["scope"]["current_builtin_agents"],
            [{"provider_id": "openai-codex", "agent_id": "agent-codex-direct-v1"}],
        )
        self.assertEqual(
            boundary["direct_tools"]["shell"]["current_status"],
            "standard_source_wired_artifact_device_authority_hold",
        )
        self.assertEqual(boundary["direct_tools"]["adb"]["current_status"], "not_implemented_hold")


if __name__ == "__main__":
    unittest.main()
