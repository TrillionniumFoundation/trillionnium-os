#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = (
    ROOT / "docs/contracts/agent-exec-adb-windows-product-boundary-v2.json"
)
ADR_PATH = ROOT / "docs/architecture/2026-08-06-codex-native-direct-shell-adb.md"
CURRENT_STATE_PATH = ROOT / "docs/CURRENT_STATE.md"
README_PATH = ROOT / "README.md"
BOUNDARY_SHA256 = "c55684e9c52d04586477e9420c0e488a8a4d6fc4eeca42e287ad5be6e585a5ff"


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate boundary key: {key}")
        result[key] = value
    return result


def reject_nonfinite(token: str) -> object:
    raise ValueError(f"non-finite boundary number: {token}")


def load_strict(payload: str) -> dict[str, object]:
    value = json.loads(
        payload,
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=reject_nonfinite,
    )
    if not isinstance(value, dict):
        raise ValueError("boundary root must be an object")
    return value


class AgentExecAdbWindowsProductBoundaryTest(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = CONTRACT_PATH.read_text(encoding="utf-8")
        self.contract = load_strict(self.raw)

    def assert_keys(self, value: object, expected: set[str]) -> None:
        self.assertIsInstance(value, dict)
        self.assertEqual(set(value), expected)

    def assert_unique_set(self, value: object, expected: set[str]) -> None:
        self.assertIsInstance(value, list)
        self.assertEqual(len(value), len(set(value)))
        self.assertEqual(set(value), expected)

    def assert_boundary(self, contract: dict[str, object]) -> None:
        self.assert_keys(
            contract,
            {
                "schema",
                "status",
                "revision",
                "effective_date",
                "decision",
                "supersedes",
                "scope",
                "direct_tools",
                "security_invariants",
                "windows_compatibility",
                "release_gates",
            },
        )
        self.assertEqual(
            contract["schema"],
            "org.trillionnium.agent-exec-adb-windows-product-boundary.v2",
        )
        self.assertEqual(contract["status"], "accepted_direction_implementation_hold")
        self.assertEqual(contract["revision"], 1)
        self.assertEqual(contract["effective_date"], "2026-08-06")
        self.assertEqual(
            contract["decision"],
            "codex_only_direct_system_api_accessibility_shell_and_adb",
        )
        self.assertEqual(
            contract["supersedes"],
            "org.trillionnium.agent-exec-adb-windows-product-boundary.v1",
        )

        scope = contract["scope"]
        self.assertEqual(
            scope["current_builtin_agents"],
            [
                {
                    "provider_id": "openai-codex",
                    "agent_id": "agent-codex-direct-v1",
                }
            ],
        )
        self.assertIs(scope["phone_local_llm_product_requirement"], False)
        self.assertEqual(scope["current_inference_placement"], "off_device")
        self.assertEqual(scope["tool_invocation_owner"], "codex_agent")
        self.assertEqual(scope["effect_transport_and_privilege_owner"], "os")
        self.assertEqual(scope["openclaw_product_status"], "retired_absent")
        self.assertEqual(
            scope["legacy_openclaw_uid_gid_status"],
            "non_reusable_ota_tombstone",
        )

        direct_tools = contract["direct_tools"]
        self.assertEqual(direct_tools["android_system_api"], "required")
        self.assertEqual(
            direct_tools["accessibility"], "required_compatibility_fallback"
        )

        shell = direct_tools["shell"]
        self.assertIs(shell["product_capability"], True)
        self.assertEqual(
            shell["current_status"],
            "standard_source_wired_artifact_device_authority_hold",
        )
        self.assertEqual(shell["primary_request"], "exact_argv_with_explicit_options")
        self.assertEqual(
            shell["explicit_command_string_mode"], "higher_risk_policy_gated"
        )
        self.assertEqual(
            shell["profiles"],
            ["standard", "elevated_root_lease", "developer_recovery"],
        )
        self.assert_unique_set(
            shell["os_owned_controls"],
            {
                "agent_authentication",
                "uid_gid_selinux_profile",
                "cgroup_seccomp_capability_profile",
                "cwd_and_environment_policy",
                "deadline_cancellation_and_output_limits",
                "audit_and_restart_semantics",
            },
        )
        self.assertIs(shell["silent_privilege_escalation"], False)

        adb = direct_tools["adb"]
        self.assertIs(adb["product_capability"], True)
        self.assertEqual(adb["current_status"], "not_implemented_hold")
        self.assertIs(adb["codex_direct_invocation"], True)
        self.assert_unique_set(
            adb["os_owned_controls"],
            {
                "transport_and_target_discovery",
                "adbd_key_and_enrollment_custody",
                "user_developer_recovery_profile_separation",
                "deadline_cancellation_and_output_limits",
                "risk_policy_user_confirmation_and_audit",
            },
        )
        self.assert_unique_set(
            adb["dangerous_operations"],
            {"root", "remount", "reboot", "sideload", "install", "uninstall", "flash"},
        )
        self.assertEqual(
            adb["dangerous_operation_policy"],
            "explicit_risk_class_and_confirmation_when_required",
        )

        security = contract["security_invariants"]
        for field in (
            "provider_owns_android_service_identity",
            "provider_owns_adbd_private_key",
            "provider_owns_os_or_app_signing_keys",
            "provider_owns_policy_enrollment_or_receipt_keys",
            "permanent_unbounded_root_credential",
        ):
            self.assertIs(security[field], False, field)
        for field in (
            "effect_bound_to_authenticated_codex_turn",
            "bounded_resources_and_explicit_terminal_or_indeterminate_result",
            "destructive_and_privacy_sensitive_operations_are_risk_classified",
        ):
            self.assertIs(security[field], True, field)

        windows = contract["windows_compatibility"]
        self.assertEqual(windows["current_status"], "research_only_not_implemented")
        self.assertEqual(windows["product_graph_status"], "absent_all_product_variants")
        self.assertIs(windows["research_assets_may_enter_target_files"], False)
        self.assertIs(windows["current_release_claim_allowed"], False)

        self.assert_unique_set(
            contract["release_gates"],
            {
                "codex_only_product_graph_and_target_files",
                "minimal_rebuilt_root_linux_with_green_production_tcb",
                "physical_codex_turn_to_effect_to_ack",
                "shell_and_adb_standard_elevated_and_destructive_policy_tests",
                "timeout_cancel_restart_reboot_power_loss_replay_tests",
                "dual_agent_to_codex_only_ota_cleanup_and_tombstone_test",
                "clean_source_bom_target_files_ota_and_avb",
            },
        )

    def test_canonical_boundary_is_closed_and_passes(self) -> None:
        self.assert_boundary(self.contract)
        canonical = json.dumps(self.contract, indent=2, ensure_ascii=True) + "\n"
        self.assertEqual(self.raw, canonical)
        self.assertEqual(hashlib.sha256(self.raw.encode()).hexdigest(), BOUNDARY_SHA256)

    def test_duplicate_json_key_is_rejected(self) -> None:
        duplicate = self.raw.replace(
            '  "status": "accepted_direction_implementation_hold",\n',
            '  "status": "accepted_direction_implementation_hold",\n'
            '  "status": "widened",\n',
            1,
        )
        with self.assertRaisesRegex(ValueError, "duplicate boundary key: status"):
            load_strict(duplicate)

    def test_codex_only_identity_cannot_drift(self) -> None:
        mutated = copy.deepcopy(self.contract)
        mutated["scope"]["current_builtin_agents"].append(
            {"provider_id": "provider-b", "agent_id": "agent-b"}
        )
        with self.assertRaises(AssertionError):
            self.assert_boundary(mutated)

    def test_shell_and_adb_cannot_be_claimed_implemented_silently(self) -> None:
        for tool in ("shell", "adb"):
            with self.subTest(tool=tool):
                mutated = copy.deepcopy(self.contract)
                mutated["direct_tools"][tool]["current_status"] = "implemented"
                with self.assertRaises(AssertionError):
                    self.assert_boundary(mutated)

    def test_os_custody_cannot_move_to_provider(self) -> None:
        mutated = copy.deepcopy(self.contract)
        mutated["security_invariants"]["provider_owns_adbd_private_key"] = True
        with self.assertRaises(AssertionError):
            self.assert_boundary(mutated)

    def test_windows_cannot_be_productized_silently(self) -> None:
        mutated = copy.deepcopy(self.contract)
        mutated["windows_compatibility"]["current_status"] = "implemented"
        with self.assertRaises(AssertionError):
            self.assert_boundary(mutated)

    def test_canonical_documents_preserve_history_and_bind_owner_open(self) -> None:
        adr = ADR_PATH.read_text(encoding="utf-8")
        current_state = CURRENT_STATE_PATH.read_text(encoding="utf-8")
        readme = README_PATH.read_text(encoding="utf-8")

        historical = " ".join(adr.split()).casefold()
        for token in ("codex", "off-device", "shell", "adb"):
            self.assertIn(token, historical)
        self.assertIn("only built-in Agent", adr)
        self.assertIn("implementation work", historical)

        for document in (current_state, readme):
            normalized = " ".join(document.split()).casefold()
            for token in ("codex", "owner-open", "shell", "adb"):
                self.assertIn(token, normalized)
        self.assertIn("supersedes older semantic", current_state)
        self.assertIn("Codex is the single semantic", readme)
        self.assertIn("Explicitly not claimed", readme)


if __name__ == "__main__":
    unittest.main()
