#!/usr/bin/env python3
from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]
CATALOG_PATH = (
    ROOT
    / "crates/trillionnium-os-types/contracts/agent-typed-operation-catalog-v1.json"
)
RUST_PATH = ROOT / "crates/trillionnium-os-types/src/typed_operation_catalog.rs"
BOUNDARY_PATH = ROOT / "docs/contracts/agent-exec-adb-windows-product-boundary-v2.json"
CATALOG_SHA256 = "c4efd224e75bc21ab95753eac4f183732c447e315ac89d4369bc5185a4997453"


def reject_duplicate_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate catalog key: {key}")
        value[key] = item
    return value


def reject_nonfinite(token: str) -> object:
    raise ValueError(f"non-finite catalog number: {token}")


def load_strict(payload: str) -> dict[str, object]:
    value = json.loads(
        payload,
        object_pairs_hook=reject_duplicate_pairs,
        parse_constant=reject_nonfinite,
    )
    if not isinstance(value, dict):
        raise ValueError("catalog root must be an object")
    return value


class AgentTypedOperationCatalogTest(unittest.TestCase):
    def setUp(self) -> None:
        self.raw = CATALOG_PATH.read_text(encoding="utf-8")
        self.catalog = load_strict(self.raw)

    def assert_keys(self, value: object, expected: set[str]) -> None:
        self.assertIsInstance(value, dict)
        self.assertEqual(set(value), expected)

    def assert_semantics(self, catalog: dict[str, object]) -> None:
        self.assert_keys(
            catalog,
            {
                "schema",
                "catalog_id",
                "revision",
                "status",
                "effect_authority",
                "product_signature",
                "principals",
                "operations",
                "durability",
                "promotion_gates",
            },
        )
        self.assertEqual(
            catalog["schema"], "org.trillionnium.agent-typed-operation-catalog.v1"
        )
        self.assertEqual(catalog["revision"], 2)
        self.assertEqual(catalog["status"], "frozen_source_candidate_hold")
        self.assertIs(catalog["effect_authority"], False)

        signature = catalog["product_signature"]
        self.assert_keys(
            signature,
            {
                "status",
                "algorithm",
                "catalog_sha256_required",
                "detached_signature_required",
                "key_owner",
                "agent_key_access",
            },
        )
        self.assertEqual(signature["status"], "absent_hold")
        self.assertEqual(signature["algorithm"], "ed25519")
        self.assertIs(signature["catalog_sha256_required"], True)
        self.assertIs(signature["detached_signature_required"], True)
        self.assertIs(signature["agent_key_access"], False)

        self.assertEqual(
            catalog["principals"],
            [
                {
                    "provider_id": "openai-codex",
                    "agent_id": "agent-codex-direct-v1",
                    "uid": 5901,
                    "gid": 5901,
                    "selinux_domain": "u:r:trillionnium_codex_agent:s0",
                }
            ],
        )

        operations = catalog["operations"]
        self.assertIsInstance(operations, list)
        self.assertEqual(len(operations), 3)
        by_id = {operation["operation_id"]: operation for operation in operations}
        self.assertEqual(
            set(by_id),
            {
                "exec.launch_package.settings.v1",
                "adb.launch_package.settings.user.v1",
                "adb.launch_package.settings.engineering-recovery.v1",
            },
        )
        for operation in operations:
            self.assert_keys(
                operation,
                {
                    "operation_id",
                    "adapter",
                    "agent_arguments",
                    "execution_descriptor",
                    "admission",
                },
            )
            self.assertEqual(
                operation["agent_arguments"],
                {"shape": "closed_empty_object", "unknown_fields": "reject"},
            )
            admission = operation["admission"]
            self.assertIs(admission["one_shot_lease_required"], True)
            self.assertIs(admission["single_delivery_attempt_required"], True)
            self.assertEqual(
                admission["user_consent"], "os_policy_decides_before_prepared"
            )

        expected_launch = [
            "activity",
            "start-activity",
            "--user",
            "current",
            "-a",
            "android.intent.action.MAIN",
            "-c",
            "android.intent.category.LAUNCHER",
            "-p",
            "com.android.settings",
        ]
        typed_exec = by_id["exec.launch_package.settings.v1"]
        self.assertEqual(typed_exec["adapter"], "typed_exec")
        self.assertEqual(
            typed_exec["admission"],
            {
                "product_variants": ["user", "userdebug", "eng", "recovery"],
                "risk_class": "foreground_app_launch",
                "one_shot_lease_required": True,
                "user_consent": "os_policy_decides_before_prepared",
                "single_delivery_attempt_required": True,
            },
        )
        exec_descriptor = typed_exec["execution_descriptor"]
        self.assert_keys(
            exec_descriptor,
            {
                "executable",
                "argv0",
                "argv",
                "uid",
                "gid",
                "selinux_domain",
                "cgroup_profile",
                "seccomp_profile",
                "capabilities",
                "environment",
                "stdin",
                "filesystem_scope",
                "network_scope",
                "deadline_ms",
                "stdout_limit_bytes",
                "stderr_limit_bytes",
                "total_output_limit_bytes",
                "descendant_process_policy",
                "opaque_fd_passing",
            },
        )
        self.assertEqual(exec_descriptor["executable"], "/system/bin/cmd")
        self.assertEqual(exec_descriptor["argv0"], "cmd")
        self.assertEqual(exec_descriptor["argv"], expected_launch)
        self.assertEqual(exec_descriptor["uid"], 2000)
        self.assertEqual(exec_descriptor["gid"], 2000)
        self.assertEqual(
            exec_descriptor["selinux_domain"], "u:r:trillionnium_typed_exec:s0"
        )
        self.assertEqual(exec_descriptor["cgroup_profile"], "typed-exec-launch-package-v1")
        self.assertEqual(exec_descriptor["seccomp_profile"], "typed-exec-launch-package-v1")
        self.assertEqual(
            exec_descriptor["environment"],
            {"ANDROID_DATA": "/data", "ANDROID_ROOT": "/system", "PATH": "/system/bin"},
        )

        adb_expectations = {
            "adb.launch_package.settings.user.v1": {
                "transport": "os_owned_local_user_product_adbd",
                "adbd_key_custody": "os_owned_user_product_not_agent_addressable",
                "product_identity": "os_selected_local_user_device_avb_identity",
                "profile": "typed-adb-launch-package-user-v1",
                "variants": ["user"],
                "risk_class": "foreground_app_launch_product_fallback",
            },
            "adb.launch_package.settings.engineering-recovery.v1": {
                "transport": "os_owned_local_engineering_recovery_adbd",
                "adbd_key_custody": "os_owned_engineering_recovery_not_agent_addressable",
                "product_identity": "os_selected_local_engineering_recovery_avb_identity",
                "profile": "typed-adb-launch-package-engineering-recovery-v1",
                "variants": ["userdebug", "eng", "recovery"],
                "risk_class": "foreground_app_launch_engineering_recovery",
            },
        }
        adb_descriptors = []
        for operation_id, expected in adb_expectations.items():
            typed_adb = by_id[operation_id]
            self.assertEqual(typed_adb["adapter"], "typed_adb")
            self.assertEqual(
                typed_adb["admission"],
                {
                    "product_variants": expected["variants"],
                    "risk_class": expected["risk_class"],
                    "one_shot_lease_required": True,
                    "user_consent": "os_policy_decides_before_prepared",
                    "single_delivery_attempt_required": True,
                    "direct_system_api_unavailable_proof_required": True,
                },
            )
            adb_descriptor = typed_adb["execution_descriptor"]
            self.assert_keys(
                adb_descriptor,
                {
                    "target",
                    "transport",
                    "service",
                    "service_arguments",
                    "serial",
                    "host",
                    "port",
                    "adbd_key_custody",
                    "product_identity",
                    "cgroup_profile",
                    "seccomp_profile",
                    "capabilities",
                    "environment",
                    "stdin",
                    "filesystem_scope",
                    "network_scope",
                    "deadline_ms",
                    "stdout_limit_bytes",
                    "stderr_limit_bytes",
                    "total_output_limit_bytes",
                    "descendant_process_policy",
                    "opaque_fd_passing",
                },
            )
            self.assertEqual(adb_descriptor["target"], "self_device_only")
            self.assertEqual(adb_descriptor["transport"], expected["transport"])
            self.assertEqual(adb_descriptor["service"], "abb_exec")
            self.assertEqual(adb_descriptor["service_arguments"], expected_launch)
            self.assertEqual(adb_descriptor["adbd_key_custody"], expected["adbd_key_custody"])
            self.assertEqual(adb_descriptor["product_identity"], expected["product_identity"])
            self.assertEqual(adb_descriptor["cgroup_profile"], expected["profile"])
            self.assertEqual(adb_descriptor["seccomp_profile"], expected["profile"])
            self.assertEqual(adb_descriptor["environment"], {})
            for forbidden_target in ("serial", "host", "port"):
                self.assertIsNone(adb_descriptor[forbidden_target])
            adb_descriptors.append(adb_descriptor)

        self.assertTrue(
            set(adb_expectations["adb.launch_package.settings.user.v1"]["variants"]).isdisjoint(
                adb_expectations["adb.launch_package.settings.engineering-recovery.v1"]["variants"]
            )
        )

        for descriptor in (exec_descriptor, *adb_descriptors):
            self.assertEqual(descriptor["capabilities"], [])
            self.assertEqual(descriptor["stdin"], "closed")
            self.assertEqual(descriptor["deadline_ms"], 15000)
            self.assertEqual(descriptor["total_output_limit_bytes"], 65536)
            self.assertIs(descriptor["opaque_fd_passing"], False)
            self.assertEqual(
                descriptor["descendant_process_policy"],
                "no_background_descendants_kill_cgroup_at_deadline",
            )

        forbidden_tokens = {
            "sh",
            "shell",
            "shell,v2,raw",
            "remount",
            "tcp",
            "root",
        }
        for descriptor, argv_key in (
            (exec_descriptor, "argv"),
            *((descriptor, "service_arguments") for descriptor in adb_descriptors),
        ):
            self.assertTrue(forbidden_tokens.isdisjoint(descriptor[argv_key]))
            pairs = [
                descriptor[argv_key][index:index + 2]
                for index in range(len(descriptor[argv_key]) - 1)
            ]
            self.assertNotIn(["sh", "-c"], pairs)

        self.assertEqual(
            catalog["durability"],
            {
                "prepared_before_effect": True,
                "terminal_result_before_return": True,
                "exact_response_replay": True,
                "outer_ack_before_reclamation": True,
                "operation_epoch_or_high_water_required": True,
                "indeterminate_outcome_policy": "hold_without_blind_retry",
            },
        )
        gates = catalog["promotion_gates"]
        self.assertEqual(
            set(gates),
            {
                "catalog_detached_signature_verified",
                "catalog_bound_to_avb_product_identity",
                "typed_exec_backend_installed",
                "typed_adb_backend_installed",
                "broker_durability_wired",
                "selinux_cgroup_seccomp_installed",
                "physical_restart_replay_evidence",
                "locked_user_device_evidence",
            },
        )
        self.assertTrue(all(value is False for value in gates.values()))

    def test_catalog_is_canonical_measured_closed_and_non_authorizing(self) -> None:
        self.assertEqual(hashlib.sha256(self.raw.encode()).hexdigest(), CATALOG_SHA256)
        self.assertEqual(
            self.raw,
            json.dumps(self.catalog, indent=2, ensure_ascii=True) + "\n",
        )
        self.assert_semantics(self.catalog)

    def test_duplicate_and_nonfinite_json_are_rejected(self) -> None:
        duplicate = self.raw.replace(
            '  "revision": 2,\n', '  "revision": 2,\n  "revision": 3,\n', 1
        )
        with self.assertRaisesRegex(ValueError, "duplicate catalog key: revision"):
            load_strict(duplicate)
        with self.assertRaisesRegex(ValueError, "non-finite catalog number"):
            load_strict(self.raw.replace('"revision": 2', '"revision": NaN', 1))

    def test_authority_target_argv_and_signature_widening_fail_semantics(self) -> None:
        mutations: list[tuple[tuple[object, ...], object]] = [
            (("effect_authority",), True),
            (("product_signature", "status"), "verified"),
            (("product_signature", "agent_key_access"), True),
            (("operations", 0, "agent_arguments", "shape"), "open_object"),
            (("operations", 0, "execution_descriptor", "executable"), "/system/bin/sh"),
            (("operations", 0, "execution_descriptor", "uid"), 0),
            (("operations", 1, "execution_descriptor", "target"), "caller_serial"),
            (("operations", 1, "execution_descriptor", "service"), "shell,v2,raw"),
            (("operations", 1, "admission", "product_variants"), ["user", "eng"]),
            (
                ("operations", 2, "execution_descriptor", "transport"),
                "os_owned_local_user_product_adbd",
            ),
            (("promotion_gates", "typed_adb_backend_installed"), True),
        ]
        for path, replacement in mutations:
            with self.subTest(path=path):
                mutated = copy.deepcopy(self.catalog)
                current: object = mutated
                for component in path[:-1]:
                    current = current[component]
                current[path[-1]] = replacement
                with self.assertRaises(AssertionError):
                    self.assert_semantics(mutated)

    def test_rust_model_embeds_hash_and_has_no_product_authority_constructor(self) -> None:
        source = RUST_PATH.read_text(encoding="utf-8")
        production = source.split("\n#[cfg(test)]\nmod tests", 1)[0]
        self.assertIn(CATALOG_SHA256, source)
        self.assertIn("materialize_source_candidate", source)
        self.assertIn("ProductCatalogAuthorityUnavailable", source)
        self.assertNotIn("pub struct ProductCatalogAuthority", source)
        self.assertNotIn("ShellV2Raw", source)
        self.assertIn("agent_principal_registry", production)
        self.assertIn("from_registration_fields", production)
        self.assertIn("PermissionPrincipal::from_stable_principal", production)
        self.assertNotIn("agent_descriptor_registry", production)
        self.assertNotIn("identity_key_sha256", production)

    def test_current_boundary_accepts_direct_tools_but_keeps_backends_held(self) -> None:
        boundary = load_strict(BOUNDARY_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            boundary["decision"],
            "codex_only_direct_system_api_accessibility_shell_and_adb",
        )
        self.assertEqual(
            boundary["direct_tools"]["shell"]["current_status"],
            "standard_source_wired_artifact_device_authority_hold",
        )
        self.assertEqual(
            boundary["direct_tools"]["adb"]["current_status"],
            "not_implemented_hold",
        )
        self.assertIn("minimal_rebuilt_root_linux_with_green_production_tcb", boundary["release_gates"])


if __name__ == "__main__":
    unittest.main()
