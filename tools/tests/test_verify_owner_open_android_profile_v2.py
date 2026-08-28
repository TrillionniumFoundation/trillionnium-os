from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-android-profile-v2.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_android_profile_v2", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class VerifyOwnerOpenAndroidProfileV2Test(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.write_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, relative: str, value: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(value, encoding="utf-8")

    def profile(self) -> dict:
        return json.loads((self.root / module.base.PROFILE).read_text(encoding="utf-8"))

    def write_profile(self, value: dict) -> None:
        self.write(
            str(module.base.PROFILE),
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )

    def write_fixture(self) -> None:
        for relative in (
            "apps/host/Cargo.toml",
            "tools/mcp.py",
            "tools/broker.py",
            "tools/supervisor.py",
            "tools/relay.py",
            "tools/qualifier.py",
        ):
            self.write(relative, "SOURCE = True\n")
        self.write(
            str(module.base.GENERATOR),
            "import sys\nraise SystemExit(0)\n",
        )
        fragment = "android-integration/owner-open-profile/generated/owner_open_packages.mk"
        overlay = "android-integration/working-tree/vendor/trillionnium/config/common.mk"
        self.write(fragment, "PRODUCT_PACKAGES += owner-open-host\n")
        self.write(overlay, "PRODUCT_PACKAGES += LegacyAuthority\n")
        self.write_profile(
            {
                "schema": module.base.EXPECTED_SCHEMA,
                "revision": "fixture-v2",
                "profile_id": "owner-open-fixture",
                "activation": {
                    "selected_in_current_product": False,
                    "product_make_fragment": fragment,
                    "current_audit_overlay": overlay,
                },
                "claims": {
                    "source_contract_only": True,
                    "soong_modules_bound": False,
                    "init_services_bound": False,
                    "selinux_domains_bound": False,
                    "target_files_built": False,
                    "image_included": False,
                    "physical_device_observed": False,
                    "public_release": False,
                },
                "required_source_artifacts": [
                    {"role": "host", "path": "apps/host/Cargo.toml"},
                    {"role": "mcp", "path": "tools/mcp.py"},
                    {"role": "broker", "path": "tools/broker.py"},
                    {"role": "supervisor", "path": "tools/supervisor.py"},
                    {"role": "relay", "path": "tools/relay.py"},
                    {"role": "qualifier", "path": "tools/qualifier.py"},
                ],
                "required_product_modules": [
                    {
                        "name": "owner-open-host",
                        "materialization": "UNBOUND_SOONG_MODULE",
                    }
                ],
                "required_services": [
                    {
                        "name": "owner_open_rootlinux",
                        "state": "CONTRACT_ONLY",
                    },
                    {
                        "name": "owner_open_emergency_stop",
                        "state": "CONTRACT_ONLY",
                    },
                ],
                "required_local_endpoints": [
                    {
                        "name": "owner_open_broker",
                        "state": "CONTRACT_ONLY",
                    },
                    {
                        "name": "adb_smart_socket_relay",
                        "state": "SOURCE_IMPLEMENTED_HOST_ONLY",
                    },
                ],
                "required_selinux_boundaries": [
                    "owner_open_client",
                    "owner_open_bootstrap",
                    "owner_open_emergency_stop",
                ],
                "forbidden_product_packages": ["LegacyAuthority"],
                "forbidden_source_markers": ["CapabilityLease"],
                "claim_ceiling": "SOURCE_CONTRACT_ONLY_L0",
            }
        )

    def activate_fully(self) -> dict:
        value = self.profile()
        value["activation"]["selected_in_current_product"] = True
        value["claims"]["source_contract_only"] = False
        for field_name in (
            "soong_modules_bound",
            "init_services_bound",
            "selinux_domains_bound",
            "target_files_built",
            "image_included",
        ):
            value["claims"][field_name] = True
        for item in value["required_product_modules"]:
            item["materialization"] = "BOUND_SOONG_MODULE"
        for item in value["required_services"]:
            item["state"] = "BOUND_INIT_SERVICE"
        for item in value["required_local_endpoints"]:
            item["state"] = "BOUND_ENDPOINT"
        self.write_profile(value)
        fragment = value["activation"]["product_make_fragment"]
        overlay = value["activation"]["current_audit_overlay"]
        self.write(overlay, f"include {fragment}\n")
        return value

    def test_foundation_profile_is_consistent_but_remains_held(self) -> None:
        report = module.verify(self.root, strict=False)
        self.assertEqual(report.errors, [])
        self.assertGreaterEqual(len(report.warnings), 2)
        self.assertEqual(report.facts["consistency_verifier"], "v2")
        self.assertEqual(
            report.facts["service_states"]["owner_open_rootlinux"],
            "CONTRACT_ONLY",
        )

    def test_strict_mode_rejects_contract_only_service_and_endpoint_states(self) -> None:
        report = module.verify(self.root, strict=True)
        self.assertTrue(
            any("source_contract_only=false" in item for item in report.errors)
        )
        self.assertTrue(any("unbound services" in item for item in report.errors))
        self.assertTrue(any("unbound endpoints" in item for item in report.errors))

    def test_image_claim_requires_target_files_and_all_materialization_claims(self) -> None:
        value = self.profile()
        value["claims"]["image_included"] = True
        self.write_profile(value)
        report = module.verify(self.root, strict=False)
        self.assertTrue(
            any("image_included=true requires target_files_built=true" in item for item in report.errors)
        )

        value["claims"]["target_files_built"] = True
        self.write_profile(value)
        report = module.verify(self.root, strict=False)
        for dependency in (
            "soong_modules_bound",
            "init_services_bound",
            "selinux_domains_bound",
        ):
            self.assertTrue(
                any(
                    f"target_files_built=true requires {dependency}=true" in item
                    for item in report.errors
                )
            )

    def test_selection_requires_soong_binding(self) -> None:
        value = self.profile()
        value["activation"]["selected_in_current_product"] = True
        self.write_profile(value)
        fragment = value["activation"]["product_make_fragment"]
        overlay = value["activation"]["current_audit_overlay"]
        self.write(overlay, f"include {fragment}\n")
        report = module.verify(self.root, strict=False)
        self.assertTrue(
            any(
                "selected_in_current_product=true requires soong_modules_bound=true"
                in item
                for item in report.errors
            )
        )

    def test_physical_and_release_claims_have_required_predecessors(self) -> None:
        value = self.profile()
        value["claims"]["physical_device_observed"] = True
        value["claims"]["public_release"] = True
        self.write_profile(value)
        report = module.verify(self.root, strict=False)
        self.assertTrue(
            any(
                "physical_device_observed=true requires image_included=true" in item
                for item in report.errors
            )
        )

        value["claims"]["physical_device_observed"] = False
        self.write_profile(value)
        report = module.verify(self.root, strict=False)
        self.assertTrue(
            any(
                "public_release=true requires physical_device_observed=true" in item
                for item in report.errors
            )
        )

    def test_missing_selinux_boundary_is_rejected(self) -> None:
        value = self.profile()
        value["required_selinux_boundaries"] = []
        self.write_profile(value)
        report = module.verify(self.root, strict=False)
        self.assertTrue(
            any("required_selinux_boundaries must be a nonempty" in item for item in report.errors)
        )

    def test_strict_mode_passes_only_after_full_consistent_binding(self) -> None:
        self.activate_fully()
        report = module.verify(self.root, strict=True)
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)
        self.assertTrue(
            all(state == "BOUND_INIT_SERVICE" for state in report.facts["service_states"].values())
        )
        self.assertTrue(
            all(state == "BOUND_ENDPOINT" for state in report.facts["endpoint_states"].values())
        )


if __name__ == "__main__":
    unittest.main()
