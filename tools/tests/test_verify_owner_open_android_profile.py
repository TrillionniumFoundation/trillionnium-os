from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-android-profile.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_android_profile", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class VerifyOwnerOpenAndroidProfileTest(unittest.TestCase):
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
        return json.loads((self.root / module.PROFILE).read_text())

    def write_profile(self, value: dict) -> None:
        self.write(str(module.PROFILE), json.dumps(value, indent=2, sort_keys=True) + "\n")

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
            str(module.GENERATOR),
            "import sys\nraise SystemExit(0)\n",
        )
        fragment = "android-integration/owner-open-profile/generated/owner_open_packages.mk"
        overlay = "android-integration/working-tree/vendor/trillionnium/config/common.mk"
        self.write(fragment, "PRODUCT_PACKAGES += owner-open-host\n")
        self.write(overlay, "PRODUCT_PACKAGES += LegacyAuthority\n")
        self.write_profile(
            {
                "schema": module.EXPECTED_SCHEMA,
                "revision": "fixture",
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
                "forbidden_product_packages": ["LegacyAuthority"],
                "forbidden_source_markers": ["CapabilityLease"],
                "claim_ceiling": "SOURCE_CONTRACT_ONLY_L0",
            }
        )

    def test_foundation_mode_reports_holds_without_false_failure(self) -> None:
        report = module.verify(self.root, strict=False)
        self.assertEqual(report.errors, [])
        self.assertGreaterEqual(len(report.warnings), 2)
        self.assertEqual(report.facts["selected_in_current_product"], False)
        self.assertEqual(report.facts["unbound_product_modules"], ["owner-open-host"])

    def test_strict_mode_rejects_unselected_unbound_legacy_graph(self) -> None:
        report = module.verify(self.root, strict=True)
        self.assertTrue(any("requires profile activation" in item for item in report.errors))
        self.assertTrue(any("unbound Soong modules" in item for item in report.errors))
        self.assertTrue(any("forbidden packages" in item for item in report.errors))

    def test_current_product_cannot_include_unbound_fragment(self) -> None:
        value = self.profile()
        fragment = value["activation"]["product_make_fragment"]
        overlay = value["activation"]["current_audit_overlay"]
        self.write(overlay, f"include {fragment}\n")
        report = module.verify(self.root, strict=False)
        self.assertTrue(any("before activation and Soong binding" in item for item in report.errors))

    def test_generated_fragment_cannot_contain_forbidden_package(self) -> None:
        value = self.profile()
        self.write(
            value["activation"]["product_make_fragment"],
            "PRODUCT_PACKAGES += LegacyAuthority\n",
        )
        report = module.verify(self.root, strict=False)
        self.assertTrue(any("contains forbidden legacy tokens" in item for item in report.errors))

    def test_missing_required_source_fails(self) -> None:
        (self.root / "tools/relay.py").unlink()
        report = module.verify(self.root, strict=False)
        self.assertTrue(any("source artifact relay is missing" in item for item in report.errors))

    def test_strict_mode_can_pass_only_after_full_binding_and_selection(self) -> None:
        value = self.profile()
        value["activation"]["selected_in_current_product"] = True
        for field_name in (
            "soong_modules_bound",
            "init_services_bound",
            "selinux_domains_bound",
            "target_files_built",
            "image_included",
        ):
            value["claims"][field_name] = True
        value["required_product_modules"][0]["materialization"] = "BOUND_SOONG_MODULE"
        self.write_profile(value)
        fragment = value["activation"]["product_make_fragment"]
        overlay = value["activation"]["current_audit_overlay"]
        self.write(overlay, f"include {fragment}\n")
        report = module.verify(self.root, strict=True)
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)


if __name__ == "__main__":
    unittest.main()
