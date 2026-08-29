from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-product-entrypoint.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_product_entrypoint", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ProductEntrypointVerifierTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.contract = self.contract_fixture()
        self.template = self.template_fixture()
        self.write_fixture()

    def tearDown(self) -> None:
        self.temp.cleanup()

    @staticmethod
    def contract_fixture() -> dict:
        return {
            "schema": module.EXPECTED_SCHEMA,
            "revision": module.EXPECTED_REVISION,
            "source_manifest": "apps/trillionnium-owner-open-host/Cargo.toml",
            "product_entrypoint": {
                "cargo_bin": "trillionnium-owner-open-r5-host",
                "source_path": "src/bin/r5_transport_host.rs",
                "role": "product_entrypoint",
                "install_name": "trillionnium-owner-open-r5-host",
                "required_cli": ["--provider"],
                "transport_options": ["--transport-core", "--event-store"],
                "default_internal_child": "trillionnium-owner-open-r5-core",
            },
            "internal_children": [
                {
                    "cargo_bin": "trillionnium-owner-open-r5-core",
                    "source_path": "src/bin/r5_control_host_v7.rs",
                    "role": "internal_execution_core",
                    "launch_flag": "--transport-core",
                    "default_sibling_binary": True,
                    "direct_product_install_entrypoint": False,
                }
            ],
            "non_product_binaries": [
                {
                    "cargo_bin": "trillionnium-owner-open-host",
                    "source_path": "src/main.rs",
                    "role": "foundation_protocol_stub",
                    "expected_marker": "UnavailableProvider",
                    "forbidden_as_product_entrypoint": True,
                    "forbidden_android_product_package": True,
                }
            ],
            "install_manifest_template": "packaging/owner-open-product/install-manifest.template.json",
            "android": {
                "required_module": "trillionnium-owner-open-r5-host",
                "required_internal_module": "trillionnium-owner-open-r5-core",
                "forbidden_modules": ["trillionnium-owner-open-host"],
                "target_files_evidence_required": True,
                "status": "EXTERNAL_HOLD",
            },
            "claim_ceiling": "SOURCE_ENTRYPOINT_SELECTED_TARGET_INSTALL_PENDING",
            "automatic_redispatch": False,
            "public_release": False,
        }

    @staticmethod
    def template_fixture() -> dict:
        return {
            "schema": module.EXPECTED_INSTALL_SCHEMA,
            "status": "UNMATERIALIZED_TEMPLATE",
            "source": {},
            "product_entrypoint": {
                "cargo_bin": "trillionnium-owner-open-r5-host"
            },
            "internal_children": [
                {"cargo_bin": "trillionnium-owner-open-r5-core"}
            ],
            "forbidden_installed_binaries": [
                {"cargo_bin": "trillionnium-owner-open-host"}
            ],
            "provider": {},
            "identity": {},
            "namespaces": {},
            "cgroup": {},
            "sockets": {},
            "stores": {},
            "selinux": {},
            "restart": {},
            "emergency_stop": {},
            "evidence": {},
            "automatic_redispatch": False,
            "public_release": False,
        }

    def write_fixture(self) -> None:
        contract_path = self.root / module.CONTRACT
        contract_path.parent.mkdir(parents=True, exist_ok=True)
        contract_path.write_text(json.dumps(self.contract), encoding="utf-8")

        package = self.root / "apps/trillionnium-owner-open-host"
        (package / "src/bin/r5_transport_host/entry").mkdir(parents=True, exist_ok=True)
        (package / "Cargo.toml").write_text(
            """
[package]
name = "trillionnium-owner-open-host"
autobins = false

[[bin]]
name = "trillionnium-owner-open-host"
path = "src/main.rs"

[[bin]]
name = "trillionnium-owner-open-r5-core"
path = "src/bin/r5_control_host_v7.rs"

[[bin]]
name = "trillionnium-owner-open-r5-host"
path = "src/bin/r5_transport_host.rs"
""".strip()
            + "\n",
            encoding="utf-8",
        )
        (package / "src/main.rs").write_text("struct UnavailableProvider;\n", encoding="utf-8")
        (package / "src/bin/r5_control_host_v7.rs").write_text("fn main() {}\n", encoding="utf-8")
        (package / "src/bin/r5_transport_host.rs").write_text("fn main() {}\n", encoding="utf-8")
        (package / "src/bin/r5_transport_host/entry/options.rs").write_text(
            '"--provider"; "--transport-core"; "--event-store"; '
            'path.set_file_name("trillionnium-owner-open-r5-core");\n',
            encoding="utf-8",
        )

        template_path = self.root / self.contract["install_manifest_template"]
        template_path.parent.mkdir(parents=True, exist_ok=True)
        template_path.write_text(json.dumps(self.template), encoding="utf-8")

        overlay = self.root / module.ANDROID_OVERLAY
        overlay.parent.mkdir(parents=True, exist_ok=True)
        overlay.write_text("# Android product not materialized in source fixture\n", encoding="utf-8")

    def rewrite(self) -> None:
        (self.root / module.CONTRACT).write_text(json.dumps(self.contract), encoding="utf-8")
        (self.root / self.contract["install_manifest_template"]).write_text(
            json.dumps(self.template), encoding="utf-8"
        )

    def test_source_selection_passes_with_android_hold_warning(self) -> None:
        report = module.verify(self.root)
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)
        self.assertTrue(report.facts["source_entrypoint_selected"])
        self.assertFalse(report.facts["target_install_qualified"])
        self.assertTrue(any("not materialized exactly" in value for value in report.warnings))

    def test_wrong_product_bin_fails(self) -> None:
        self.contract["product_entrypoint"]["cargo_bin"] = "trillionnium-owner-open-host"
        self.rewrite()
        report = module.verify(self.root)
        self.assertTrue(any("product Cargo bin" in value for value in report.errors))

    def test_missing_unavailable_provider_marker_fails(self) -> None:
        path = self.root / "apps/trillionnium-owner-open-host/src/main.rs"
        path.write_text("fn main() {}\n", encoding="utf-8")
        report = module.verify(self.root)
        self.assertTrue(any("non-product marker" in value for value in report.errors))

    def test_install_template_cannot_omit_forbidden_binary(self) -> None:
        self.template["forbidden_installed_binaries"] = []
        self.rewrite()
        report = module.verify(self.root)
        self.assertTrue(any("omits a forbidden product binary" in value for value in report.errors))

    def test_strict_android_requires_exact_product_modules(self) -> None:
        report = module.verify(self.root, strict_android=True)
        self.assertTrue(any("Android product entrypoint is not materialized" in value for value in report.errors))

    def test_forbidden_foundation_binary_in_android_overlay_fails_strict(self) -> None:
        overlay = self.root / module.ANDROID_OVERLAY
        overlay.write_text(
            "PRODUCT_PACKAGES += trillionnium-owner-open-r5-host "
            "trillionnium-owner-open-r5-core trillionnium-owner-open-host\n",
            encoding="utf-8",
        )
        report = module.verify(self.root, strict_android=True)
        self.assertTrue(any("forbidden=['trillionnium-owner-open-host']" in value for value in report.errors))


if __name__ == "__main__":
    unittest.main()
