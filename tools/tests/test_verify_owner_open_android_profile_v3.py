from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-android-profile-v3.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_android_profile_v3", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class VerifyOwnerOpenAndroidProfileV3Test(unittest.TestCase):
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
        return json.loads((self.root / module.PROFILE).read_text(encoding="utf-8"))

    def write_profile(self, value: dict) -> None:
        self.write(
            str(module.PROFILE),
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
        self.write(str(module.GENERATOR), "raise SystemExit(0)\n")
        fragment = "android-integration/owner-open-profile/generated/owner_open_packages_v2.mk"
        overlay = "android-integration/working-tree/vendor/trillionnium/config/common.mk"
        self.write(fragment, "PRODUCT_PACKAGES += rootfs-image\n")
        self.write(overlay, "PRODUCT_PACKAGES += LegacyAuthority\n")
        self.write_profile(
            {
                "schema": module.EXPECTED_SCHEMA,
                "revision": "fixture-v3",
                "profile_id": "owner-open-fixture-v3",
                "activation": {
                    "selected_in_current_product": False,
                    "product_make_fragment": fragment,
                    "current_audit_overlay": overlay,
                },
                "claims": {
                    "source_contract_only": True,
                    "rootlinux_payload_bound": False,
                    "android_bootstrap_bound": False,
                    "soong_modules_bound": False,
                    "init_services_bound": False,
                    "selinux_domains_bound": False,
                    "target_files_built": False,
                    "image_included": False,
                    "physical_device_observed": False,
                    "public_release": False,
                },
                "rootlinux_payload": {
                    "format": "squashfs",
                    "read_only": True,
                    "android_install_path": "/system_ext/etc/trillionnium/rootlinux/rootfs.squashfs",
                    "manifest_install_path": "/system_ext/etc/trillionnium/rootlinux/rootfs.manifest.json",
                    "runtime_mount_path": "/data/trillionnium/owner-open/root",
                    "writable_overlay_path": "/data/trillionnium/owner-open/overlay",
                    "state_root": "/data/trillionnium/owner-open/state",
                    "artifact_state": "UNBOUND_ROOTFS_IMAGE",
                    "manifest_state": "UNBOUND_ROOTFS_MANIFEST",
                    "required_entries": [
                        {
                            "role": "host",
                            "path": "/usr/libexec/trillionnium/host",
                            "state": "UNBOUND_ROOTFS_ENTRY",
                        },
                        {
                            "role": "codex",
                            "path": "/usr/bin/codex",
                            "state": "UNBOUND_ROOTFS_ENTRY",
                        },
                    ],
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
                        "name": "rootfs-image",
                        "role": "rootlinux_payload",
                        "destination": "etc/trillionnium/rootlinux/rootfs.squashfs",
                        "materialization": "UNBOUND_SOONG_MODULE",
                    },
                    {
                        "name": "rootfs-manifest",
                        "role": "rootlinux_manifest",
                        "destination": "etc/trillionnium/rootlinux/rootfs.manifest.json",
                        "materialization": "UNBOUND_SOONG_MODULE",
                    },
                    {
                        "name": "bootstrap",
                        "role": "android_native_bootstrap",
                        "destination": "bin/bootstrap",
                        "materialization": "UNBOUND_SOONG_MODULE",
                    },
                    {
                        "name": "emergency-stop",
                        "role": "android_native_emergency_stop",
                        "destination": "bin/emergency-stop",
                        "materialization": "UNBOUND_SOONG_MODULE",
                    },
                    {
                        "name": "init-rc",
                        "role": "android_init_config",
                        "destination": "etc/init/owner-open.rc",
                        "materialization": "UNBOUND_SOONG_MODULE",
                    },
                    {
                        "name": "profile-config",
                        "role": "profile_config",
                        "destination": "etc/trillionnium/owner-open/profile-v2.json",
                        "materialization": "UNBOUND_SOONG_MODULE",
                    },
                ],
                "required_services": [
                    {
                        "name": "bootstrap",
                        "owner": "android_init",
                        "state": "CONTRACT_ONLY",
                    },
                    {
                        "name": "host",
                        "owner": "rootlinux_supervisor",
                        "state": "CONTRACT_ONLY",
                    },
                ],
                "required_local_endpoints": [
                    {
                        "name": "client-ingress",
                        "state": "CONTRACT_ONLY",
                    },
                    {
                        "name": "adb-relay",
                        "state": "SOURCE_IMPLEMENTED_HOST_ONLY",
                    },
                ],
                "required_selinux_boundaries": [
                    "owner_open_client",
                    "owner_open_bootstrap",
                ],
                "forbidden_android_destinations_for_rootlinux_roles": [
                    "bin/trillionnium-owner-open-r5-host"
                ],
                "forbidden_product_packages": ["LegacyAuthority"],
                "forbidden_source_markers": ["CapabilityLease"],
                "claim_ceiling": "SOURCE_CONTRACT_ONLY_L0",
            }
        )

    def activate(self) -> dict:
        value = self.profile()
        value["activation"]["selected_in_current_product"] = True
        value["claims"]["source_contract_only"] = False
        for claim in (
            "rootlinux_payload_bound",
            "android_bootstrap_bound",
            "soong_modules_bound",
            "init_services_bound",
            "selinux_domains_bound",
            "target_files_built",
            "image_included",
        ):
            value["claims"][claim] = True
        value["rootlinux_payload"]["artifact_state"] = "BOUND_ROOTFS_IMAGE"
        value["rootlinux_payload"]["manifest_state"] = "BOUND_ROOTFS_MANIFEST"
        for entry in value["rootlinux_payload"]["required_entries"]:
            entry["state"] = "BOUND_ROOTFS_ENTRY"
        for item in value["required_product_modules"]:
            item["materialization"] = "BOUND_SOONG_MODULE"
        for service in value["required_services"]:
            service["state"] = (
                "BOUND_INIT_SERVICE"
                if service["owner"] == "android_init"
                else "BOUND_ROOTLINUX_SERVICE"
            )
        for endpoint in value["required_local_endpoints"]:
            endpoint["state"] = "BOUND_ENDPOINT"
        self.write_profile(value)
        fragment = value["activation"]["product_make_fragment"]
        overlay = value["activation"]["current_audit_overlay"]
        self.write(overlay, f"include {fragment}\n")
        return value

    def test_foundation_profile_preserves_rootlinux_payload_truth(self) -> None:
        report = module.verify(self.root, strict=False)
        self.assertEqual(report.errors, [])
        self.assertEqual(report.facts["rootlinux_payload_format"], "squashfs")
        self.assertEqual(
            report.facts["rootlinux_entry_states"]["host"],
            "UNBOUND_ROOTFS_ENTRY",
        )
        self.assertGreaterEqual(len(report.warnings), 2)

    def test_rootlinux_runtime_cannot_be_reserved_as_android_binary(self) -> None:
        value = self.profile()
        value["required_product_modules"].append(
            {
                "name": "bad-host",
                "role": "bad-rootlinux-host",
                "destination": "bin/trillionnium-owner-open-r5-host",
                "materialization": "UNBOUND_SOONG_MODULE",
            }
        )
        self.write_profile(value)
        report = module.verify(self.root, strict=False)
        self.assertTrue(
            any("incorrectly reserved as Android executable" in item for item in report.errors)
        )

    def test_payload_image_claim_requires_payload_and_bootstrap_binding(self) -> None:
        value = self.profile()
        value["claims"]["image_included"] = True
        value["claims"]["target_files_built"] = True
        value["claims"]["soong_modules_bound"] = True
        value["claims"]["init_services_bound"] = True
        value["claims"]["selinux_domains_bound"] = True
        self.write_profile(value)
        report = module.verify(self.root, strict=False)
        self.assertTrue(
            any("image_included=true requires rootlinux_payload_bound=true" in item for item in report.errors)
        )
        self.assertTrue(
            any("image_included=true requires android_bootstrap_bound=true" in item for item in report.errors)
        )

    def test_bound_payload_claim_requires_image_manifest_and_all_entries(self) -> None:
        value = self.profile()
        value["claims"]["rootlinux_payload_bound"] = True
        self.write_profile(value)
        report = module.verify(self.root, strict=False)
        self.assertTrue(any("BOUND_ROOTFS_IMAGE" in item for item in report.errors))
        self.assertTrue(any("BOUND_ROOTFS_MANIFEST" in item for item in report.errors))
        self.assertTrue(any("unbound entries" in item for item in report.errors))

    def test_strict_service_state_depends_on_lifecycle_owner(self) -> None:
        value = self.activate()
        value["required_services"][1]["state"] = "BOUND_INIT_SERVICE"
        self.write_profile(value)
        report = module.verify(self.root, strict=True)
        self.assertTrue(
            any("mis-owned services" in item for item in report.errors)
        )

    def test_strict_v3_passes_only_after_complete_payload_and_native_binding(self) -> None:
        self.activate()
        report = module.verify(self.root, strict=True)
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)
        self.assertEqual(
            report.facts["service_states_v3"]["host"],
            "BOUND_ROOTLINUX_SERVICE",
        )
        self.assertTrue(
            all(state == "BOUND_ENDPOINT" for state in report.facts["endpoint_states_v3"].values())
        )


if __name__ == "__main__":
    unittest.main()
