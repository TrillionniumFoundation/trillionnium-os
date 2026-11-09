from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-android-source-closure-v2.py"
spec = importlib.util.spec_from_file_location(
    "verify_owner_open_android_source_closure_v2", SCRIPT
)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)

ROOT = Path(__file__).resolve().parents[2]


def copy_file(source_root: Path, destination_root: Path, relative: Path) -> None:
    source = source_root / relative
    destination = destination_root / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source, destination)


class VerifyOwnerOpenAndroidSourceClosureTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="owner-open-android-source-")
        self.root = Path(self.temp.name)
        profile = json.loads((ROOT / module.PROFILE).read_text(encoding="utf-8"))
        paths = {
            module.PROFILE,
            module.GENERATED_FRAGMENT,
            module.COMMON_OWNER_OPEN,
            module.SUPERVISOR_CONFIG,
        }
        paths.update(module.BASE.ACTIVE_SOURCE_FILES)
        for field_name in ("semantic_contract", "architecture_decision"):
            paths.add(Path(profile[field_name]))
        for item in profile["required_source_artifacts"]:
            paths.add(Path(item["path"]))
        for relative in sorted(paths):
            copy_file(ROOT, self.root, relative)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def rewrite(self, relative: Path, old: str, new: str) -> None:
        path = self.root / relative
        text = path.read_text(encoding="utf-8")
        self.assertIn(old, text)
        path.write_text(text.replace(old, new, 1), encoding="utf-8")

    def test_checked_in_source_closure_is_complete_without_external_claims(self) -> None:
        report = module.verify(self.root)
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)
        self.assertTrue(report.facts["source_modules_authored"])
        self.assertFalse(report.facts["soong_compiled"])
        self.assertFalse(report.facts["target_files_built"])
        self.assertFalse(report.facts["physical_device_observed"])
        self.assertFalse(report.facts["public_release"])
        self.assertFalse(report.facts["automatic_effect_redispatch"])
        self.assertEqual(
            report.facts["semantic_contract"],
            "docs/GLOBAL_DEVELOPMENT_PROGRAM.md",
        )
        self.assertEqual(
            report.facts["architecture_decision"],
            "docs/GLOBAL_ARCHITECTURE.md",
        )

    def test_r52_unknown_policy_grant_and_marker_clear_fail_closed(self) -> None:
        relative = module.ANDROID_ROOT / "sepolicy/private/domains.te"
        path = self.root / relative
        original = path.read_text()
        for extra in (
            "set_prop(shell, trillionnium_owner_open_stop_prop)",
            "allow shell trillionnium_owner_open_stop_prop:property_service set;",
            "allow trillionnium_owner_open_client trillionnium_owner_open_inhibit_file:file read;",
            "allow trillionnium_owner_open_bootstrap trillionnium_owner_open_inhibit_file:file unlink;",
            "allow { shell } core_data_file_type:file r_file_perms;",
        ):
            with self.subTest(extra=extra):
                path.write_text(original + "\n" + extra + "\n")
                report = module.verify(self.root)
                self.assertFalse(report.ok, report.facts)
                self.assertTrue(any("policy generation source digest differs" in e for e in report.errors), report.errors)
        path.write_text(original)

    def test_r52_ingress_control_availability_unknown_services_and_order_fail_closed(self) -> None:
        path = self.root / module.ANDROID_ROOT / "init/trillionnium-owner-open.rc"
        original = path.read_text()
        for changed in (
            original.replace("start trillionnium_owner_open_ingress\n    exec_start trillionnium_owner_open_verify", "exec_start trillionnium_owner_open_verify\n    start trillionnium_owner_open_ingress"),
            original + "\non property:trillionnium.owner_open.ready=0\n    stop trillionnium_owner_open_ingress\n",
            original + "\nservice unexpected_owner_service /system/bin/true\n    user root\n",
        ):
            with self.subTest(changed=changed[-100:]):
                path.write_text(changed)
                self.assertFalse(module.verify(self.root).ok)
        path.write_text(original)

    def test_missing_profile_reference_fails_closed(self) -> None:
        (self.root / "docs/GLOBAL_ARCHITECTURE.md").unlink()
        report = module.verify(self.root)
        self.assertFalse(report.ok)
        self.assertTrue(
            any("profile architecture_decision" in error for error in report.errors),
            report.errors,
        )

    def test_profile_reference_traversal_fails_closed(self) -> None:
        path = self.root / module.PROFILE
        value = json.loads(path.read_text(encoding="utf-8"))
        value["semantic_contract"] = "../docs/GLOBAL_DEVELOPMENT_PROGRAM.md"
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        report = module.verify(self.root)
        self.assertFalse(report.ok)
        self.assertTrue(
            any("semantic_contract is not canonical" in error for error in report.errors),
            report.errors,
        )

    def test_missing_android_runtime_profile_fails_closed(self) -> None:
        (self.root / module.ANDROID_ROOT / "config/profile-v3.json").unlink()
        report = module.verify(self.root)
        self.assertFalse(report.ok)
        self.assertTrue(
            any(
                "android_runtime_profile" in error or "profile-v3.json" in error
                for error in report.errors
            ),
            report.errors,
        )

    def test_soong_module_drift_fails_closed(self) -> None:
        self.rewrite(
            module.ANDROID_ROOT / "Android.bp",
            'name: "trillionnium-owner-open-ingress"',
            'name: "trillionnium-owner-open-ingress-drift"',
        )
        report = module.verify(self.root)
        self.assertTrue(any("Android.bp misses required modules" in error for error in report.errors))

    def test_bootstrap_and_profile_path_drift_fails_closed(self) -> None:
        self.rewrite(
            module.ANDROID_ROOT / "native/owner_open_bootstrap.cpp",
            '"/usr/libexec/trillionnium/provider-adapter"',
            '"/opt/other-runtime"',
        )
        report = module.verify(self.root)
        self.assertTrue(any("bootstrap does not bind" in error for error in report.errors))

    def test_unknown_product_package_and_init_service_fail_closed(self) -> None:
        for relative, old, new, error in (
            (module.ANDROID_ROOT / "product.mk", "    TrillionniumOwnerOpenShell", "    ArbitraryPrivilegeModule", "PRODUCT_PACKAGES differs"),
            (module.ANDROID_ROOT / "init/trillionnium-owner-open.rc", "service trillionnium_owner_open_verify ", "service arbitrary_privileged_service ", "init service set differs"),
            (module.ANDROID_ROOT / "Android.bp", 'name: "trillionnium-sun-btfm-modprobe-init-rc"', 'name: "arbitrary-module"', "Android.bp module inventory differs"),
        ):
            with self.subTest(relative=relative):
                path = self.root / relative
                original = path.read_text(encoding="utf-8")
                self.rewrite(relative, old, new)
                report = module.verify(self.root)
                self.assertTrue(any(error in value for value in report.errors), report.errors)
                path.write_text(original, encoding="utf-8")

    def test_active_variant_claim_provider_and_payload_drift_fail_closed(self) -> None:
        path = self.root / module.BASE.ACTIVE_RUNTIME_PROFILE
        original = path.read_text(encoding="utf-8")
        for field, member, value in (
            ("claims", "physical_device_observed", True),
            ("provider", "long_lived_credentials_on_phone", True),
            ("provider", "automatic_redispatch", True),
            ("rootlinux_payload", "image", "/tmp/alternate.erofs"),
            ("mount_handoff", "bootstrap_mount_operations", True),
            ("provider", "automatic_redispatch", 0),
            ("claims", "source_modules_authored", 1),
            ("rootlinux_payload", "read_only_lower", 1),
        ):
            with self.subTest(field=field, member=member):
                profile = json.loads(original)
                profile[field][member] = value
                path.write_text(json.dumps(profile), encoding="utf-8")
                report = module.verify(self.root)
                self.assertTrue(any(f"profile {field} differs" in error for error in report.errors), report.errors)
        path.write_text(original, encoding="utf-8")

    def test_init_read_only_mount_guard_and_btfm_sku_drift_fail_closed(self) -> None:
        for relative, old, new in (
            (module.ANDROID_ROOT / "init/trillionnium-owner-open.rc", "ro nosuid nodev", "rw nosuid nodev"),
            (module.ANDROID_ROOT / "init/trillionnium-owner-open.rc", "property:trillionnium.owner_open.verified=1 && ", ""),
            (module.ANDROID_ROOT / "init/trillionnium-sun-btfm-modprobe.rc", "ro.boot.product.vendor.sku=sun", "ro.boot.product.vendor.sku=other"),
        ):
            with self.subTest(relative=relative, old=old):
                path = self.root / relative
                original = path.read_text(encoding="utf-8")
                self.rewrite(relative, old, new)
                self.assertFalse(module.verify(self.root).ok)
                path.write_text(original, encoding="utf-8")

    def test_later_package_and_duplicate_module_cannot_bypass_inventory(self) -> None:
        for relative, suffix in (
            (module.ANDROID_ROOT / "product.mk", "\nPRODUCT_PACKAGES += arbitrary_privileged_module\n"),
            (module.ANDROID_ROOT / "product.mk", "\nPRODUCT_PACKAGES := arbitrary_privileged_module\n"),
            (module.ANDROID_ROOT / "Android.bp", '\ncc_binary {\n name: "trillionnium-owner-open-bootstrap",\n}\n'),
            (module.ANDROID_ROOT / "init/trillionnium-owner-open.rc", '\nservice trillionnium_owner_open_ingress /system/bin/arbitrary\n    user root\n'),
        ):
            with self.subTest(relative=relative, suffix=suffix):
                path = self.root / relative
                original = path.read_text(encoding="utf-8")
                path.write_text(original + suffix, encoding="utf-8")
                self.assertFalse(module.verify(self.root).ok)
                path.write_text(original, encoding="utf-8")

    def test_opt_in_teardown_and_early_ready_order_drift_fail_closed(self) -> None:
        for relative, old, new in (
            (module.ANDROID_ROOT / "product.mk", "ifeq ($(TRILLINNIUM_DOGFOOD_USERDEBUG_ADB_ROOT),true)", "ifeq (true,true)"),
            (module.ANDROID_ROOT / "init/trillionnium-owner-open.rc", "property:init.svc.trillionnium_owner_open_bootstrap=stopped", "property:arbitrary=1"),
            (module.ANDROID_ROOT / "init/trillionnium-owner-open.rc", "setprop trillionnium.owner_open.ready 0", "setprop trillionnium.owner_open.ready 1"),
        ):
            with self.subTest(relative=relative, old=old):
                path = self.root / relative
                original = path.read_text(encoding="utf-8")
                self.rewrite(relative, old, new)
                self.assertFalse(module.verify(self.root).ok)
                path.write_text(original, encoding="utf-8")

    def test_property_namespace_type_and_wildcard_drift_fail_closed(self) -> None:
        relative = module.ANDROID_ROOT / "sepolicy/private/property_contexts"
        path = self.root / relative
        original = path.read_text(encoding="utf-8")
        for changed in (
            original.replace("exact bool", "exact string", 1),
            original.replace("exact string", "prefix string", 1),
            original + "\ntrillionnium.owner_open.privileged u:object_r:trillionnium_owner_open_prop:s0 prefix string\n",
        ):
            path.write_text(changed, encoding="utf-8")
            report = module.verify(self.root)
            self.assertTrue(any("property context inventory/type" in error for error in report.errors), report.errors)
        path.write_text(original, encoding="utf-8")

    def test_missing_selinux_boundary_fails_closed(self) -> None:
        (self.root / module.ANDROID_ROOT / "sepolicy/private/types.te").unlink()
        report = module.verify(self.root)
        self.assertFalse(report.ok)
        self.assertTrue(
            any("types.te" in error or "SELinux types" in error for error in report.errors),
            report.errors,
        )

    def test_missing_data_ready_property_fails_closed(self) -> None:
        relative = module.ANDROID_ROOT / "sepolicy/private/property_contexts"
        self.rewrite(
            relative,
            "trillionnium.owner_open.data_ready",
            "trillionnium.owner_open.data_ready_drifted",
        )
        report = module.verify(self.root)
        self.assertTrue(
            any("property_contexts misses trillionnium.owner_open.data_ready" in error for error in report.errors),
            report.errors,
        )

    def test_profile_data_ready_property_drift_fails_closed(self) -> None:
        path = self.root / module.ANDROID_ROOT / "config/profile-v3.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["data_ready_property"] = "trillionnium.owner_open.data_ready_drifted"
        path.write_text(
            json.dumps(value, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        report = module.verify(self.root)
        self.assertTrue(
            any("runtime profile data_ready_property" in error for error in report.errors),
            report.errors,
        )

    def test_supervisor_automatic_redispatch_fails_closed(self) -> None:
        path = self.root / module.SUPERVISOR_CONFIG
        value = json.loads(path.read_text(encoding="utf-8"))
        value["automatic_effect_redispatch"] = True
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        report = module.verify(self.root)
        self.assertTrue(any("automatic_effect_redispatch" in error for error in report.errors))

    def test_external_claim_promotion_fails_closed(self) -> None:
        path = self.root / module.PROFILE
        value = json.loads(path.read_text(encoding="utf-8"))
        value["claims"]["target_files_built"] = True
        path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n", encoding="utf-8")
        report = module.verify(self.root)
        self.assertTrue(any("cannot promote claim target_files_built" in error for error in report.errors))


if __name__ == "__main__":
    unittest.main()
