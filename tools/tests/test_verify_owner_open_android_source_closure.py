from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-android-source-closure.py"
spec = importlib.util.spec_from_file_location(
    "verify_owner_open_android_source_closure", SCRIPT
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

    def test_missing_android_runtime_profile_fails_closed(self) -> None:
        (self.root / module.ANDROID_ROOT / "config/profile-v3.json").unlink()
        report = module.verify(self.root)
        self.assertTrue(any("runtime profile" in error for error in report.errors))

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
            '"/usr/bin/codex"',
            '"/usr/bin/codex-drift"',
        )
        report = module.verify(self.root)
        self.assertTrue(any("bootstrap does not bind" in error for error in report.errors))

    def test_missing_selinux_boundary_fails_closed(self) -> None:
        path = self.root / module.ANDROID_ROOT / "sepolicy/private/types.te"
        path.write_text(
            path.read_text(encoding="utf-8").replace(
                "trillionnium_owner_open_ingress", "owner_open_ingress_removed"
            ),
            encoding="utf-8",
        )
        domains = self.root / module.ANDROID_ROOT / "sepolicy/private/domains.te"
        domains.write_text(
            domains.read_text(encoding="utf-8").replace(
                "trillionnium_owner_open_ingress", "owner_open_ingress_removed"
            ),
            encoding="utf-8",
        )
        report = module.verify(self.root)
        self.assertTrue(any("SELinux source misses" in error for error in report.errors))

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
