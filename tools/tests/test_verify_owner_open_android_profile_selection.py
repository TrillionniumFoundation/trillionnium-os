from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-android-profile-selection.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_android_profile_selection", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class VerifyOwnerOpenAndroidProfileSelectionTest(unittest.TestCase):
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

    def contract(self) -> dict:
        return json.loads((self.root / module.CONTRACT).read_text(encoding="utf-8"))

    def write_contract(self, value: dict) -> None:
        self.write(
            str(module.CONTRACT),
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )

    def write_fixture(self) -> None:
        selected = {
            "architecture_decision": "docs/architecture/rootlinux.md",
            "profile": "android/profile-v2.json",
            "generated_fragment": "android/generated/packages-v2.mk",
            "generator": "tools/generator-v3.py",
            "verifier": "tools/verifier-v3.py",
            "tests": "tools/tests/test-v3.py",
            "workflow": ".github/workflows/android-v3.yml",
            "plan": "docs/plan/android-v3.md",
            "status": "docs/status/android-v3.json",
        }
        self.write(selected["architecture_decision"], "Root Linux payload\n")
        self.write(
            selected["profile"],
            json.dumps(
                {
                    "schema": module.PROFILE_SCHEMA,
                    "profile_id": "fixture-v3",
                    "architecture_decision": selected["architecture_decision"],
                    "activation": {
                        "selected_in_current_product": False,
                        "product_make_fragment": selected["generated_fragment"],
                    },
                    "claims": {"source_contract_only": True},
                    "rootlinux_payload": {"read_only": True},
                },
                indent=2,
            )
            + "\n",
        )
        self.write(
            selected["generated_fragment"],
            "ROOT LINUX PAYLOAD CONTRACT ONLY\n"
            "trillionnium-owner-open-rootfs-image\n"
            "trillionnium-owner-open-bootstrap\n"
            "not Android /system_ext/bin executables\n",
        )
        self.write(
            selected["generator"],
            "org.trillionnium.owner-open.android-profile.v2\n"
            "ROOT LINUX PAYLOAD CONTRACT ONLY\n"
            "UNBOUND_SOONG_MODULE\n",
        )
        self.write(
            selected["verifier"],
            "BOUND_ROOTFS_IMAGE\n"
            "BOUND_ROOTLINUX_SERVICE\n"
            "strict Android v3\n"
            "incorrectly reserved as Android executable\n",
        )
        self.write(selected["tests"], "PASS = True\n")
        self.write(selected["workflow"], "name: android-v3\n")
        self.write(selected["plan"], "selected Root Linux profile v3\n")
        self.write(selected["status"], "{}\n")
        self.write("tools/helper-v1.py", "HELPER = True\n")
        self.write_contract(
            {
                "schema": module.EXPECTED_SCHEMA,
                "revision": "fixture",
                "selected": selected,
                "structural_helpers": ["tools/helper-v1.py"],
                "superseded_product_selections": ["android/profile-v1.json"],
                "required_markers": {
                    selected["profile"]: [
                        module.PROFILE_SCHEMA,
                        "rootlinux_payload",
                    ],
                    selected["generator"]: [
                        module.PROFILE_SCHEMA,
                        "ROOT LINUX PAYLOAD CONTRACT ONLY",
                        "UNBOUND_SOONG_MODULE",
                    ],
                    selected["verifier"]: [
                        "BOUND_ROOTFS_IMAGE",
                        "BOUND_ROOTLINUX_SERVICE",
                        "strict Android v3",
                        "incorrectly reserved as Android executable",
                    ],
                    selected["generated_fragment"]: [
                        "ROOT LINUX PAYLOAD CONTRACT ONLY",
                        "trillionnium-owner-open-rootfs-image",
                        "trillionnium-owner-open-bootstrap",
                        "not Android /system_ext/bin executables",
                    ],
                },
                "release_reference_roots": [
                    selected["plan"],
                    selected["status"],
                    selected["workflow"],
                ],
                "forbidden_release_reference_tokens": ["profile-v1.json"],
                "claim_ceiling": "SOURCE_CONTRACT_ONLY_L0",
            }
        )

    def test_clean_selection_passes(self) -> None:
        report = module.verify(self.root)
        self.assertEqual(report.errors, [])
        self.assertEqual(report.facts["profile_id"], "fixture-v3")

    def test_selected_path_cannot_be_superseded(self) -> None:
        value = self.contract()
        value["superseded_product_selections"].append(value["selected"]["profile"])
        self.write_contract(value)
        report = module.verify(self.root)
        self.assertTrue(any("also superseded" in item for item in report.errors))

    def test_profile_fragment_must_match_selection_contract(self) -> None:
        value = json.loads((self.root / "android/profile-v2.json").read_text())
        value["activation"]["product_make_fragment"] = "android/generated/other.mk"
        self.write("android/profile-v2.json", json.dumps(value) + "\n")
        report = module.verify(self.root)
        self.assertTrue(any("fragment does not match" in item for item in report.errors))

    def test_release_root_cannot_reference_superseded_profile(self) -> None:
        self.write("docs/plan/android-v3.md", "include android/profile-v1.json\n")
        report = module.verify(self.root)
        self.assertTrue(
            any("selects superseded Android tokens" in item for item in report.errors)
        )

    def test_required_marker_drift_fails(self) -> None:
        self.write("tools/verifier-v3.py", "BOUND_ROOTFS_IMAGE\n")
        report = module.verify(self.root)
        self.assertTrue(any("missing markers" in item for item in report.errors))

    def test_selected_symlink_fails(self) -> None:
        path = self.root / "tools/generator-v3.py"
        target = self.root / "tools/real-generator.py"
        target.write_text(path.read_text(), encoding="utf-8")
        path.unlink()
        path.symlink_to(target.name)
        report = module.verify(self.root)
        self.assertTrue(any("not a real file" in item for item in report.errors))


if __name__ == "__main__":
    unittest.main()
