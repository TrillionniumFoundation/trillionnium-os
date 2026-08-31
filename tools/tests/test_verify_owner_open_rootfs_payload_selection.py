from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-rootfs-payload-selection.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_rootfs_payload_selection", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class VerifyOwnerOpenRootfsPayloadSelectionTest(unittest.TestCase):
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
            "stager": "tools/stager-release.py",
            "image_builder": "tools/builder-v2.py",
            "staging_test": "tools/tests/test-stager.py",
            "image_test": "tools/tests/test-builder.py",
            "staging_protocol": "docs/protocols/staging.md",
            "image_protocol": "docs/protocols/image.md",
            "architecture_decision": "docs/architecture/rootlinux.md",
            "workflow": ".github/workflows/rootfs.yml",
        }
        self.write(
            selected["stager"],
            "ROOTFS_PAYLOAD_STAGED_NOT_IMAGE\n"
            "payload source changed between inspection and copy\n"
            "payload staging changed its output parent mode\n"
            "rootfs_image_built\n",
        )
        self.write(
            "tools/builder-helper.py",
            "HELPER = True\n",
        )
        self.write(
            selected["image_builder"],
            "import builder-helper as base\n"
            "image tool process group could not be reaped\n"
            "command timed out and was reaped\n"
            "normalized staging copy drifted\n",
        )
        self.write(selected["staging_test"], "PASS = True\n")
        self.write(selected["image_test"], "PASS = True\n")
        self.write(selected["staging_protocol"], "staging protocol\n")
        self.write(
            selected["image_protocol"],
            "independent normalized copy\n"
            "byte-identical image hashes\n"
            "ROOTFS_IMAGE_BUILT_NOT_ANDROID_INCLUDED\n",
        )
        self.write(selected["architecture_decision"], "Root Linux payload\n")
        self.write(selected["workflow"], "name: rootfs\n")
        self.write("docs/plan/rootfs.md", "release payload v2\n")
        self.write("docs/status/android.json", "{}\n")
        self.write_contract(
            {
                "schema": module.EXPECTED_SCHEMA,
                "revision": "fixture",
                "selected": selected,
                "implementation_helpers": ["tools/builder-helper.py"],
                "superseded_drafts": ["tools/stager-draft.py"],
                "required_markers": {
                    selected["stager"]: [
                        "ROOTFS_PAYLOAD_STAGED_NOT_IMAGE",
                        "payload source changed between inspection and copy",
                        "payload staging changed its output parent mode",
                        "rootfs_image_built",
                    ],
                    selected["image_builder"]: [
                        "image tool process group could not be reaped",
                        "command timed out and was reaped",
                        "normalized staging copy drifted",
                    ],
                    selected["image_protocol"]: [
                        "independent normalized copy",
                        "byte-identical image hashes",
                        "ROOTFS_IMAGE_BUILT_NOT_ANDROID_INCLUDED",
                    ],
                },
                "release_reference_roots": [
                    "docs/plan/rootfs.md",
                    "docs/status/android.json",
                    selected["workflow"],
                ],
                "forbidden_release_reference_tokens": ["stager-draft.py"],
                "claim_ceiling": "SOURCE_IMPLEMENTED_L0",
            }
        )

    def test_clean_selection_passes(self) -> None:
        report = module.verify(self.root)
        self.assertEqual(report.errors, [])
        self.assertEqual(report.facts["selected_count"], 8)

    def test_selected_path_cannot_be_superseded(self) -> None:
        value = self.contract()
        value["superseded_drafts"].append(value["selected"]["stager"])
        self.write_contract(value)
        report = module.verify(self.root)
        self.assertTrue(any("also superseded" in item for item in report.errors))

    def test_release_root_cannot_reference_draft(self) -> None:
        self.write("docs/plan/rootfs.md", "use tools/stager-draft.py\n")
        report = module.verify(self.root)
        self.assertTrue(
            any("selects superseded payload tokens" in item for item in report.errors)
        )

    def test_required_marker_drift_fails(self) -> None:
        self.write("tools/stager-release.py", "ROOTFS_PAYLOAD_STAGED_NOT_IMAGE\n")
        report = module.verify(self.root)
        self.assertTrue(any("missing markers" in item for item in report.errors))

    def test_missing_selected_file_fails(self) -> None:
        (self.root / "tools/tests/test-builder.py").unlink()
        report = module.verify(self.root)
        self.assertTrue(any("is missing" in item for item in report.errors))

    def test_selected_symlink_fails(self) -> None:
        path = self.root / "tools/stager-release.py"
        target = self.root / "tools/real-stager.py"
        target.write_text(path.read_text(), encoding="utf-8")
        path.unlink()
        path.symlink_to(target.name)
        report = module.verify(self.root)
        self.assertTrue(any("not a real file" in item for item in report.errors))


if __name__ == "__main__":
    unittest.main()
