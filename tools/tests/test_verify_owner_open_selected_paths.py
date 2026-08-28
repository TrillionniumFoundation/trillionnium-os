from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-selected-paths.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_selected_paths", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class VerifyOwnerOpenSelectedPathsTest(unittest.TestCase):
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
        return json.loads(
            (self.root / module.CONTRACT_PATH).read_text(encoding="utf-8")
        )

    def write_contract(self, value: dict) -> None:
        self.write(
            str(module.CONTRACT_PATH),
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        )

    def write_fixture(self) -> None:
        selected = {
            "supervisor": "tools/release_supervisor.py",
            "relay": "tools/release_relay.py",
            "qualifier": "tools/release_qualifier.py",
        }
        self.write(
            selected["supervisor"],
            "evidence parent\nconfig_restored\nPASS_RELEASE_SUPERVISED_INSTALLED_CODEX_MCP_QUALIFICATION\n",
        )
        self.write(
            selected["relay"],
            "SELECTED_ENTRY\nautomatic_redispatch=False\npayload_logged=False\n",
        )
        self.write(
            selected["qualifier"],
            "SELECTED_RELAY\nrelay descriptor does not identify the release entry\n",
        )
        self.write("tools/tests/test_release.py", "PASS = True\n")
        self.write(".github/workflows/release.yml", "name: release\n")
        self.write("docs/plan/release.md", "release supervisor relay qualifier\n")
        self.write("docs/status/release.json", "{}\n")
        contract = {
            "schema": module.EXPECTED_SCHEMA,
            "revision": "fixture",
            "selected": selected,
            "selected_tests": ["tools/tests/test_release.py"],
            "selected_workflows": [".github/workflows/release.yml"],
            "superseded_drafts": ["tools/draft_relay.py"],
            "required_markers": {
                selected["supervisor"]: [
                    "evidence parent",
                    "config_restored",
                    "PASS_RELEASE_SUPERVISED_INSTALLED_CODEX_MCP_QUALIFICATION",
                ],
                selected["relay"]: [
                    "SELECTED_ENTRY",
                    "automatic_redispatch=False",
                    "payload_logged=False",
                ],
                selected["qualifier"]: [
                    "SELECTED_RELAY",
                    "relay descriptor does not identify the release entry",
                ],
            },
            "release_reference_roots": [
                "docs/plan/release.md",
                "docs/status/release.json",
                ".github/workflows/release.yml",
            ],
            "forbidden_release_reference_tokens": ["draft_relay.py"],
        }
        self.write_contract(contract)

    def test_clean_fixture_passes(self) -> None:
        report = module.verify(self.root)
        self.assertEqual(report.errors, [])
        self.assertEqual(report.facts["selected_count"], 3)

    def test_selected_path_cannot_also_be_a_draft(self) -> None:
        value = self.contract()
        value["superseded_drafts"].append(value["selected"]["relay"])
        self.write_contract(value)
        report = module.verify(self.root)
        self.assertTrue(any("also appear as drafts" in item for item in report.errors))

    def test_release_reference_cannot_select_draft_token(self) -> None:
        self.write("docs/plan/release.md", "use tools/draft_relay.py\n")
        report = module.verify(self.root)
        self.assertTrue(
            any("selects superseded draft tokens" in item for item in report.errors)
        )

    def test_required_marker_drift_fails(self) -> None:
        self.write("tools/release_relay.py", "SELECTED_ENTRY\n")
        report = module.verify(self.root)
        self.assertTrue(any("missing markers" in item for item in report.errors))

    def test_missing_selected_file_fails(self) -> None:
        (self.root / "tools/release_qualifier.py").unlink()
        report = module.verify(self.root)
        self.assertTrue(any("selected path is missing" in item for item in report.errors))

    def test_selected_symlink_fails(self) -> None:
        path = self.root / "tools/release_relay.py"
        target = self.root / "tools/real.py"
        target.write_text(path.read_text(), encoding="utf-8")
        path.unlink()
        path.symlink_to(target.name)
        report = module.verify(self.root)
        self.assertTrue(any("not a real file" in item for item in report.errors))


if __name__ == "__main__":
    unittest.main()
