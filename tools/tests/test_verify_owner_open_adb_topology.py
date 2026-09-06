from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "verify-owner-open-adb-topology.py"
spec = importlib.util.spec_from_file_location("verify_owner_open_adb_topology", SCRIPT)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
REPOSITORY = Path(__file__).resolve().parents[2]


@unittest.skipUnless(
    (REPOSITORY / module.CONTRACT).is_file(),
    "G1 retired the historical R5 ADB-topology contract; this legacy suite is not active evidence",
)
class VerifyOwnerOpenAdbTopologyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.value = module.load_contract(REPOSITORY / module.CONTRACT)
        for item in self.value["required_sources"]:
            source = REPOSITORY / item["path"]
            target = self.root / item["path"]
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
        self.write(self.value)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def write(self, value: dict) -> None:
        path = self.root / module.CONTRACT
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )

    def report(self, value: dict | None = None):
        if value is not None:
            self.write(value)
        return module.verify(self.root)

    def test_selected_topology_is_closed_and_non_authorizing(self) -> None:
        report = self.report()
        self.assertEqual(report.errors, [])
        self.assertTrue(report.ok)
        self.assertEqual(report.facts["adb_server_socket"], "tcp:127.0.0.1:15038")
        self.assertEqual(report.facts["reverse"]["owner_host_endpoint"], "tcp:5037")

    def test_nonloopback_or_port_splice_fails(self) -> None:
        value = copy.deepcopy(self.value)
        value["device_relay"]["listen_host"] = "0.0.0.0"
        value["device_relay"]["upstream_port"] = 16000
        report = self.report(value)
        self.assertTrue(any("loopback-only" in item for item in report.errors))
        self.assertTrue(any("reverse device endpoint" in item for item in report.errors))

    def test_any_injection_or_automatic_retry_fails(self) -> None:
        value = copy.deepcopy(self.value)
        value["rootlinux_client"]["serial_injected"] = True
        value["rootlinux_client"]["automatic_redispatch"] = True
        value["owner_host_bootstrap"]["automatic_mapping_retry"] = True
        report = self.report(value)
        self.assertTrue(any("serial_injected" in item for item in report.errors))
        self.assertTrue(any("automatic_redispatch" in item for item in report.errors))
        self.assertTrue(any("automatically retried" in item for item in report.errors))

    def test_external_claims_cannot_be_promoted_by_source_edit(self) -> None:
        value = copy.deepcopy(self.value)
        value["claims"]["physical_usb_target_observed"] = True
        value["claims"]["same_turn_physical_adb_effect_observed"] = True
        report = self.report(value)
        self.assertTrue(any("physical_usb_target_observed" in item for item in report.errors))
        self.assertTrue(
            any("same_turn_physical_adb_effect_observed" in item for item in report.errors)
        )

    def test_missing_selected_source_marker_fails(self) -> None:
        relative = "tools/owner-open/adb_smart_socket_relay_release.py"
        (self.root / relative).write_text("SELECTED_ENTRY = True\n", encoding="utf-8")
        report = self.report()
        self.assertTrue(any("required source markers missing" in item for item in report.errors))

    def test_unknown_contract_member_fails_closed(self) -> None:
        value = copy.deepcopy(self.value)
        value["semantic_policy"] = "allow"
        report = self.report(value)
        self.assertTrue(any("keys differ" in item for item in report.errors))


if __name__ == "__main__":
    unittest.main()
