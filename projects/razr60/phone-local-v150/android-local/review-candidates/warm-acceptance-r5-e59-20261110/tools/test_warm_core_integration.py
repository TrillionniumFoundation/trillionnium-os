"""Actual frozen core oracle + synthetic warm collector + actual action binder.

Set HEPTA_WARM_CORE_SOURCE to the reviewed core source directory containing
core_assertions.py, core_phone_suite.py and test_core_assertions.py. Set
HEPTA_CORE_TEST_DRIVERS to the acceptance tools being tested. No private phone
fixture is needed, and this test never contacts a device or starts a process.
"""
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

CORE_SOURCE = os.environ.get("HEPTA_WARM_CORE_SOURCE")
if not CORE_SOURCE:
    raise unittest.SkipTest("explicit reviewed core source required for warm integration")
sys.path.insert(0, str(Path(CORE_SOURCE).resolve()))
import core_assertions as checks
import core_phone_suite as core
import test_core_assertions as synthetic_core
import phone_acceptance as acceptance
import phone_suite as suite
from test_warm_action_binding import collect_warm, reseal, write
from test_warm_receipts import G


class WarmCoreIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for target in ((acceptance, "Adb"), (socket, "create_connection"), (subprocess, "Popen"), (subprocess, "run")):
            guard = patch.object(*target, side_effect=AssertionError("phone/network/process access forbidden"))
            guard.start(); self.addCleanup(guard.stop)

    def collect(self, fixture, verdict="pass"):
        if not (fixture.root / "task/result.json").is_file():
            previous = json.loads((fixture.root / "task" / ("step-%02d-after.json" % fixture.step)).read_bytes())
            step, _, _, after = fixture.event("done", previous["package"], status="success")
            path = fixture.root / "task" / ("step-%02d-action.json" % step)
            receipt = json.loads(path.read_bytes()); receipt["dispatched"] = False; write(path, receipt)
            write(fixture.root / "task/result.json", dict(task_id=fixture.task_id, steps=step,
                status="model_reported_done", model_reported_success=True, cleanup_known=True,
                final_observation_id=after["observation_id"]))
        directory = self.root / "collected" / fixture.case["case_id"]
        collect_warm(fixture.root, directory, verdict)
        for name in ("ui-final.xml", "ui-final-window.txt"):
            (directory / name).write_bytes((fixture.root / name).read_bytes())
        return directory

    def home(self, assertion="settings_home"):
        fixture = synthetic_core.Evidence(self.root / "source", assertion)
        if assertion == "search_return_home":
            fixture.event("back", checks.SEARCH, after_package=checks.SETTINGS)
        else:
            fixture.event("open", "com.motorola.launcher", target_package=checks.SETTINGS, after_package=checks.SETTINGS)
        fixture.homepage_ui()
        return fixture

    def test_actual_core_driver_pin_includes_new_helper_and_rejects_omission(self):
        directory = Path(suite.__file__).parent
        pin, content = core.driver_files(directory)
        self.assertIn("warm_action_evidence.py", content)
        helper = next(item for item in pin["files"] if item["path"] == "warm_action_evidence.py")
        self.assertEqual(helper["sha256"], acceptance.digest(content[helper["path"]]))
        loaded_suite, loaded_acceptance = core.load_drivers(pin, directory)
        self.assertIs(loaded_suite, suite); self.assertIs(loaded_acceptance, acceptance)
        pin["files"] = [item for item in pin["files"] if item["path"] != "warm_action_evidence.py"]
        with self.assertRaisesRegex(ValueError, "changed from the frozen plan"):
            core.verify_driver_pin(pin, directory)

    def test_real_core_homepage_done_and_bound_effects_accept_complete_warm_case(self):
        fixture = self.home(); directory = self.collect(fixture)
        result = core.evaluate_one(directory, fixture.case, suite, acceptance)
        self.assertEqual(result["verdict"], "pass", result)
        self.assertTrue(result["action_sequence"]["passed"], result)
        extra = result["goal_specific_checks"]
        self.assertTrue(extra["evidence_complete"]); self.assertTrue(extra["all_passed"])
        home = next(c["evidence"] for c in extra["checks"] if c["kind"] == "independent_settings_homepage")
        done = next(c["binding"] for c in home["checks"] if c["kind"] == "native_bound_terminal_done")
        self.assertEqual(done["request_sequence"], 2)
        self.assertTrue(done["generation_process_exit_observed"])
        self.assertFalse(home["phone_contacted"]); self.assertFalse(home["full_task_acceptance_claimed"])

    def test_real_core_initial_precondition_uses_the_same_complete_collection(self):
        fixture = self.home("search_return_home"); directory = self.collect(fixture)
        result = core.evaluate_one(directory, fixture.case, suite, acceptance)
        self.assertEqual(result["verdict"], "pass", result)
        precondition = result["goal_specific_checks"]["precondition_evidence"]
        self.assertEqual(precondition["observed_initial_package"], checks.SEARCH)
        self.assertEqual(precondition["model_binding"]["worker_generation"], G)
        self.assertEqual(precondition["model_binding"]["generation_requests_verified"], 2)

    def test_real_core_read_only_find_app_and_later_open_are_bound(self):
        builder = synthetic_core.CoreChecks(); builder.root = self.root / "source"
        fixture = builder.discovery(); directory = self.collect(fixture)
        result = core.evaluate_one(directory, fixture.case, suite, acceptance)
        self.assertEqual(result["verdict"], "pass", result)
        bindings = result["goal_specific_checks"]["model_action_bindings"]
        self.assertEqual([b["request_sequence"] for b in bindings], [1, 2])
        self.assertTrue(all(b["generation_requests_verified"] == 3 for b in bindings))

    def test_valid_homepage_cannot_override_missing_worker_exit_evidence(self):
        fixture = self.home(); directory = self.collect(fixture)
        (directory / "runs" / G / "app-session-receipt.json").unlink()
        result = core.evaluate_one(directory, fixture.case, suite, acceptance)
        self.assertEqual(result["verdict"], "unverified", result)
        self.assertEqual(result["launch_attempt_count"], 1)
        self.assertFalse(result["action_sequence"]["evidence_complete"])
        self.assertFalse(result["goal_specific_checks"]["evidence_complete"])

    def test_complete_warm_homepage_never_upgrades_original_failure(self):
        fixture = self.home(); directory = self.collect(fixture, "fail")
        result = core.evaluate_one(directory, fixture.case, suite, acceptance)
        self.assertEqual(result["verdict"], "fail", result)
        self.assertEqual(result["original_case_verdict"], "fail")
        self.assertTrue(result["action_sequence"]["passed"])
        self.assertTrue(result["goal_specific_checks"]["all_passed"])

    def test_resealed_terminal_mismatch_is_unverified_through_actual_core(self):
        fixture = self.home(); directory = self.collect(fixture)
        path = directory / "task/result.json"
        terminal = json.loads(path.read_bytes()); terminal["status"] = "partial"; write(path, terminal)
        reseal(directory)
        result = core.evaluate_one(directory, fixture.case, suite, acceptance)
        self.assertEqual(result["verdict"], "unverified", result)
        self.assertFalse(result["action_sequence"]["evidence_complete"])


if __name__ == "__main__":
    unittest.main()
