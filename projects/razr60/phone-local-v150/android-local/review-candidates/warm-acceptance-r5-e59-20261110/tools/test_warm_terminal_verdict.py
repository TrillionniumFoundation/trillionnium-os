"""Base verdict coherence, producer done invariants, and bounded local waits."""
import copy
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_warm_core_integration as integration
import test_warm_terminal_closure as terminal_tests
from test_warm_action_binding import basic_source, collect_warm, reseal, write, FIRST

acceptance, suite, core = integration.acceptance, integration.suite, integration.core


class WarmTerminalVerdictTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for target in ((acceptance, "Adb"), (socket, "create_connection"), (subprocess, "Popen"), (subprocess, "run")):
            guard = patch.object(*target, side_effect=AssertionError("phone/network/process access forbidden"))
            guard.start(); self.addCleanup(guard.stop)

    def case(self, name):
        builder = terminal_tests.WarmTerminalClosureTests(); builder.root = self.root
        return builder.case(name)

    def change_terminal(self, directory, status, verdict):
        path = directory / "task/result.json"
        final = json.loads(path.read_bytes()); final.update(status=status, model_reported_success=False); write(path, final)
        path = directory / "acceptance.json"
        report = json.loads(path.read_bytes()); report["verdict"] = verdict; write(path, report)
        reseal(directory, synchronize_terminal=True)

    def test_base_pass_requires_successful_terminal_even_with_matching_hashes(self):
        for status in ("partial", "failed", "cancelled", "blocked"):
            with self.subTest(status=status):
                directory, fixture = self.case(status)
                self.change_terminal(directory, status, "pass")
                result = core.evaluate_one(directory, fixture.case, suite, acceptance)
                self.assertEqual(result["verdict"], "unverified", result)
                self.assertFalse(result["action_sequence"]["evidence_complete"])

    def test_failed_base_can_retain_action_diagnostics_without_upgrade(self):
        directory, fixture = self.case("failure")
        self.change_terminal(directory, "partial", "fail")
        result = core.evaluate_one(directory, fixture.case, suite, acceptance)
        self.assertEqual(result["verdict"], "fail", result)
        self.assertEqual(result["original_case_verdict"], "fail")
        self.assertTrue(result["action_sequence"]["passed"])
        self.assertTrue(result["action_sequence"]["evidence_complete"])

    def test_done_observation_must_keep_producer_fields_stable(self):
        changes = (("package", "other.application"), ("window_id", 8), ("rotation", 1),
                   ("observation_state_sha256", "f" * 64))
        for field, value in changes:
            with self.subTest(field=field):
                directory, fixture = self.case("changed-" + field)
                path = directory / "task/step-03-after.json"
                after = json.loads(path.read_bytes()); after[field] = value; write(path, after)
                reseal(directory)
                result = core.evaluate_one(directory, fixture.case, suite, acceptance)
                self.assertEqual(result["verdict"], "unverified", result)

    def test_equal_missing_or_wrong_typed_done_fields_cannot_qualify(self):
        changes = (("window_id", None), ("rotation", None), ("observation_state_sha256", None),
                   ("window_id", True), ("rotation", False), ("observation_state_sha256", "not-a-digest"))
        for index, (field, value) in enumerate(changes):
            with self.subTest(field=field, value=value):
                directory, fixture = self.case("invalid%d" % index)
                for suffix in ("before", "after"):
                    path = directory / ("task/step-03-" + suffix + ".json")
                    observation = json.loads(path.read_bytes())
                    if value is None: observation.pop(field)
                    else: observation[field] = value
                    write(path, observation)
                reseal(directory)
                result = core.evaluate_one(directory, fixture.case, suite, acceptance)
                self.assertEqual(result["verdict"], "unverified", result)

    def wait_case(self, name, duration=100):
        source, directory = self.root / (name + "-source"), self.root / name
        basic_source(source)
        before_path = source / "task/step-01-before.json"
        before = json.loads(before_path.read_bytes()); before["package"] = "com.android.settings"; write(before_path, before)
        path = source / "task/step-01-action.json"
        receipt = json.loads(path.read_bytes()); receipt["action"].update(action="wait", duration_ms=duration)
        receipt["dispatched"] = False; write(path, receipt)
        raw = (json.dumps(receipt["action"]) + "\n").encode()
        path = source / "task/step-01-model-0.json"
        model = json.loads(path.read_bytes()); model["raw_text"] = raw.decode(); write(path, model)
        run = source / "runs" / FIRST
        (run / "raw-text.txt").write_bytes(raw)
        prompt = (run / "prompt.txt").read_text().replace('"com.motorola.launcher"', '"com.android.settings"')
        (run / "prompt.txt").write_text(prompt)
        collect_warm(source, directory)
        return directory

    def binding(self, directory, step=1):
        path = directory / ("task/step-%02d-action.json" % step)
        before = directory / ("task/step-%02d-before.json" % step)
        return suite.model_action_binding(directory, path, json.loads(path.read_bytes()), json.loads(before.read_bytes()))

    def test_complete_wait_then_done_is_bound_without_inventing_an_effect(self):
        for duration in (100, 2000):
            directory = self.wait_case("wait%d" % duration, duration)
            binding = self.binding(directory)
            self.assertTrue(binding["verified"], binding)
            self.assertEqual(binding["controller_steps_verified"], 2)
            self.assertTrue(self.binding(directory, 2)["verified"])
            self.assertNotIn("wait", suite.EFFECTS)

    def test_actual_core_open_wait_done_preserves_real_effect_requirement(self):
        builder = integration.WarmCoreIntegrationTests(); builder.root = self.root
        fixture = integration.synthetic_core.Evidence(self.root / "source", "settings_home")
        fixture.event("open", "com.motorola.launcher", target_package=integration.checks.SETTINGS,
                      after_package=integration.checks.SETTINGS)
        step, _, _, _ = fixture.event("wait", integration.checks.SETTINGS, duration_ms=100)
        path = fixture.root / ("task/step-%02d-action.json" % step)
        receipt = json.loads(path.read_bytes()); receipt["dispatched"] = False; write(path, receipt)
        fixture.homepage_ui()
        directory = builder.collect(fixture)
        result = core.evaluate_one(directory, fixture.case, suite, acceptance)
        self.assertEqual(result["verdict"], "pass", result)
        self.assertEqual([item["action"] for item in result["action_sequence"]["observed_dispatched_actions"]], ["open"])

    def test_wait_cannot_dispatch_or_substitute_a_duration(self):
        for mode in ("dispatched", "changed-duration"):
            directory = self.wait_case(mode)
            path = directory / "task/step-01-action.json"
            receipt = json.loads(path.read_bytes())
            if mode == "dispatched": receipt["dispatched"] = True
            else: receipt["action"]["duration_ms"] = 200
            write(path, receipt); reseal(directory)
            self.assertFalse(self.binding(directory)["verified"])

    def test_wait_duration_requires_exact_bounded_integer_in_all_records(self):
        for index, duration in enumerate((99, 2001, True, 100.0)):
            with self.subTest(duration=duration):
                directory = self.wait_case("duration%d" % index, duration)
                self.assertFalse(self.binding(directory)["verified"])


if __name__ == "__main__":
    unittest.main()
