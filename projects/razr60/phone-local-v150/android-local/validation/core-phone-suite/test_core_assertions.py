"""Synthetic host regressions; these are not phone/model acceptance results."""
from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock
import xml.etree.ElementTree as ET

BASE = Path(os.environ.get("HEPTA_CORE_TEST_DRIVERS", str(Path(__file__).resolve().parents[2] / "lfm3-controller/tools"))).resolve()
sys.path.insert(0, str(BASE))
import phone_acceptance as acceptance
import phone_suite as suite
import core_assertions as checks
import core_phone_suite as core


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False))


class Evidence:
    def __init__(self, root, assertion):
        self.root = root
        self.case = next(c for c in core.templates() if c["assertion"] == assertion)
        self.instruction = self.case["instruction"]
        self.task_id = "a" * 32
        self.step = 0
        self.owner_sha = acceptance.digest(self.instruction.encode())
        write(root / "task/owner.json", {"task_id": self.task_id, "instruction": self.instruction,
                                         "instruction_utf8_sha256": self.owner_sha})

    def event(self, kind, package, node=None, after_nodes=None, after_package=None, search=None, **fields):
        self.step += 1
        index = self.step
        before_id, after_id, run_id = "%032x" % (index * 2), "%032x" % (index * 2 + 1), "%032x" % (100 + index)
        before = {"observation_id": before_id, "package": package, "nodes": [node] if node else [],
                  "screen_width": 720, "screen_height": 1280, "rotation": 0, "window_id": 1}
        after = {**before, "observation_id": after_id, "package": after_package or package,
                 "nodes": after_nodes if after_nodes is not None else before["nodes"]}
        action = {"action": kind, "observation_id": before_id, "package": fields.pop("target_package", package), **fields}
        if node is not None:
            action["node_id"] = node["id"]
        receipt = {"action": action, "accepted": True, "dispatched": kind != "find_app", "stale": False,
                   "model_issued": True, "model_run_id": run_id}
        if kind == "find_app":
            receipt.update(read_only=True, effect="launcher_catalogue_read")
        prefix = self.root / "task" / ("step-%02d" % index)
        write(Path(str(prefix) + "-before.json"), before)
        write(Path(str(prefix) + "-after.json"), after)
        write(Path(str(prefix) + "-action.json"), receipt)
        raw = (json.dumps(action, ensure_ascii=False) + "\n").encode()
        write(Path(str(prefix) + "-model-0.json"), {"run_id": run_id, "raw_text": raw.decode(),
                                                   "observation_id": before_id, "original_instruction_sha256": self.owner_sha})
        run = self.root / "runs" / run_id
        run.mkdir(parents=True)
        (run / "raw-text.txt").write_bytes(raw)
        write(run / "native-result.json", {"schema": "hepta.geniex-once.result.v1", "request_id": run_id,
                                           "raw_text_sha256": acceptance.digest(raw), "raw_text_bytes": len(raw),
                                           "generation_complete": True, "raw_text_utf8": True, "raw_text_truncated": False, "error": None})
        projected = []
        if node:
            capabilities = "".join(c for c, key in (("c", "clickable"), ("t", "editable"), ("s", "scrollable")) if node.get(key))
            projected = [[node["id"], node.get("text", ""), [0, 0, 100, 100], capabilities]]
        prompt = {"screen": {"observation_id": before_id, "package": package, "nodes": projected},
                  "apps": [[checks.CALCULATOR, "计算器"], [checks.SETTINGS, "设置"]], "app_search": search or {"query": "", "offset": 0}}
        (run / "prompt.txt").write_text("UNTRUSTED_DATA\n" + json.dumps(prompt, ensure_ascii=False) + "\nOWNER\n" + self.instruction)
        return index, run_id, before, after

    def ui(self, package, labels):
        root = ET.Element("hierarchy")
        for label in labels:
            attrs = {"package": package, "class": "android.widget.TextView", "text": label} if isinstance(label, str) else {"package": package, **label}
            ET.SubElement(root, "node", attrs)
        (self.root / "ui-final.xml").write_bytes(ET.tostring(root))
        (self.root / "ui-final-window.txt").write_text("mCurrentFocus=Window{123 u0 " + package + "/.Main}\n")

    def evaluate(self):
        return checks.evaluate_case(self.root, self.case, suite, acceptance)


def button(label):
    return {"id": "n1", "text": label, "clickable": True, "bounds": [0, 0, 100, 100]}


class CoreChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def calculator(self, labels=None):
        fixture = Evidence(self.root, "calculator_keypad")
        fixture.event("open", "com.motorola.launcher", target_package=checks.CALCULATOR, after_package=checks.CALCULATOR)
        for label in labels or ["清除", "2", "3", "乘", "1", "9", "等于"]:
            fixture.event("click", checks.CALCULATOR, node=button(label),
                          after_nodes=[{"id": "r1", "text": "23×19", "view_id": "formula"}])
        fixture.ui(checks.CALCULATOR, [{"class": "android.widget.TextView", "resource-id": "result", "text": "437"}])
        return fixture

    def test_real_keypad_sequence_passes(self):
        self.assertTrue(self.calculator().evaluate()["all_passed"])

    def test_direct_result_type_fails_even_with_437_visible(self):
        fixture = self.calculator()
        fixture.event("type", checks.CALCULATOR, node={"id": "n1", "editable": True}, text="437")
        self.assertFalse(fixture.evaluate()["all_passed"])

    def test_direct_expression_type_fails_too(self):
        fixture = self.calculator()
        fixture.event("type", checks.CALCULATOR, node={"id": "n1", "editable": True}, text="23×19")
        self.assertFalse(fixture.evaluate()["all_passed"])

    def test_missing_equals_fails(self):
        fixture = self.calculator(["清除", "2", "3", "乘", "1", "9"])
        self.assertFalse(fixture.evaluate()["all_passed"])

    def test_extra_digit_cannot_be_hidden_by_subsequence(self):
        fixture = self.calculator(["清除", "2", "4", "3", "乘", "1", "9", "等于"])
        self.assertFalse(fixture.evaluate()["all_passed"])

    def test_missing_clear_cannot_reuse_old_expression(self):
        fixture = self.calculator(["2", "3", "乘", "1", "9", "等于"])
        self.assertFalse(fixture.evaluate()["all_passed"])

    def test_unbound_native_raw_is_unverified(self):
        fixture = self.calculator()
        raw = next((self.root / "runs").glob("*/raw-text.txt"))
        raw.write_text("{}")
        result = fixture.evaluate()
        self.assertFalse(result["all_passed"])
        self.assertFalse(result["evidence_complete"])

    def test_node_not_given_to_model_is_unverified(self):
        fixture = self.calculator()
        path = self.root / "runs" / ("%032x" % 102) / "prompt.txt"
        text = path.read_text()
        data, _, owner = text[len("UNTRUSTED_DATA\n"):].partition("\nOWNER\n")
        data = json.loads(data)
        data["screen"]["nodes"] = []
        path.write_text("UNTRUSTED_DATA\n" + json.dumps(data) + "\nOWNER\n" + owner)
        self.assertFalse(fixture.evaluate()["evidence_complete"])

    def search(self, typed=True, result=True, field_id=checks.SEARCH_FIELD):
        fixture = Evidence(self.root, "chinese_search")
        if typed:
            fixture.event("type", checks.SEARCH, node={"id": "n1", "editable": True, "view_id": field_id, "text": "NFC"}, text="蓝牙",
                          after_nodes=[{"id": "n2", "editable": True, "view_id": field_id, "text": "蓝牙"}])
        labels = [{"class": "android.widget.EditText", "resource-id": checks.SEARCH_FIELD, "text": "蓝牙"}]
        if result:
            labels.append({"class": "android.widget.TextView", "resource-id": "title", "text": "蓝牙"})
        fixture.ui(checks.SEARCH, labels)
        return fixture

    def test_exact_chinese_type_and_result_pass(self):
        self.assertTrue(self.search().evaluate()["all_passed"])

    def test_visible_query_without_model_type_fails(self):
        self.assertFalse(self.search(typed=False).evaluate()["all_passed"])

    def test_query_field_alone_is_not_search_result(self):
        self.assertFalse(self.search(result=False).evaluate()["all_passed"])

    def test_type_into_other_field_fails(self):
        self.assertFalse(self.search(field_id="other_edit").evaluate()["all_passed"])

    def test_false_final_foreground_fails(self):
        fixture = self.search()
        (self.root / "ui-final-window.txt").write_text("mCurrentFocus=Window{1 u0 com.motorola.launcher/.Main}\n")
        self.assertFalse(fixture.evaluate()["all_passed"])

    def scroll(self, changed=True):
        fixture = Evidence(self.root, "scroll")
        before = {"id": "n1", "scrollable": True, "text": "网络和互联网", "view_id": "list"}
        after = {**before, "text": "系统" if changed else before["text"]}
        fixture.event("scroll", checks.SETTINGS, node=before, after_nodes=[after], direction="forward")
        fixture.ui(checks.SETTINGS, ["设置", "系统"])
        return fixture

    def test_scroll_must_change_visible_content(self):
        self.assertTrue(self.scroll().evaluate()["all_passed"])

    def test_dispatched_but_unchanged_scroll_fails(self):
        self.assertFalse(self.scroll(False).evaluate()["all_passed"])

    def discovery(self, returned=True):
        fixture = Evidence(self.root, "find_app")
        catalogue_sha = "b" * 64
        write(self.root / "task/initial-app-catalogue.json", {"catalogue_sha256": catalogue_sha})
        index, run_id, before, _ = fixture.event("find_app", "com.motorola.launcher", query="计算器", offset=0)
        apps = [{"package": checks.CALCULATOR, "label": "计算器"}] if returned else []
        write(self.root / "task/step-01-find-app.json", {"schema": "hepta.local-app-discovery.v1", "task_id": fixture.task_id,
              "request_observation_id": before["observation_id"], "model_run_id": run_id,
              "original_instruction_sha256": fixture.owner_sha, "query": "计算器", "offset": 0,
              "model_issued": True, "read_only": True, "dispatched": False, "catalogue_sha256": catalogue_sha,
              "apps": apps, "returned": len(apps)})
        fixture.event("open", "com.motorola.launcher", target_package=checks.CALCULATOR, after_package=checks.CALCULATOR,
                      search={"query": "计算器", "offset": 0})
        fixture.ui(checks.CALCULATOR, ["计算器"])
        return fixture

    def test_real_find_then_open_passes(self):
        self.assertTrue(self.discovery().evaluate()["all_passed"])

    def test_opened_app_absent_from_search_result_fails(self):
        self.assertFalse(self.discovery(False).evaluate()["all_passed"])

    def test_find_result_with_wrong_model_run_is_unverified(self):
        fixture = self.discovery()
        path = self.root / "task/step-01-find-app.json"
        value = json.loads(path.read_text()); value["model_run_id"] = "f" * 32; write(path, value)
        self.assertFalse(fixture.evaluate()["evidence_complete"])

    def test_model_profile_is_forwarded_without_a_fixed_model_sha(self):
        candidate = {"model_profile": "another-model", "model_sha256": "c" * 64}
        plan = {"suite_id": "fixture", "candidate": candidate, "cases": [core.templates()[0]]}
        self.assertIs(core.base_plan(plan, suite)["candidate"], candidate)

    def test_unknown_submission_stops_following_cases_without_replay(self):
        pin, _ = core.driver_files(BASE)
        candidate = {"package": acceptance.PACKAGE, "apk_sha256": "a" * 64, "version_code": 3,
                     "model_sha256": acceptance.MODEL_SHA256, "compute": "npu", "context_tokens": 4096, "threads": 4}
        plan = {"schema": core.SCHEMA, "suite_id": "fixture-unknown", "candidate": candidate, "drivers": pin, "cases": core.templates()[:2]}
        calls = []
        def failure(args):
            calls.append(args.case_id)
            raise RuntimeError("synthetic interrupted submission")
        fake_acceptance = SimpleNamespace(Adb=lambda *args: None, run_task=failure,
                                         private_write=acceptance.private_write, write_json=acceptance.write_json)
        fake_suite = SimpleNamespace(SCHEMA=suite.SCHEMA, summarize=suite.summarize, validate_plan=suite.validate_plan,
                                     require_existing_adb_server=lambda *args, **kwargs: {"fixture": True},
                                     preflight=lambda *args: {"fixture": True}, case_args=suite.case_args)
        output = self.root / "run"
        args = SimpleNamespace(output=output, adb="never-executed", adb_host="127.0.0.1", adb_port=5061,
                               serial="synthetic", command_timeout=20)
        with mock.patch.object(core, "load_drivers", return_value=(fake_suite, fake_acceptance)), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(core.run(args, plan, json.dumps(plan).encode()), 2)
        result = json.loads((output / "suite-result.json").read_text())
        self.assertEqual(calls, [plan["cases"][0]["case_id"]])
        self.assertEqual(result["counts"]["unknown"], 1)
        self.assertEqual(result["counts"]["not_run"], 1)
        self.assertIsNone(result["actual_launches"])


if __name__ == "__main__":
    unittest.main()
