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

BASE = Path(os.environ.get("HEPTA_CORE_TEST_DRIVERS", str(Path(__file__).resolve().parent.parent / "razr-model-profiles-code7-r1/tools"))).resolve()
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
        if self.case["assertion"] in checks.HOME_KINDS and package == checks.SETTINGS and labels == ["设置", "搜索设置"]:
            self.homepage_ui()
            return
        root = ET.Element("hierarchy")
        for label in labels:
            attrs = {"package": package, "class": "android.widget.TextView", "text": label} if isinstance(label, str) else {"package": package, **label}
            ET.SubElement(root, "node", attrs)
        (self.root / "ui-final.xml").write_bytes(ET.tostring(root))
        (self.root / "ui-final-window.txt").write_text("mCurrentFocus=Window{123 u0 " + package + "/.Main}\n")

    def homepage_ui(self):
        """Synthetic complete homepage evidence for existing goal-order tests.

        Real captured positive/negative evidence is exercised separately in
        test_settings_homepage.py; this helper does not claim phone acceptance.
        """
        xml = ET.Element("hierarchy", {"rotation": "0"})

        def node(parent, resource="", text="", box="[0,0][720,1280]", cls="android.widget.FrameLayout", **extra):
            return ET.SubElement(parent, "node", {"package": checks.SETTINGS, "class": cls,
                "resource-id": resource, "text": text, "bounds": box, "enabled": "true", **extra})

        root = node(xml)
        home = node(root, checks.SETTINGS + ":id/settings_homepage_container")
        bar = node(home, checks.SETTINGS + ":id/homepage_app_bar_regular_phone_view", box="[0,0][720,120]")
        search = node(bar, checks.SETTINGS + ":id/search_action_bar", box="[10,10][700,90]", clickable="true")
        node(search, checks.SETTINGS + ":id/search_action_bar_title", "搜索设置", "[20,20][200,60]", "android.widget.TextView")
        content = node(home, checks.SETTINGS + ":id/main_content_scrollable_container", box="[0,120][720,1280]")
        categories = node(content, checks.SETTINGS + ":id/homepage_container", box="[0,120][720,1280]")
        observed = [{"id": "search", "view_id": checks.SETTINGS + ":id/search_action_bar_title",
                     "text": "搜索设置", "bounds": [20, 20, 200, 60]}]
        for i, label in enumerate(("存储", "电池", "系统")):
            box = [20, 150 + i * 120, 200, 200 + i * 120]
            row = node(categories, box="[0,%d][720,%d]" % (120 + i * 120, 240 + i * 120), clickable="true")
            node(row, "android:id/title", label, "[%d,%d][%d,%d]" % tuple(box), "android.widget.TextView")
            observed.append({"id": "title%d" % i, "view_id": "android:id/title", "text": label, "bounds": box})
        (self.root / "ui-final.xml").write_bytes(ET.tostring(xml))
        (self.root / "ui-final-window.txt").write_text(
            "WINDOW MANAGER WINDOWS (synthetic)\n"
            "  Window #0 Window{123 u0 com.android.settings/com.android.settings.Settings}:\n"
            "    mDisplayId=0\n    mAttrs={ty=BASE_APPLICATION}\n"
            "    mActivityRecord=ActivityRecord{1 u0 com.android.settings/.Settings t1}\n"
            "    mViewVisibility=0x0 mObscured=false\n"
            "    mHasSurface=true isReadyForDisplay()=true\n"
            "    Frames: frame=[0,0][720,1280]\n"
            "      Surface: shown=true mDrawState=HAS_DRAWN mLastHidden=false\n"
            "    isOnScreen=true\n    isVisible=true\n"
            "  mTopFocusedDisplayId=0\n")
        step, run_id, before, after = self.event("done", checks.SETTINGS, status="success", summary="synthetic completion")
        common = {"nodes": observed, "nodes_truncated": False, "ime_visible": False,
                  "app_tree_sha256": "b" * 64, "observation_state_sha256": "c" * 64,
                  "window": {"scope": "active_root_only", "metadata_status": "observed", "type": 1,
                             "window_id": 1, "display_id": 0, "root_bounds": [0, 0, 720, 1280],
                             "bounds": [0, 0, 720, 1280], "root_class": "android.widget.FrameLayout",
                             "root_class_truncated": False, "title": "设置", "title_truncated": False}}
        before.update(common); after.update(common)
        prefix = self.root / "task" / ("step-%02d" % step)
        write(Path(str(prefix) + "-before.json"), before); write(Path(str(prefix) + "-after.json"), after)
        action_path = Path(str(prefix) + "-action.json")
        receipt = json.loads(action_path.read_text()); receipt["dispatched"] = False; write(action_path, receipt)
        projection = {"observation_id": before["observation_id"], "package": checks.SETTINGS,
                      "size": [720, 1280], "ime_visible": False, "nodes_omitted": 0,
                      "window": {key: common["window"][key] for key in ("scope", "root_bounds", "bounds", "type", "title", "root_class")},
                      "nodes": [[n["id"], n["text"], n["bounds"], ""] for n in observed]}
        prompt = ("UNTRUSTED_DATA\n" + json.dumps({"screen": projection}, ensure_ascii=False) + "\nOWNER\n" + self.instruction).encode()
        run = self.root / "runs" / run_id
        (run / "prompt.txt").write_bytes(prompt)
        native = json.loads((run / "native-result.json").read_text())
        native["input_sha256"] = {"prompt": acceptance.digest(prompt)}; write(run / "native-result.json", native)
        write(self.root / "task/result.json", {"task_id": self.task_id, "steps": step, "status": "model_reported_done",
              "model_reported_success": True, "cleanup_known": True, "final_observation_id": after["observation_id"]})

    def evaluate(self):
        return checks.evaluate_case(self.root, self.case, suite, acceptance)

    def full(self, verdict="pass"):
        write(self.root / "acceptance.json", {"case_id": self.case["case_id"], "instruction": self.instruction,
              "instruction_sha256": self.owner_sha, "task_id": self.task_id, "launch_attempt_count": 1,
              "verdict": verdict, "cleanup_unknown": False})
        return core.evaluate_one(self.root, self.case, suite, acceptance)

    def home(self, package="com.motorola.launcher"):
        raw = package + "/.Home\n"
        write(self.root / "home-environment.json", {"schema": "hepta.core-home-environment.v1",
              "case_id": self.case["case_id"], "candidate_apk_sha256": "a"*64, "android_user": 0,
              "home_component": package+"/.Home", "home_package": package,
              "command": ["cmd", "package", "resolve-activity", "--brief", "--user", "0",
                          "-a", "android.intent.action.MAIN", "-c", "android.intent.category.HOME"],
              "raw_stdout_utf8": raw, "raw_stdout_sha256": acceptance.digest(raw.encode()),
              "read_only": True, "collected_before_task_submission": True})


def button(label):
    return {"id": "n1", "text": label, "clickable": True, "bounds": [0, 0, 100, 100]}


class CoreChecks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def calculator(self, labels=None, launcher_click=False):
        fixture = Evidence(self.root, "calculator_keypad")
        if launcher_click:
            fixture.event("click", "com.motorola.launcher", node=button("计算器"), after_package=checks.CALCULATOR)
        else:
            fixture.event("open", "com.motorola.launcher", target_package=checks.CALCULATOR, after_package=checks.CALCULATOR)
        for label in labels or ["清除", "2", "3", "乘", "1", "9", "等于"]:
            fixture.event("click", checks.CALCULATOR, node=button(label),
                          after_nodes=[{"id": "r1", "text": "23×19", "view_id": "formula"}])
        fixture.ui(checks.CALCULATOR, [{"class": "android.widget.TextView", "resource-id": "result", "text": "437"}])
        return fixture

    def test_real_keypad_sequence_passes(self):
        self.assertTrue(self.calculator().evaluate()["all_passed"])

    def test_launcher_click_then_real_keypad_passes_full_core(self):
        self.assertEqual(self.calculator(launcher_click=True).full()["verdict"], "pass")

    def test_home_goal_accepts_model_launcher_click(self):
        f = Evidence(self.root, "settings_home")
        f.event("click", "com.motorola.launcher", node=button("设置"), after_package=checks.SETTINGS)
        f.ui(checks.SETTINGS, ["设置", "搜索设置"])
        self.assertEqual(f.full()["verdict"], "pass")

    def test_restored_search_then_real_back_can_reach_home(self):
        f = Evidence(self.root, "settings_home")
        f.event("open", "com.motorola.launcher", target_package=checks.SETTINGS, after_package=checks.SEARCH)
        f.event("back", checks.SEARCH, after_package=checks.SETTINGS)
        f.ui(checks.SETTINGS, ["设置", "搜索设置"])
        self.assertEqual(f.full()["verdict"], "pass")

    def test_target_ui_never_upgrades_failed_or_unfinished_base_task(self):
        f = Evidence(self.root, "settings_home")
        f.event("click", "com.motorola.launcher", node=button("设置"), after_package=checks.SETTINGS)
        f.ui(checks.SETTINGS, ["设置", "搜索设置"])
        self.assertEqual(f.full("fail")["verdict"], "fail")

    def test_visible_goal_without_bound_effect_does_not_pass(self):
        f = Evidence(self.root, "settings_home")
        f.ui(checks.SETTINGS, ["设置", "搜索设置"])
        self.assertEqual(f.full()["verdict"], "fail")

    def test_apps_goal_accepts_launch_restoring_the_correct_page(self):
        f = Evidence(self.root, "apps_management")
        f.event("click", "com.motorola.launcher", node=button("设置"), after_package=checks.SETTINGS)
        f.ui(checks.SETTINGS, ["应用管理", "特殊应用权限"])
        self.assertEqual(f.full()["verdict"], "pass")

    def test_return_goal_accepts_observed_back_button(self):
        f = Evidence(self.root, "search_return_home")
        f.event("click", checks.SEARCH, node=button("返回"), after_package=checks.SETTINGS)
        f.ui(checks.SETTINGS, ["设置", "搜索设置"])
        self.assertEqual(f.full()["verdict"], "pass")

    def test_return_goal_rejects_unrelated_click_even_with_final_home(self):
        f = Evidence(self.root, "search_return_home")
        f.event("click", checks.SEARCH, node=button("广告"), after_package=checks.SETTINGS)
        f.ui(checks.SETTINGS, ["设置", "搜索设置"])
        self.assertEqual(f.full()["verdict"], "fail")

    def test_return_case_already_home_is_inapplicable_not_model_failure(self):
        f = Evidence(self.root, "search_return_home")
        f.event("done", checks.SETTINGS, status="success", summary="已在首页")
        p = self.root / "task/step-01-action.json"
        value = json.loads(p.read_text()); value["dispatched"] = False; write(p, value)
        f.ui(checks.SETTINGS, ["设置", "搜索设置"])
        result = f.full()
        self.assertEqual(result["verdict"], "unverified")
        self.assertTrue(result["precondition_missing"])

    def navigation(self, kind, packages):
        f = Evidence(self.root, kind)
        launcher = "com.motorola.launcher"
        before = launcher
        for package in packages:
            if package == launcher:
                f.event("home", before, after_package=package)
            else:
                f.event("click", before, node=button("图标"), after_package=package)
            before = package
        f.ui(checks.SETTINGS, ["设置", "搜索设置"])
        if kind == "ordered_navigation":
            f.home()
        return f

    def test_ordered_navigation_uses_real_arrivals_not_open_tool(self):
        f = self.navigation("ordered_navigation", [checks.SEARCH, "com.motorola.launcher", checks.SETTINGS])
        self.assertEqual(f.full()["verdict"], "pass")

    def test_home_intent_without_actual_launcher_arrival_fails(self):
        f = self.navigation("ordered_navigation", [checks.SETTINGS, "com.baidu.searchbox", checks.SETTINGS])
        self.assertEqual(f.full()["verdict"], "fail")

    def test_cross_app_allows_launcher_click_routes_in_exact_target_order(self):
        f = self.navigation("cross_app", [checks.SETTINGS, "com.motorola.launcher", checks.CALCULATOR,
                                          "com.motorola.launcher", checks.SETTINGS])
        self.assertEqual(f.full()["verdict"], "pass")

    def test_wrong_target_visit_cannot_hide_before_correct_subsequence(self):
        f = self.navigation("cross_app", [checks.CALCULATOR, checks.SETTINGS, checks.CALCULATOR, checks.SETTINGS])
        self.assertEqual(f.full()["verdict"], "fail")

    def test_extra_calculator_input_during_cross_app_is_rejected(self):
        f = Evidence(self.root, "cross_app")
        f.event("open", "com.motorola.launcher", target_package=checks.SETTINGS, after_package=checks.SETTINGS)
        f.event("open", checks.SETTINGS, target_package=checks.CALCULATOR, after_package=checks.CALCULATOR)
        f.event("click", checks.CALCULATOR, node=button("2"))
        f.event("open", checks.CALCULATOR, target_package=checks.SETTINGS, after_package=checks.SETTINGS)
        f.ui(checks.SETTINGS, ["设置", "搜索设置"])
        self.assertEqual(f.full()["verdict"], "fail")

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

    def test_chinese_search_full_core_does_not_require_open(self):
        self.assertEqual(self.search().full()["verdict"], "pass")

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
        plan = {"schema": core.SCHEMA, "suite_id": "fixture-unknown", "candidate": candidate, "drivers": pin,
                "core": core.core_pin(), "cases": core.templates()[:2]}
        calls = []
        def failure(args):
            calls.append(args.case_id)
            raise RuntimeError("synthetic interrupted submission")
        fake_acceptance = SimpleNamespace(Adb=lambda *args: None, run_task=failure,
                                         private_write=acceptance.private_write, write_json=acceptance.write_json)
        fake_suite = SimpleNamespace(SCHEMA=suite.SCHEMA, summarize=suite.summarize, validate_plan=suite.validate_plan,
                                     require_existing_adb_server=lambda *args, **kwargs: {"fixture": True},
                                     preflight=lambda *args: {"fixture": True}, case_args=suite.case_args,
                                     selected_profile=suite.selected_profile, DEFAULT_PROFILE=suite.DEFAULT_PROFILE,
                                     acceptance=acceptance)
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
