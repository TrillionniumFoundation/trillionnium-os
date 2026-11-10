"""Replay generated or explicitly supplied private evidence; never contact a phone.

The public runner generates all default fixture bytes from scratch. An explicit
--external-fixtures path selects private retained evidence with its SHA manifest.
Negative mutations affect disposable copies only. These tests qualify a page
oracle, not Android, native performance, or all tasks.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import xml.etree.ElementTree as ET

REVIEW = Path(__file__).resolve().parent.parent
FIXTURES = Path(os.environ.get("HEPTA_ORACLE_FIXTURE_ROOT", REVIEW / "fixtures"))
MANIFEST = Path(os.environ.get("HEPTA_ORACLE_MANIFEST", FIXTURES.parent / "EVIDENCE-SOURCES.json"))
DRIVERS = Path(os.environ.get("HEPTA_CORE_TEST_DRIVERS", REVIEW / "drivers"))
sys.path.insert(0, str(DRIVERS))
import phone_acceptance as acceptance
import phone_suite as suite
import core_assertions as checks
import core_phone_suite as core

HOME = "core-settings-home-01"
CROSS = "core-cross-app-01"
SUBPAGE = "core-search-return-home-01"


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


class SettingsHomepageEvidence(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.plan = json.loads((FIXTURES / "original-plan.json").read_text())
        cls.manifest = json.loads(MANIFEST.read_text())
        cls.verify_originals()

    @classmethod
    def verify_originals(cls):
        for item in cls.manifest["files"]:
            relative = Path(item["dest"]).relative_to("fixtures")
            path = FIXTURES / relative
            raw = path.read_bytes()
            if len(raw) != item["bytes"] or hashlib.sha256(raw).hexdigest() != item["sha"]:
                raise AssertionError("captured original changed: " + str(relative))

    @classmethod
    def tearDownClass(cls):
        cls.verify_originals()

    def setUp(self):
        temp_root = REVIEW / "tmp"
        temp_root.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=temp_root)
        self.directory = Path(self.temp.name) / CROSS
        shutil.copytree(FIXTURES / "cases" / CROSS, self.directory)
        self.case = copy.deepcopy(next(c for c in self.plan["cases"] if c["case_id"] == CROSS))
        self.patches = [mock.patch.object(acceptance, "Adb", side_effect=AssertionError("phone access forbidden")),
                        mock.patch.object(socket, "create_connection", side_effect=AssertionError("network forbidden")),
                        mock.patch.object(subprocess, "Popen", side_effect=AssertionError("subprocess forbidden")),
                        mock.patch.object(subprocess, "run", side_effect=AssertionError("subprocess forbidden"))]
        for patch in self.patches:
            patch.start()

    def tearDown(self):
        for patch in reversed(self.patches):
            patch.stop()
        self.temp.cleanup()

    def evaluate(self, directory=None, case=None):
        return checks.settings_homepage_evidence(directory or self.directory, case or self.case, suite, acceptance)

    def mutate_json(self, relative, mutate):
        path = self.directory / relative
        value = json.loads(path.read_text())
        mutate(value)
        write_json(path, value)

    def mutate_pair(self, mutate):
        for suffix in ("before", "after"):
            self.mutate_json("task/step-04-" + suffix + ".json", mutate)

    def mutate_xml(self, mutate):
        path = self.directory / "ui-final.xml"
        xml = ET.fromstring(path.read_bytes())
        mutate(xml)
        path.write_bytes(ET.tostring(xml, encoding="utf-8"))

    def home_block(self):
        path = self.directory / "ui-final-window.txt"
        text = path.read_text()
        pattern = re.compile(r"^  Window #\d+ Window\{[^ }]+ u0 com\.android\.settings/com\.android\.settings\.Settings\}:\n.*?(?=^  Window #|\Z)", re.M | re.S)
        matches = list(pattern.finditer(text))
        self.assertEqual(len(matches), 1)
        return path, text, matches[0]

    def mutate_window(self, mutate):
        path, text, match = self.home_block()
        path.write_text(text[:match.start()] + mutate(match.group()) + text[match.end():])

    def mutate_system_window(self, kind, mutate):
        path = self.directory / "ui-final-window.txt"
        text = path.read_text()
        pattern = re.compile(r"^  Window #\d+ Window\{[^\n]+\}:\n.*?(?=^  Window #|\Z)", re.M | re.S)
        matches = [m for m in pattern.finditer(text)
                   if re.search(r"\bmDisplayId=(\d+)\b", m.group()).group(1) == "0"
                   and re.search(r"\bty=" + kind + r"\b", m.group())]
        self.assertEqual(len(matches), 1)
        match = matches[0]
        path.write_text(text[:match.start()] + mutate(match.group()) + text[match.end():])

    def assert_rejected(self, complete=None):
        value = self.evaluate()
        self.assertFalse(value["passed"], value)
        if complete is not None:
            self.assertIs(value["evidence_complete"], complete, value)
        self.assertFalse(value["phone_contacted"])
        self.assertFalse(value["full_task_acceptance_claimed"])
        return value

    def test_two_scrolled_homepages_pass_with_exact_native_binding(self):
        for name in (HOME, CROSS):
            with self.subTest(case=name):
                directory = FIXTURES / "cases" / name
                case = next(c for c in self.plan["cases"] if c["case_id"] == name)
                value = self.evaluate(directory, case)
                self.assertTrue(value["passed"], value)
                self.assertTrue(value["evidence_complete"])
                self.assertEqual(value["errors"], [])
                self.assertTrue(value["checks"][0]["binding"]["verified"])
                self.assertIn("ui-final-window.txt", value["source_files"])
                ui = checks.final_ui(directory, acceptance)
                self.assertFalse(acceptance.ui_predicates(ui, checks.SETTINGS, ["设置", "搜索设置"])["all_passed"])

    def test_system_subsettings_rejected_despite_package_and_search(self):
        directory = FIXTURES / "cases" / SUBPAGE
        case = next(c for c in self.plan["cases"] if c["case_id"] == SUBPAGE)
        weak = acceptance.ui_predicates(checks.final_ui(directory, acceptance), checks.SETTINGS, ["搜索设置"])
        self.assertTrue(weak["all_passed"])
        value = self.evaluate(directory, case)
        self.assertFalse(value["passed"])
        self.assertTrue(value["evidence_complete"])
        negative = {c["kind"] for c in value["checks"] if not c["passed"]}
        self.assertIn("independent_visible_unobscured_settings_activity", negative)
        self.assertIn("same_window_homepage_structure", negative)

    def test_future_templates_only_remove_collapsible_title_from_four_home_cases(self):
        old = {c["case_id"]: c for c in self.plan["cases"]}
        for candidate in core.templates():
            with self.subTest(case=candidate["case_id"]):
                expected = copy.deepcopy(old[candidate["case_id"]])
                if candidate["assertion"] in checks.HOME_KINDS:
                    self.assertEqual(expected["expected_visible_text"], ["设置", "搜索设置"])
                    expected["expected_visible_text"] = ["搜索设置"]
                self.assertEqual(candidate, expected)

    def test_visible_settings_window_flags_are_mandatory(self):
        replacements = [("mObscured=false", "mObscured=true"), ("mViewVisibility=0x0", "mViewVisibility=0x8"),
                        ("mHasSurface=true", "mHasSurface=false"), ("isReadyForDisplay()=true", "isReadyForDisplay()=false"),
                        ("isOnScreen=true", "isOnScreen=false"), ("isVisible=true", "isVisible=false"),
                        ("Surface: shown=true", "Surface: shown=false"), ("mDrawState=HAS_DRAWN", "mDrawState=NO_SURFACE")]
        original = (self.directory / "ui-final-window.txt").read_bytes()
        for old, new in replacements:
            with self.subTest(flag=old):
                (self.directory / "ui-final-window.txt").write_bytes(original)
                self.mutate_window(lambda text: text.replace(old, new))
                self.assert_rejected(complete=True)

    def test_wrong_display_or_frame_rejected(self):
        original = (self.directory / "ui-final-window.txt").read_bytes()
        before = json.loads((self.directory / "task/step-04-before.json").read_text())
        width, height = before["screen_width"], before["screen_height"]
        original_frame = "frame=[0,0][%d,%d]" % (width, height)
        wrong_frame = "frame=[0,0][%d,%d]" % (width, height - 100)
        for old, new in (("mDisplayId=0", "mDisplayId=1"), (original_frame, wrong_frame)):
            with self.subTest(field=old):
                (self.directory / "ui-final-window.txt").write_bytes(original)
                self.mutate_window(lambda text: text.replace(old, new))
                self.assert_rejected(complete=True)

    def test_global_wms_footer_cannot_supply_a_hidden_window_identity(self):
        self.mutate_window(lambda text: text.replace("mObscured=false", "mObscured=true"))
        self.assertIn("Hiding System Alert Windows:", (self.directory / "ui-final-window.txt").read_text())
        self.assert_rejected(complete=True)

    def test_duplicate_home_window_is_ambiguous(self):
        path, text, match = self.home_block()
        path.write_text(text + "\n" + re.sub(r"Window #\d+", "Window #999", match.group(), count=1))
        self.assert_rejected(complete=True)

    def test_other_visible_application_window_rejected(self):
        path, text, match = self.home_block()
        foreign = match.group().replace("com.android.settings/com.android.settings.Settings", "example.other/example.other.Main")
        path.write_text(text + "\n" + re.sub(r"Window #\d+", "Window #999", foreign, count=1))
        self.assert_rejected(complete=True)

    def test_visible_overlay_or_dialog_rejected_even_if_home_is_not_obscured(self):
        path, original, match = self.home_block()
        for kind in ("APPLICATION_OVERLAY", "APPLICATION_ATTACHED_DIALOG", "NOTIFICATION_SHADE", "INPUT_METHOD"):
            with self.subTest(kind=kind):
                foreign = match.group().replace("com.android.settings/com.android.settings.Settings", "example.other/Overlay")
                foreign = foreign.replace("ty=BASE_APPLICATION", "ty=" + kind)
                path.write_text(original + "\n" + re.sub(r"Window #\d+", "Window #999", foreign, count=1))
                self.assert_rejected(complete=True)

    def test_home_on_nonfocused_display_rejected(self):
        path = self.directory / "ui-final-window.txt"
        path.write_text(path.read_text().replace("mTopFocusedDisplayId=0", "mTopFocusedDisplayId=1"))
        self.assert_rejected(complete=True)

    def test_missing_focused_display_is_unverified(self):
        path = self.directory / "ui-final-window.txt"
        path.write_text(path.read_text().replace("mTopFocusedDisplayId=0", ""))
        self.assert_rejected(complete=False)

    def test_system_bar_must_remain_a_thin_edge_strip(self):
        original = (self.directory / "ui-final-window.txt").read_bytes()
        for kind in ("STATUS_BAR", "NAVIGATION_BAR"):
            with self.subTest(kind=kind):
                (self.directory / "ui-final-window.txt").write_bytes(original)
                self.mutate_system_window(kind, lambda text: re.sub(r"\bframe=\[\d+,\d+\]\[\d+,\d+\]", "frame=[0,700][1224,1600]", text))
                self.assert_rejected(complete=True)

    def test_system_bar_requires_systemui_window_identity(self):
        self.mutate_system_window("STATUS_BAR", lambda text: text.replace("package=com.android.systemui", "package=example.overlay"))
        self.assert_rejected(complete=True)

    def test_allowed_edge_bar_cannot_cover_the_verified_search_entry(self):
        before = json.loads((self.directory / "task/step-04-before.json").read_text())
        search = next(n for n in before["nodes"] if n.get("view_id", "").endswith("search_action_bar_title"))
        covering_frame = "frame=[0,0][%d,%d]" % (before["screen_width"], search["bounds"][1] + 1)
        self.mutate_system_window("STATUS_BAR", lambda text: re.sub(r"\bframe=\[\d+,\d+\]\[\d+,\d+\]", covering_frame, text))
        self.assert_rejected(complete=True)

    def test_visible_wallpaper_is_not_an_allowed_foreground_window(self):
        self.mutate_system_window("WALLPAPER", lambda text: text.replace("isVisible=false", "isVisible=true").replace("isOnScreen=false", "isOnScreen=true"))
        self.assert_rejected(complete=True)

    def test_original_native_prompt_binds_terminal_window_projection(self):
        self.mutate_pair(lambda value: value["window"].__setitem__("root_class", "example.OtherRoot"))
        self.mutate_xml(lambda xml: xml[0].set("class", "example.OtherRoot"))
        self.assert_rejected(complete=False)

    def test_transparent_home_window_rejected(self):
        original = (self.directory / "ui-final-window.txt").read_bytes()
        for alpha in ("alpha=0.0", "mShownAlpha=0.0", "mAlpha=0.0", "alpha=nan"):
            with self.subTest(alpha=alpha):
                (self.directory / "ui-final-window.txt").write_bytes(original)
                self.mutate_window(lambda text: text.replace("mViewVisibility=0x0", "mViewVisibility=0x0 " + alpha))
                self.assert_rejected(complete=True)

    def test_conflicting_home_window_type_is_unverified(self):
        self.mutate_window(lambda text: text.replace("ty=BASE_APPLICATION", "ty=BASE_APPLICATION ty=APPLICATION_OVERLAY"))
        self.assert_rejected(complete=False)

    def test_conflicting_home_surface_is_unverified(self):
        self.mutate_window(lambda text: text + "      Surface: shown=false mDrawState=NO_SURFACE mLastHidden=true\n")
        self.assert_rejected(complete=False)

    def test_conflicting_home_activity_is_unverified(self):
        self.mutate_window(lambda text: text + "    mActivityRecord=ActivityRecord{other u0 example.other/.Main t9}\n")
        self.assert_rejected(complete=False)

    def test_missing_window_evidence_is_unverified(self):
        (self.directory / "ui-final-window.txt").unlink()
        self.assert_rejected(complete=False)

    def test_window_partial_record_is_unverified(self):
        self.mutate_window(lambda text: re.sub(r"\bmDisplayId=\d+", "", text))
        self.assert_rejected(complete=False)

    def test_package_and_search_word_without_structure_rejected(self):
        self.mutate_xml(lambda xml: [n.set("resource-id", "") for n in xml.iter("node")
                                    if "homepage" in n.get("resource-id", "")])
        self.assert_rejected(complete=True)

    def test_hidden_homepage_container_rejected(self):
        self.mutate_xml(lambda xml: next(n for n in xml.iter("node") if n.get("resource-id", "").endswith("settings_homepage_container")).set("visible-to-user", "false"))
        self.assert_rejected(complete=True)

    def test_foreign_package_homepage_anchor_rejected(self):
        self.mutate_xml(lambda xml: next(n for n in xml.iter("node") if n.get("resource-id", "").endswith("homepage_container")).set("package", "example.other"))
        self.assert_rejected(complete=True)

    def test_duplicate_anchor_rejected(self):
        def change(xml):
            anchor = next(n for n in xml.iter("node") if n.get("resource-id", "").endswith("settings_homepage_container"))
            xml[0].append(copy.deepcopy(anchor))
        self.mutate_xml(change)
        self.assert_rejected(complete=True)

    def test_offscreen_or_inverted_anchor_rejected(self):
        self.mutate_xml(lambda xml: next(n for n in xml.iter("node") if n.get("resource-id", "").endswith("homepage_app_bar_regular_phone_view")).set("bounds", "[0,100][0,50]"))
        self.assert_rejected(complete=True)

    def test_active_search_input_rejected_even_with_home_anchors(self):
        def change(xml):
            ET.SubElement(xml[0], "node", {"package": checks.SETTINGS, "class": "android.widget.EditText",
                "resource-id": "android:id/search_src_text", "text": "搜索设置", "bounds": "[0,400][500,500]", "enabled": "true"})
        self.mutate_xml(change)
        self.assert_rejected(complete=True)

    def test_subpage_toolbar_rejected_even_with_home_anchors(self):
        def change(xml):
            ET.SubElement(xml[0], "node", {"package": checks.SETTINGS, "class": "android.view.ViewGroup",
                "resource-id": checks.SETTINGS + ":id/collapsing_toolbar", "content-desc": "系统",
                "bounds": "[0,400][500,500]", "enabled": "true"})
        self.mutate_xml(change)
        self.assert_rejected(complete=True)

    def test_xml_search_must_match_terminal_observation_bounds(self):
        self.mutate_xml(lambda xml: next(n for n in xml.iter("node") if n.get("resource-id", "").endswith("search_action_bar_title")).set("bounds", "[300,170][600,257]"))
        self.assert_rejected(complete=True)

    def test_xml_titles_must_match_terminal_observation(self):
        self.mutate_xml(lambda xml: [n.set("text", "wrong:" + n.get("text", "")) for n in xml.iter("node") if n.get("resource-id") == "android:id/title"])
        self.assert_rejected(complete=True)

    def test_observation_and_xml_cannot_replace_the_native_prompt_projection(self):
        def change_observation(value):
            for node in value["nodes"]:
                if node.get("view_id") == "android:id/title": node["text"] = "wrong:" + node["text"]
        self.mutate_pair(change_observation)
        self.mutate_xml(lambda xml: [n.set("text", "wrong:" + n.get("text", "")) for n in xml.iter("node") if n.get("resource-id") == "android:id/title"])
        self.assert_rejected(complete=True)

    def test_xml_rotation_mismatch_unverified(self):
        self.mutate_xml(lambda xml: xml.set("rotation", "1"))
        self.assert_rejected(complete=False)

    def test_truncated_observation_or_window_metadata_unverified(self):
        original = {suffix: (self.directory / ("task/step-04-" + suffix + ".json")).read_bytes() for suffix in ("before", "after")}
        for field in ("nodes_truncated", "root_class_truncated", "title_truncated"):
            with self.subTest(field=field):
                for suffix, raw in original.items(): (self.directory / ("task/step-04-" + suffix + ".json")).write_bytes(raw)
                self.mutate_pair(lambda value: value.__setitem__(field, True) if field == "nodes_truncated" else value["window"].__setitem__(field, True))
                self.assert_rejected(complete=False)

    def test_final_observation_changed_after_done_unverified(self):
        self.mutate_json("task/step-04-after.json", lambda value: value["nodes"][0].__setitem__("text", "changed"))
        self.assert_rejected(complete=False)

    def test_terminal_result_must_name_exact_final_observation(self):
        self.mutate_json("task/result.json", lambda value: value.__setitem__("final_observation_id", "0" * 32))
        self.assert_rejected(complete=False)

    def test_original_owner_instruction_is_required(self):
        self.case["instruction"] += "changed"
        self.assert_rejected(complete=False)

    def test_native_raw_tamper_rejected(self):
        action = json.loads((self.directory / "task/step-04-action.json").read_text())
        path = self.directory / "runs" / action["model_run_id"] / "raw-text.txt"
        path.write_bytes(path.read_bytes() + b" ")
        self.assert_rejected(complete=False)

    def test_native_prompt_tamper_rejected(self):
        action = json.loads((self.directory / "task/step-04-action.json").read_text())
        path = self.directory / "runs" / action["model_run_id"] / "prompt.txt"
        path.write_bytes(path.read_bytes() + b" ")
        self.assert_rejected(complete=False)

    def test_dispatched_action_must_equal_original_native_decision(self):
        self.mutate_json("task/step-04-action.json", lambda value: value["action"].__setitem__("summary", "changed"))
        self.assert_rejected(complete=False)

    def test_symlink_xml_rejected(self):
        path = self.directory / "ui-final.xml"
        path.unlink(); path.symlink_to(FIXTURES / "cases" / CROSS / "ui-final.xml")
        self.assert_rejected(complete=False)

    def test_duplicate_json_keys_rejected(self):
        path = self.directory / "task/result.json"
        raw = path.read_text()
        path.write_text(raw.replace('"cleanup_known": true', '"cleanup_known": true, "cleanup_known": true'))
        self.assert_rejected(complete=False)


if __name__ == "__main__":
    unittest.main(verbosity=2)
