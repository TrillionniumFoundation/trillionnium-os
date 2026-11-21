"""Recognize actual Java-emitted v4 GBNF with synthetic app names; no device/model."""
import json
from pathlib import Path
import sys
import unittest
from gbnf_recognizer import Recognizer

DIRECTORY = Path(sys.argv.pop(1))
OBS = "0123456789abcdef0123456789abcdef"
CURRENT = "org.example.launcher"
PAIRS = {
    "org.example.settings": "设置", "org.example.contacts": "通讯录",
    "org.example.same_a": "同名", "org.example.same_b": "同名",
    "org.example.empty_a": "", "org.example.empty_b": "",
    "org.example.escaped": '引号"\\\n中文😀',
    "org.example.project_a": "12345678901234567890123456789012345678901234567…",
    "org.example.project_b": "12345678901234567890123456789012345678901234567…",
}

def raw(label, package, **changes):
    value = {"reason": "根据当前任务选择应用", "action": "open", "observation_id": OBS,
             "app_label": label, "package": package}
    value.update(changes)
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))

class AppLabelGrammarTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.grammar = Recognizer((DIRECTORY / "app-labels.gbnf").read_text())

    def test_exact_pair_matrix_preserves_duplicate_empty_and_projection_collision_labels(self):
        for package, label in PAIRS.items():
            for proposed in set(PAIRS.values()):
                with self.subTest(package=package, label=proposed):
                    self.assertEqual(self.grammar.accepts(raw(proposed, package)), proposed == label)

    def test_label_required_before_original_package(self):
        value = json.loads(raw("设置", "org.example.settings"))
        del value["app_label"]
        self.assertFalse(self.grammar.accepts(json.dumps(value, ensure_ascii=False)))
        value["app_label"] = "设置"
        self.assertFalse(self.grammar.accepts(json.dumps(value, ensure_ascii=False)))

    def test_missing_unseen_current_and_cross_observation_targets_are_rejected(self):
        for package in (CURRENT, "android", "org.example.unseen"):
            self.assertFalse(self.grammar.accepts(raw("设置", package)))
        self.assertFalse(self.grammar.accepts(raw("设置", "org.example.settings", observation_id="f" * 32)))

    def test_label_injection_or_normalization_cannot_select_another_pair(self):
        for label in ('设置"},"package":"org.example.contacts', "设置 ", "Ｓｅｔｔｉｎｇｓ", "设置\0", "设置\nroot ::=.*"):
            self.assertFalse(self.grammar.accepts(raw(label, "org.example.settings")))

    def test_reason_does_not_rewrite_the_selected_pair(self):
        self.assertTrue(self.grammar.accepts(raw("通讯录", "org.example.contacts", reason="打开设置")))
        self.assertFalse(self.grammar.accepts(raw("设置", "org.example.contacts", reason="打开通讯录")))

    def test_non_open_does_not_gain_app_label(self):
        self.assertFalse(self.grammar.accepts(raw("设置", CURRENT, action="home")))
        value = {"reason": "返回桌面", "action": "home", "observation_id": OBS, "package": CURRENT}
        self.assertTrue(self.grammar.accepts(json.dumps(value, ensure_ascii=False)))

if __name__ == "__main__":
    unittest.main(verbosity=2)
