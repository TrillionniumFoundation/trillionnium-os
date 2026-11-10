"""Synthetic v4 native-input/action binding regressions; never contacts a phone."""
import copy
import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import unittest

if os.environ.get("HEPTA_APP_LABEL_TOOLS"):
    sys.path.insert(0, os.environ["HEPTA_APP_LABEL_TOOLS"])
import phone_acceptance as m

V4 = "hepta.observed-action-gbnf.v4-app-label-first"
SCHEMA = "hepta.observed-app-labels.v1"
ENCODING = "utf8-length-prefixed-be32-sorted-package.v1"
OBS = "0123456789abcdef0123456789abcdef"
CURRENT = "org.example.launcher"
PAIRS = {"org.example.settings": "设置", "org.example.contacts": "通讯录",
         "org.example.same_a": "同名", "org.example.same_b": "同名",
         "org.example.empty_a": "", "org.example.empty_b": "",
         "org.example.escaped": '引号"\\\n中文😀'}

def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")

def digest_contract(schema, encoding, pairs):
    blob = bytearray()
    for value in (schema, encoding, OBS, CURRENT):
        raw = value.encode("utf-8"); blob.extend(struct.pack(">I", len(raw))); blob.extend(raw)
    blob.extend(struct.pack(">I", len(pairs)))
    for package, label in sorted(pairs.items()):
        for value in (package, label):
            raw = value.encode("utf-8"); blob.extend(struct.pack(">I", len(raw))); blob.extend(raw)
    return hashlib.sha256(blob).hexdigest()

def decision(package="org.example.settings", label="设置", **changes):
    value = {"reason": "按当前目录选择应用", "action": "open", "observation_id": OBS,
             "app_label": label, "package": package}
    value.update(changes)
    return value

class AppLabelBindingTests(unittest.TestCase):
    def setUp(self):
        self.grammar = b'root ::= "metadata binding fixture, no grammar execution claimed"\n'
        self.data = {"action_schema": V4, "apps": [[p, l] for p, l in PAIRS.items()],
                     "open_allowed_packages": list(PAIRS),
                     "screen": {"observation_id": OBS, "package": CURRENT, "nodes": []}}
        self.prompt = b"UNTRUSTED_DATA\n" + encoded(self.data) + b"\nOWNER\nsynthetic owner"
        self.native = {"input_sha256": {"grammar": m.digest(self.grammar), "prompt": m.digest(self.prompt)}}
        self.receipt = {"grammar_schema": V4, "grammar_sha256": m.digest(self.grammar),
                        "grammar_observation_id": OBS, "grammar_current_package": CURRENT,
                        "prompt_sha256": m.digest(self.prompt),
                        "target_label_contract": {"schema": m.LABEL_SCHEMA, "encoding": m.LABEL_ENCODING,
                            "observation_id": OBS, "package": CURRENT, "pairs_count": 0,
                            "sha256": digest_contract(m.LABEL_SCHEMA, m.LABEL_ENCODING, {})},
                        "app_label_contract": {"schema": SCHEMA, "encoding": ENCODING,
                            "observation_id": OBS, "package": CURRENT, "pairs_count": len(PAIRS),
                            "sha256": digest_contract(SCHEMA, ENCODING, PAIRS)}}

    def valid(self, value=None, receipt=None, native=None, prompt=None, grammar=None):
        raw = encoded(decision() if value is None else value)
        return m.controller_grammar_binding_valid(self.receipt if receipt is None else receipt,
            self.native if native is None else native, self.grammar if grammar is None else grammar,
            {OBS: {CURRENT}}, self.prompt if prompt is None else prompt, raw)

    def rebind_data(self, data):
        prompt = b"UNTRUSTED_DATA\n" + encoded(data) + b"\nOWNER\nsynthetic owner"
        receipt, native = copy.deepcopy(self.receipt), copy.deepcopy(self.native)
        receipt["prompt_sha256"] = native["input_sha256"]["prompt"] = m.digest(prompt)
        return receipt, native, prompt

    def test_native_bound_valid_pair(self):
        self.assertTrue(self.valid())

    def test_duplicate_empty_and_escaped_labels_keep_all_original_packages(self):
        for package, label in PAIRS.items():
            with self.subTest(package=package):
                self.assertTrue(self.valid(decision(package, label)))

    def test_pair_matrix_rejects_crossed_values(self):
        for package, label in PAIRS.items():
            for supplied in set(PAIRS.values()):
                with self.subTest(package=package, label=supplied):
                    self.assertEqual(self.valid(decision(package, supplied)), supplied == label)

    def test_label_is_mandatory_and_ordered(self):
        value = decision(); del value["app_label"]
        self.assertFalse(self.valid(value))
        value["app_label"] = "设置"
        self.assertFalse(self.valid(value))
        for label in (None, True, 1, "设置 ", "Ｓｅｔｔｉｎｇｓ"):
            self.assertFalse(self.valid(decision(label=label)))

    def test_reason_does_not_repair_or_replace_pair(self):
        self.assertTrue(self.valid(decision("org.example.contacts", "通讯录", reason="打开设置")))
        self.assertFalse(self.valid(decision("org.example.contacts", "设置", reason="打开通讯录")))

    def test_receipt_contract_must_be_complete_and_exact(self):
        receipt = copy.deepcopy(self.receipt); del receipt["app_label_contract"]
        self.assertFalse(self.valid(receipt=receipt))
        for key in self.receipt["app_label_contract"]:
            receipt = copy.deepcopy(self.receipt); del receipt["app_label_contract"][key]
            self.assertFalse(self.valid(receipt=receipt), key)
        for key, value in (("schema", "unknown"), ("encoding", "unknown"), ("observation_id", "f" * 32),
                           ("package", "org.example.other"), ("sha256", "0" * 64), ("pairs_count", True), ("pairs_count", 7.0)):
            receipt = copy.deepcopy(self.receipt); receipt["app_label_contract"][key] = value
            self.assertFalse(self.valid(receipt=receipt), (key, value))

    def test_prompt_and_grammar_bytes_cannot_be_swapped(self):
        self.assertFalse(self.valid(prompt=self.prompt + b" "))
        self.assertFalse(self.valid(grammar=self.grammar + b" "))
        data = copy.deepcopy(self.data); data["apps"][0][1] = "通讯录"
        receipt, native, prompt = self.rebind_data(data)
        self.assertFalse(self.valid(receipt=receipt, native=native, prompt=prompt))

    def test_unknown_missing_or_downgraded_schema_does_not_qualify(self):
        for schema in (None, "unknown", "hepta.observed-action-gbnf.v1", "hepta.observed-action-gbnf.v2-reason-first", m.LABEL_ACTION_SCHEMA):
            receipt = copy.deepcopy(self.receipt); receipt["grammar_schema"] = schema
            self.assertFalse(self.valid(receipt=receipt))
            del receipt["app_label_contract"]
            self.assertFalse(self.valid(receipt=receipt), schema)
            value = decision(); del value["app_label"]
            self.assertFalse(self.valid(value, receipt=receipt), (schema, "stripped label"))

    def test_v4_requires_schema_in_real_native_prompt(self):
        for schema in (None, "unknown", m.LABEL_ACTION_SCHEMA):
            data = copy.deepcopy(self.data)
            if schema is None: del data["action_schema"]
            else: data["action_schema"] = schema
            receipt, native, prompt = self.rebind_data(data)
            self.assertFalse(self.valid(receipt=receipt, native=native, prompt=prompt))

    def test_allowed_subset_does_not_expand_to_omitted_or_current_apps(self):
        self.assertFalse(self.valid(decision("org.example.unseen", "设置")))
        self.assertFalse(self.valid(decision(CURRENT, "设置")))
        for allowed in (["org.example.unseen"], ["android"], [CURRENT], ["org.example.settings"] * 2):
            data = copy.deepcopy(self.data); data["open_allowed_packages"] = allowed
            receipt, native, prompt = self.rebind_data(data)
            self.assertFalse(self.valid(receipt=receipt, native=native, prompt=prompt))

    def test_blocked_open_cannot_remain_allowed(self):
        for field, value in (("blocked", {"open_packages": ["org.example.settings"]}),
                             ("blocked_action", {"action": "open", "package": "org.example.settings"})):
            data = copy.deepcopy(self.data); data[field] = value
            receipt, native, prompt = self.rebind_data(data)
            self.assertFalse(self.valid(receipt=receipt, native=native, prompt=prompt))

    def test_duplicate_package_or_malformed_app_rows_fail(self):
        bad_rows = [self.data["apps"] + [self.data["apps"][0]], [["org.example.settings", "x" * 50]],
                    [["org.example.settings", None]], [["org.example.settings"]], [["bad", "设置"]],
                    [["org.example.settings", "x\0y"]]]
        for rows in bad_rows:
            data = copy.deepcopy(self.data); data["apps"] = rows
            receipt, native, prompt = self.rebind_data(data)
            self.assertFalse(self.valid(receipt=receipt, native=native, prompt=prompt))

    def test_non_open_keeps_current_package_and_rejects_app_label(self):
        value = {"reason": "返回", "action": "home", "observation_id": OBS, "package": CURRENT}
        self.assertTrue(self.valid(value))
        value["app_label"] = "设置"; self.assertFalse(self.valid(value))
        del value["app_label"]; value["package"] = "org.example.settings"
        self.assertFalse(self.valid(value))

    def test_stale_identity_and_extra_action_fields_rejected(self):
        self.assertFalse(self.valid(decision(observation_id="f" * 32)))
        for key, value in (("node_id", "n1"), ("node_label", "设置"), ("text", "extra"), ("schema", V4)):
            self.assertFalse(self.valid(decision(**{key: value})))

    def test_real_prompt_binding_cannot_be_replaced_by_success_flags(self):
        receipt = copy.deepcopy(self.receipt); receipt.update(grammar_binding_valid=True, native_result_binding_valid=True)
        receipt["app_label_contract"]["sha256"] = "0" * 64
        self.assertFalse(self.valid(receipt=receipt))

if __name__ == "__main__":
    unittest.main(verbosity=2)
