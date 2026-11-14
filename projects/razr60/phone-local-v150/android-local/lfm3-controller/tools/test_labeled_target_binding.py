"""Host-only v3 evidence contracts. No ADB, model generation, or phone actions."""
import copy
import json
import unittest
import phone_acceptance as m

OBS = "0123456789abcdef0123456789abcdef"
PKG = "com.example.app"
LABELS = {"n12": "1", "n13": "2", "n14": "3", "n20": "重复", "n21": "重复",
    "n22": "", "n23": "", "n24": '引号"\\\n中文😀'}
CANONICAL_SHA = "1c9ba0d8ad6b033070d323b5c6c5a21417f43337f1751a52cc25dc6282650fa3"


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def prompt(nodes=None, observation=OBS, package=PKG):
    rows = [[node_id, label, [0, 0, 100, 100], "c"] for node_id, label in LABELS.items()] if nodes is None else nodes
    return b"UNTRUSTED_DATA\n" + encoded({"screen": {
        "observation_id": observation, "package": package, "nodes": rows}}) + b"\nOWNER\nfixture owner"


def action(label="2", node_id="n13", name="click", **changes):
    value = {"reason": "根据可见目标操作", "action": name, "observation_id": OBS, "package": PKG,
        "node_label": label, "node_id": node_id}
    value.update(changes)
    return value


class LabelBindingTests(unittest.TestCase):
    def setUp(self):
        self.grammar = b'root ::= "metadata-test-only"\n'
        self.prompt = prompt()
        self.native = {"input_sha256": {"grammar": m.digest(self.grammar), "prompt": m.digest(self.prompt)}}
        self.receipt = {"grammar_schema": m.LABEL_ACTION_SCHEMA, "grammar_sha256": m.digest(self.grammar),
            "grammar_observation_id": OBS, "grammar_current_package": PKG, "prompt_sha256": m.digest(self.prompt),
            "target_label_contract": {"schema": m.LABEL_SCHEMA, "encoding": m.LABEL_ENCODING,
                "observation_id": OBS, "package": PKG, "sha256": CANONICAL_SHA, "pairs_count": len(LABELS)}}

    def valid(self, value=None, receipt=None, native=None, prompt_bytes=None):
        return m.controller_grammar_binding_valid(self.receipt if receipt is None else receipt,
            self.native if native is None else native, self.grammar, {OBS: {PKG}},
            self.prompt if prompt_bytes is None else prompt_bytes, encoded(action() if value is None else value))

    def test_explicit_v3_receipt_binds_the_actual_native_prompt_and_exact_pair(self):
        self.assertTrue(self.valid())
        for name in ("click", "type", "scroll"):
            self.assertTrue(self.valid(action(name=name)))
        self.assertFalse(m.controller_grammar_binding_valid(self.receipt, self.native, self.grammar, {OBS: {PKG}}))

    def test_unknown_missing_or_incomplete_label_metadata_never_qualifies(self):
        for schema in (None, "hepta.observed-action-gbnf.v3", "hepta.observed-action-gbnf.v99"):
            self.assertFalse(self.valid(receipt={**self.receipt, "grammar_schema": schema}))
        self.assertFalse(self.valid(receipt={k: v for k, v in self.receipt.items() if k != "target_label_contract"}))
        for key in self.receipt["target_label_contract"]:
            receipt = copy.deepcopy(self.receipt); del receipt["target_label_contract"][key]
            self.assertFalse(self.valid(receipt=receipt), key)
        for key, value in (("schema", "unknown"), ("encoding", "unknown"), ("observation_id", "f" * 32),
                ("package", "com.example.other"), ("sha256", "0" * 64), ("pairs_count", 1), ("pairs_count", True)):
            receipt = copy.deepcopy(self.receipt); receipt["target_label_contract"][key] = value
            self.assertFalse(self.valid(receipt=receipt), (key, value))

    def test_unknown_crossed_missing_or_unordered_pairs_are_rejected(self):
        for value in (action(label="1"), action(label="unknown"), action(node_id="n99"), action(label=None),
                action(node_id=None), action(label=" 2"), action(label="２")):
            self.assertFalse(self.valid(value), value)
        for key in ("node_label", "node_id"):
            value = action(); del value[key]
            self.assertFalse(self.valid(value))
        value = action(); label = value.pop("node_label"); value["node_label"] = label
        self.assertFalse(self.valid(value))

    def test_duplicate_and_empty_labels_never_resolve_to_another_id(self):
        for node_id in ("n20", "n21", "n22", "n23", "n24"):
            self.assertTrue(self.valid(action(label=LABELS[node_id], node_id=node_id)))
        self.assertFalse(self.valid(action(label="重复", node_id="n22")))
        self.assertFalse(self.valid(action(label="", node_id="n20")))

    def test_reason_neither_replaces_nor_repairs_the_pair(self):
        self.assertTrue(self.valid(action(reason="实际选择文字1和n12")))
        self.assertFalse(self.valid(action(label="1", reason="实际选择文字1和n12")))

    def test_wrong_observation_and_package_fail_even_with_a_valid_pair(self):
        self.assertFalse(self.valid(action(observation_id="f" * 32)))
        self.assertFalse(self.valid(action(package="com.example.other")))
        for changed in (prompt(observation="f" * 32), prompt(package="com.example.other")):
            self.assertFalse(self.valid(prompt_bytes=changed))

    def test_prompt_bytes_cannot_be_swapped_or_changed_under_the_receipt(self):
        changed = self.prompt.replace(b'"n13","2"', b'"n13","1"')
        self.assertNotEqual(changed, self.prompt)
        self.assertFalse(self.valid(prompt_bytes=changed))
        for target in ("app", "native"):
            receipt = copy.deepcopy(self.receipt); native = copy.deepcopy(self.native)
            if target == "app": receipt["prompt_sha256"] = "0" * 64
            else: native["input_sha256"]["prompt"] = "0" * 64
            self.assertFalse(self.valid(receipt=receipt, native=native))
        # Even rebinding the native prompt hash cannot forge the fixed pair hash.
        receipt = copy.deepcopy(self.receipt); native = copy.deepcopy(self.native)
        receipt["prompt_sha256"] = native["input_sha256"]["prompt"] = m.digest(changed)
        self.assertFalse(self.valid(receipt=receipt, native=native, prompt_bytes=changed))

    def test_malformed_duplicate_or_oversized_prompt_labels_fail_closed(self):
        bad_rows = [
            [["n13", "2", [], "c"], ["n13", "2", [], "c"]],
            [["n13", "x" * 38, [], "c"]], [["n13", "😀" * 19, [], "c"]],
            [["n13", None, [], "c"]], [["invalid", "2", [], "c"]],
            [["n13", "2"]],
        ]
        for rows in bad_rows:
            data = prompt(rows); receipt = copy.deepcopy(self.receipt); native = copy.deepcopy(self.native)
            receipt["prompt_sha256"] = native["input_sha256"]["prompt"] = m.digest(data)
            self.assertFalse(self.valid(receipt=receipt, native=native, prompt_bytes=data))

    def test_non_node_actions_cannot_carry_a_target_pair(self):
        self.assertFalse(self.valid(action(name="back")))
        value = action(name="back"); del value["node_label"]; del value["node_id"]
        self.assertTrue(self.valid(value))


if __name__ == "__main__":
    unittest.main()
