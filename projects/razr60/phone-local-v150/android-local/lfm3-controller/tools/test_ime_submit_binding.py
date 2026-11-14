"""Synthetic v5 evidence regressions. No ADB, Android calls or model inference.

These tests bind independently constructed protocol bytes, not an imitation
Accessibility dispatcher. Actual Android behavior requires separate device tests.
"""
import copy
import hashlib
import json
from pathlib import Path
import struct
import tempfile
import unittest

import phone_acceptance as a
import phone_suite as s

V5 = "hepta.observed-action-gbnf.v5-ime-enter"
OBS = "0123456789abcdef0123456789abcdef"
TASK = "a" * 32
RUN = "b" * 32
PKG = "org.example.search"
TEXT = "中文搜索词" * 30 + "尾部完整值😀"
OWNER = "在测试搜索应用查找指定文字，不发送消息、不下单、不付款。"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def contract_digest(schema, encoding, pairs):
    raw = bytearray()
    def field(value):
        value = value.encode("utf-8")
        raw.extend(struct.pack(">I", len(value))); raw.extend(value)
    for value in (schema, encoding, OBS, PKG):
        field(value)
    raw.extend(struct.pack(">I", len(pairs)))
    for identity, label in sorted(pairs.items()):
        field(identity); field(label)
    return sha(raw)


class Fixture:
    def __init__(self, label="搜索", background=False, schema=V5):
        self.label = label
        self.grammar = b'root ::= "metadata fixture; grammar execution is tested separately"\n'
        self.action = {"reason": "根据当前可编辑搜索框调用已观察的编辑器动作", "action": "submit",
            "observation_id": OBS, "package": PKG, "node_label": "当前搜索", "node_id": "n7"}
        self.capability = {"schema": "hepta.observed-ime-enter.v1", "action_name": "ACTION_IME_ENTER",
            "action_label": label, "action_label_sha256": sha(label.encode("utf-8")),
            "input_text_sha256": sha(TEXT.encode("utf-8"))}
        self.data = {"action_schema": schema, "apps": [], "open_allowed_packages": [],
            "screen": {"observation_id": OBS, "package": PKG,
                "nodes": [["n7", "当前搜索", [0, 0, 100, 40], "tf"], ["n8", "其他字段", [0, 50, 100, 90], "tf"]],
                "editable_fields": [{"node_id": "n7", "role": "editable_text", "text": TEXT[:96],
                    "focused": True, "enabled": True}, {"node_id": "n8", "role": "editable_text",
                    "text": "另一个输入", "focused": True, "enabled": True}],
                "submit_actions": {"n7": dict(self.capability)}}}
        if schema == a.FIXED_INTENT_ACTION_SCHEMA:
            self.data["fixed_intent_tools"] = []
        self.app = {"run_id": RUN, "grammar_schema": schema, "grammar_sha256": sha(self.grammar),
            "grammar_observation_id": OBS, "grammar_current_package": PKG,
            "target_label_contract": {"schema": "hepta.observed-target-labels.v1",
                "encoding": "utf8-length-prefixed-be32-sorted-node-id.v1", "observation_id": OBS,
                "package": PKG, "pairs_count": 2,
                "sha256": contract_digest("hepta.observed-target-labels.v1",
                    "utf8-length-prefixed-be32-sorted-node-id.v1", {"n7": "当前搜索", "n8": "其他字段"})},
            "app_label_contract": {"schema": "hepta.observed-app-labels.v1",
                "encoding": "utf8-length-prefixed-be32-sorted-package.v1", "observation_id": OBS,
                "package": PKG, "pairs_count": 0,
                "sha256": contract_digest("hepta.observed-app-labels.v1",
                    "utf8-length-prefixed-be32-sorted-package.v1", {})}}
        self.native = {"schema": "hepta.geniex-once.result.v1", "request_id": RUN,
            "generation_complete": True, "raw_text_utf8": True, "raw_text_truncated": False, "error": None,
            "input_sha256": {"grammar": sha(self.grammar)}}
        self.before = {"observation_id": OBS, "package": PKG, "window_id": 7,
            "window": {"metadata_status": "observed", "window_id": 7, "type": 1, "display_id": 0},
            "nodes": [{"id": "n7", "text": TEXT[:96], "editable": True, "focused": True,
                "input_text_sha256": self.capability["input_text_sha256"], "submit_available": True,
                "ime_enter": {"schema": "hepta.observed-ime-enter.v1", "observed": True, "present": True,
                    "action_label": label, "action_label_sha256": self.capability["action_label_sha256"],
                    "query_allowed": True, "reason_code": "observed_query_label"}}]}
        identity = {"task_id": TASK, "model_run_id": RUN, "observation_id": OBS, "package": PKG,
            "node_id": "n7", "window_id": 7, "display_id": 0, "background_generation": None,
            "input_text_sha256": self.capability["input_text_sha256"], "action_label": label,
            "action_label_sha256": self.capability["action_label_sha256"],
            "attempt_id": "c" * 64, "attempt_ordinal": 1}
        self.result = {**identity, "schema": "hepta.ime-submit-result.v1", "attempt_consumed": True,
            "dispatch_attempted": True, "api_accepted": True, "result": "accepted",
            "automatic_retry_allowed": False, "goal_independently_verified": False}
        self.journal = {**identity, "schema": "hepta.ime-submit-attempt.v1", "attempt_consumed": True,
            "stage": "consumed_before_call", "automatic_retry_allowed": False}
        self.receipt = {"action": self.action, "accepted": True, "dispatched": True, "stale": False,
            "model_run_id": RUN, "model_issued": True, "ime_submit": self.result, "background_session": None}
        if background:
            bg = {"mode": "background", "generation": "dddddddd-dddd-dddd-dddd-dddddddddddd", "display_id": 11,
                "allowed_packages": [PKG], "bootstrap_package": PKG,
                "bootstrap_source": "owner_selected_initial_app", "bootstrap_model_issued": False,
                "home_allowed": False, "main_display_fallback": False}
            self.before["background_session"] = copy.deepcopy(bg)
            self.data["background_session"] = copy.deepcopy(bg)
            self.before["window"]["display_id"] = 11
            self.result.update(display_id=11, background_generation=bg["generation"])
            self.journal.update(display_id=11, background_generation=bg["generation"])
            self.receipt["background_session"] = {"task_id": TASK, "generation": bg["generation"], "display_id": 11}
        self.rebind()

    def rebind(self):
        self.prompt = b"UNTRUSTED_DATA\n" + encoded(self.data) + b"\nOWNER\n" + OWNER.encode("utf-8")
        self.raw = encoded(self.action)
        self.app["prompt_sha256"] = self.native["input_sha256"]["prompt"] = sha(self.prompt)
        self.native.update(raw_text_bytes=len(self.raw), raw_text_sha256=sha(self.raw))

    def valid(self):
        return a.controller_grammar_binding_valid(self.app, self.native, self.grammar,
            {OBS: {PKG}}, self.prompt, self.raw)

    def write(self, root):
        task, run = root / "task", root / "runs" / RUN
        task.mkdir(parents=True, exist_ok=True); run.mkdir(parents=True, exist_ok=True)
        def save(path, value):
            path.write_bytes(encoded(value))
        save(task / "owner.json", {"task_id": TASK, "instruction": OWNER,
            "instruction_utf8_sha256": sha(OWNER.encode("utf-8"))})
        save(task / "step-01-before.json", self.before)
        save(task / "step-01-after.json", {"observation_id": "e" * 32, "package": PKG})
        save(task / "step-01-action.json", self.receipt)
        save(task / "step-01-model-0.json", {"run_id": RUN, "observation_id": OBS,
            "raw_text": self.raw.decode("utf-8"), "original_instruction_sha256": sha(OWNER.encode("utf-8"))})
        save(task / "ime-submit-01-attempt.json", self.journal)
        save(run / "app-receipt.json", self.app); save(run / "native-result.json", self.native)
        (run / "prompt.txt").write_bytes(self.prompt); (run / "grammar.gbnf").write_bytes(self.grammar)
        (run / "raw-text.txt").write_bytes(self.raw)


class SubmitPromptBindingTests(unittest.TestCase):
    def test_v5_exact_capability_is_bound(self):
        f = Fixture()
        self.assertTrue(f.valid())
        self.assertEqual(a.ime_submit_prompt_capability(f.data, f.action), f.capability)

    def test_v6_submit_retains_query_and_node_requirements(self):
        f = Fixture(schema=a.FIXED_INTENT_ACTION_SCHEMA)
        self.assertTrue(f.valid())
        self.assertEqual(a.ime_submit_prompt_capability(f.data, f.action), f.capability)
        for label in ("付款", "下单", "发送", "Enter"):
            self.assertFalse(Fixture(label, schema=a.FIXED_INTENT_ACTION_SCHEMA).valid())
        f.action["node_label"] = "其他字段"; f.rebind()
        self.assertFalse(f.valid())

    def test_v6_receipt_does_not_upgrade_a_v5_prompt(self):
        f = Fixture(); f.app["grammar_schema"] = a.FIXED_INTENT_ACTION_SCHEMA
        self.assertFalse(f.valid())
        f.data["action_schema"] = a.FIXED_INTENT_ACTION_SCHEMA; f.rebind()
        self.assertFalse(f.valid())  # The actual v6 producer always supplies its fixed-tool domain.

    def test_real_query_labels_only(self):
        for label in ("搜索", "搜尋", "查询", "查詢", "查找", "search", "query", "find", "ＳＥＡＲＣＨ", " Search "):
            with self.subTest(label=label):
                self.assertTrue(Fixture(label).valid())
        for label in ("Enter", "Go", "Done", "Next", "确认", "提交", "发送", "付款", "下单", "Search and pay", "\u0085search\u0085", "search\0", "", "↵", " " * 251 + "search"):
            with self.subTest(label=label):
                self.assertFalse(Fixture(label).valid())
        self.assertFalse(a.ime_query_label_allowed(None))

    def test_v3_v4_and_downgraded_prompt_cannot_accept_submit(self):
        for schema in (a.LABEL_ACTION_SCHEMA, a.APP_LABEL_ACTION_SCHEMA, "hepta.observed-action-gbnf.v1"):
            f = Fixture(); f.app["grammar_schema"] = schema
            self.assertFalse(f.valid())
            f.data["action_schema"] = schema; f.rebind()
            self.assertFalse(f.valid())

    def test_non_submit_v5_decision_keeps_existing_behavior(self):
        f = Fixture(); f.action = {"action": "wait", "observation_id": OBS, "package": PKG, "duration_ms": 100}
        f.data["screen"]["submit_actions"] = {}; f.rebind()
        self.assertTrue(f.valid())

    def test_missing_capability_or_crossed_node_pair_fails(self):
        for change in ("missing", "wrong_label", "wrong_id", "wrong_observation", "wrong_package", "late_label"):
            with self.subTest(change=change):
                f = Fixture()
                if change == "missing": del f.data["screen"]["submit_actions"]
                elif change == "wrong_label": f.action["node_label"] = "其他字段"
                elif change == "wrong_id": f.action["node_id"] = "n8"
                elif change == "wrong_observation": f.action["observation_id"] = "f" * 32
                elif change == "wrong_package": f.action["package"] = "org.example.other"
                else: f.action["node_label"] = f.action.pop("node_label")
                f.rebind(); self.assertFalse(f.valid())

    def test_focused_editable_metadata_is_required_without_type_permission(self):
        f = Fixture(); f.data["screen"]["nodes"][0][3] = "f"; f.rebind()
        self.assertTrue(f.valid())  # t is permission, not factual editability.
        for key, value in (("role", "noninteractive_text"), ("focused", False), ("focused", 1), ("enabled", False)):
            f = Fixture(); f.data["screen"]["editable_fields"][0][key] = value; f.rebind()
            self.assertFalse(f.valid())
        f = Fixture(); f.data["screen"]["nodes"][0][3] = "t"; f.rebind()
        self.assertFalse(f.valid())

    def test_capability_fields_hashes_and_source_are_closed(self):
        for key, value in (("schema", "unknown"), ("action_name", "ACTION_CLICK"), ("action_label_sha256", "0" * 64),
                           ("input_text_sha256", None), ("input_text_sha256", "1" * 63), ("action_label", None)):
            f = Fixture(); f.data["screen"]["submit_actions"]["n7"][key] = value; f.rebind()
            self.assertFalse(f.valid(), key)
        for key in Fixture().capability:
            f = Fixture(); del f.data["screen"]["submit_actions"]["n7"][key]; f.rebind()
            self.assertFalse(f.valid(), key)
        f = Fixture(); f.data["screen"]["submit_actions"]["n7"]["keycode"] = 66; f.rebind()
        self.assertFalse(f.valid())

    def test_node_domain_cannot_include_omitted_or_duplicate_targets(self):
        for kind in ("omitted", "duplicate_node", "duplicate_field", "noneditable"):
            f = Fixture()
            if kind == "omitted": f.data["screen"]["submit_actions"]["n9"] = dict(f.capability)
            elif kind == "duplicate_node": f.data["screen"]["nodes"].append(f.data["screen"]["nodes"][0])
            elif kind == "duplicate_field": f.data["screen"]["editable_fields"].append(f.data["screen"]["editable_fields"][0])
            else: f.data["screen"]["editable_fields"] = []
            f.rebind(); self.assertFalse(f.valid(), kind)

    def test_submit_cannot_add_text_keycodes_or_other_parameters(self):
        for key, value in (("text", "rewrite"), ("keycode", 66), ("ime_action_id", 3), ("action_id", 1),
                           ("display_id", 0), ("x", 10), ("y", 20), ("shell", "cmd"), ("app_label", "Search")):
            f = Fixture(); f.action[key] = value; f.rebind()
            self.assertFalse(f.valid(), key)

    def test_native_prompt_and_grammar_hashes_cannot_be_swapped(self):
        f = Fixture(); f.prompt += b" "
        self.assertFalse(f.valid())
        f = Fixture(); f.grammar += b" "
        self.assertFalse(f.valid())
        f = Fixture(); f.native["input_sha256"]["prompt"] = "0" * 64
        self.assertFalse(f.valid())


class SubmitSequenceBindingTests(unittest.TestCase):
    def run_fixture(self, fixture, mutate=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); fixture.write(root)
            if mutate is not None: mutate(root)
            return s.action_sequence(root, [{"action": "submit", "package": PKG}])

    def assert_rejected(self, fixture, mutate=None):
        result = self.run_fixture(fixture, mutate)
        self.assertFalse(result["passed"], result)
        self.assertFalse(result["evidence_complete"], result)
        return result

    def test_successful_api_call_is_effect_not_goal_proof(self):
        result = self.run_fixture(Fixture())
        self.assertTrue(result["passed"], result)
        binding = result["model_action_bindings"][0]
        self.assertTrue(binding["ime_submit_binding_valid"])
        self.assertFalse(binding["ime_submit_goal_independently_verified"])

    def test_v6_query_dispatch_keeps_exact_before_call_and_background_binding(self):
        for background in (False, True):
            f = Fixture(background=background, schema=a.FIXED_INTENT_ACTION_SCHEMA)
            result = self.run_fixture(f)
            self.assertTrue(result["passed"], result)
            self.assertFalse(result["model_action_bindings"][0]["ime_submit_goal_independently_verified"])
            f.journal["input_text_sha256"] = "0" * 64
            self.assert_rejected(f)

    def test_background_requires_same_owned_display_generation(self):
        result = self.run_fixture(Fixture(background=True))
        self.assertTrue(result["passed"], result)
        for target, key, value in (("result", "display_id", 0), ("result", "background_generation", "e" * 32),
                                   ("background", "display_id", 0), ("background", "main_display_fallback", True)):
            f = Fixture(background=True)
            if target == "result": f.result[key] = value
            else: f.before["background_session"][key] = value
            self.assert_rejected(f)
        f = Fixture(background=True)
        for value in (f.before["background_session"], f.data["background_session"], f.receipt["background_session"]):
            value["generation"] = "d" * 32
        f.result["background_generation"] = f.journal["background_generation"] = "d" * 32
        f.rebind(); self.assert_rejected(f)  # The real broker uses canonical UUID strings, not task HEX32 IDs.

    def test_raw_decision_cannot_be_replaced_by_receipt(self):
        f = Fixture(); f.receipt["action"] = {**f.action, "node_id": "n8"}
        self.assert_rejected(f)

    def test_native_prompt_must_contain_original_owner(self):
        f = Fixture(); f.prompt = f.prompt.replace(OWNER.encode(), "另一个任务".encode())
        f.native["input_sha256"]["prompt"] = f.app["prompt_sha256"] = sha(f.prompt)
        self.assert_rejected(f)

    def test_result_identity_fields_are_exact_and_typed(self):
        for key, value in (("task_id", "f" * 32), ("model_run_id", "f" * 32), ("observation_id", "f" * 32),
                           ("package", "org.example.other"), ("node_id", "n8"), ("window_id", 8),
                           ("display_id", 1), ("window_id", True), ("display_id", False),
                           ("input_text_sha256", sha(TEXT[:96].encode())), ("action_label_sha256", "0" * 64),
                           ("attempt_ordinal", True), ("attempt_ordinal", 1.0), ("attempt_id", "different")):
            f = Fixture(); f.result[key] = value
            self.assert_rejected(f)

    def test_unknown_refused_or_unconsumed_cannot_count_as_success(self):
        for key, value in (("schema", "unknown"), ("attempt_consumed", False), ("dispatch_attempted", False),
                           ("api_accepted", False), ("api_accepted", None), ("api_accepted", 1),
                           ("result", "refused"), ("result", "unknown"), ("result", "not_dispatched"),
                           ("automatic_retry_allowed", True), ("goal_independently_verified", True)):
            f = Fixture(); f.result[key] = value
            self.assert_rejected(f)
        for status in ("refused", "unknown"):
            f = Fixture(); f.receipt["accepted"] = False
            f.result.update(result=status, api_accepted=False if status == "refused" else None)
            result = self.run_fixture(f)
            self.assertFalse(result["passed"])
            self.assertEqual(result["observed_dispatched_actions"], [])

    def test_before_observation_must_confirm_actual_node_capability(self):
        for key, value in (("editable", False), ("focused", False), ("focused", 1), ("enabled", False),
                           ("password", True), ("submit_available", False), ("input_text_sha256", "0" * 64)):
            f = Fixture(); f.before["nodes"][0][key] = value
            self.assert_rejected(f)
        for key, value in (("observed", False), ("present", False), ("query_allowed", False),
                           ("action_label", "Enter"), ("action_label_sha256", "0" * 64)):
            f = Fixture(); f.before["nodes"][0]["ime_enter"][key] = value
            self.assert_rejected(f)

    def test_missing_before_node_and_unknown_window_metadata_fail(self):
        for kind in ("no_node", "duplicate_node", "unknown_window", "foreign_window", "non_app", "unknown_display"):
            f = Fixture()
            if kind == "no_node": f.before["nodes"] = []
            elif kind == "duplicate_node": f.before["nodes"].append(copy.deepcopy(f.before["nodes"][0]))
            elif kind == "unknown_window": f.before["window"]["metadata_status"] = "unknown"
            elif kind == "foreign_window": f.before["window"]["window_id"] = 8
            elif kind == "non_app": f.before["window"]["type"] = 2
            else: f.before["window"]["display_id"] = None
            self.assert_rejected(f)

    def test_missing_native_input_or_journal_fails(self):
        for relative in ("task/ime-submit-01-attempt.json", "runs/" + RUN + "/app-receipt.json",
                         "runs/" + RUN + "/prompt.txt", "runs/" + RUN + "/grammar.gbnf"):
            self.assert_rejected(Fixture(), lambda root, name=relative: (root / name).unlink())

    def test_journal_identity_cannot_be_forged_or_marked_not_consumed(self):
        for key, value in (("task_id", "f" * 32), ("model_run_id", "e" * 32), ("observation_id", "f" * 32),
                           ("input_text_sha256", "0" * 64), ("attempt_id", "other"), ("attempt_ordinal", 2),
                           ("attempt_ordinal", True), ("stage", "after_call"), ("attempt_consumed", False),
                           ("automatic_retry_allowed", True), ("action_label", "付款")):
            f = Fixture(); f.journal[key] = value
            self.assert_rejected(f)
        f = Fixture(); f.journal["dispatch_attempted"] = False
        self.assert_rejected(f)  # A before-call journal cannot claim a known dispatch result.

    def test_duplicate_consumed_input_or_attempt_cannot_qualify(self):
        for duplicate in ("input", "attempt"):
            f = Fixture()
            def mutate(root):
                other = copy.deepcopy(f.journal); other["attempt_ordinal"] = 2
                if duplicate == "input": other["attempt_id"] = "other-id"
                else: other["input_text_sha256"] = sha(b"another input")
                (root / "task/ime-submit-02-attempt.json").write_bytes(encoded(other))
            self.assert_rejected(f, mutate)

    def test_symlinked_submit_inputs_or_journal_do_not_qualify(self):
        for relative in ("task/ime-submit-01-attempt.json", "runs/" + RUN + "/prompt.txt"):
            def mutate(root, name=relative):
                original = root / name; renamed = original.with_suffix(".actual")
                original.rename(renamed); original.symlink_to(renamed.name)
            self.assert_rejected(Fixture(), mutate)


if __name__ == "__main__":
    unittest.main(verbosity=2)
