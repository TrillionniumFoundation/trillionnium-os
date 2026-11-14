"""v6 protocol/effect regressions using synthetic IO and retained failed-task bytes.

No ADB, Android calls, model inference, or phone qualification is performed.
The retained v47 task remains failed; its first fixed-tool projection is reused
only to check compatibility with actual production serialization.
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

V6 = "hepta.observed-action-gbnf.v6-fixed-intents"
OBS, TASK, RUN = "0" * 32, "a" * 32, "b" * 32
CURRENT = "org.example.launcher"
OWNER = "新建本轮测试便签，不分享或发送。"
GENERATION = "dddddddd-dddd-dddd-dddd-dddddddddddd"
REQUEST = "eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee"


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def pair_digest(schema, encoding, pairs):
    raw = bytearray()
    def field(text):
        value = text.encode("utf-8")
        raw.extend(struct.pack(">I", len(value))); raw.extend(value)
    for text in (schema, encoding, OBS, CURRENT):
        field(text)
    raw.extend(struct.pack(">I", len(pairs)))
    for key, label in sorted(pairs.items()):
        field(key); field(label)
    return sha(raw)


class Fixture:
    def __init__(self, action="notes.create", background=False, raw_label=None, projected_label=None):
        if action == "notes.create":
            package, component, parameter, outcome, label = ("com.motorola.stylus",
                "com.motorola.stylus/com.motorola.stylus.note.text.TextNoteActivity",
                "text", "draft_opened", "Moto 笔记")
        else:
            package, component, parameter, outcome, label = ("com.zui.browser",
                "com.zui.browser/com.lenovo.browser.BrowserActivity",
                "query", "search_opened", "浏览器")
        if raw_label is not None:
            label = raw_label
        projected = label if projected_label is None else projected_label
        self.package = package
        self.grammar = b'root ::= "synthetic metadata fixture; grammar execution tested separately"\n'
        self.capability = {"action": action, "app_label": projected, "package": package, "parameter": parameter,
            "source": "installed_fixed_intent_adapter", "requested_outcome": outcome,
            "max_code_points": 1024, "max_utf8_bytes": 4096}
        self.action = {"reason": "使用当前已观察的固定本地入口", "action": action, "observation_id": OBS,
            "app_label": projected, "package": package, parameter: "本轮正文\n保留原文😀"}
        self.data = {"action_schema": V6, "apps": [["org.example.settings", "设置"]],
            "open_allowed_packages": ["org.example.settings"], "fixed_intent_tools": [self.capability],
            "screen": {"observation_id": OBS, "package": CURRENT, "nodes": []}}
        self.app = {"run_id": RUN, "app_uid": 10051, "grammar_schema": V6, "grammar_sha256": sha(self.grammar),
            "grammar_observation_id": OBS, "grammar_current_package": CURRENT,
            "target_label_contract": {"schema": a.LABEL_SCHEMA, "encoding": a.LABEL_ENCODING,
                "observation_id": OBS, "package": CURRENT, "pairs_count": 0,
                "sha256": pair_digest(a.LABEL_SCHEMA, a.LABEL_ENCODING, {})},
            "app_label_contract": {"schema": a.APP_LABEL_SCHEMA, "encoding": a.APP_LABEL_ENCODING,
                "observation_id": OBS, "package": CURRENT, "pairs_count": 1,
                "sha256": pair_digest(a.APP_LABEL_SCHEMA, a.APP_LABEL_ENCODING, {"org.example.settings": "设置"})}}
        self.native = {"schema": "hepta.geniex-once.result.v1", "request_id": RUN,
            "generation_complete": True, "raw_text_utf8": True, "raw_text_truncated": False,
            "error": None, "input_sha256": {"grammar": sha(self.grammar)}}
        self.before = {"observation_id": OBS, "package": CURRENT, "window_id": 7,
            "window": {"metadata_status": "observed", "window_id": 7, "type": 1, "display_id": 0}, "nodes": []}
        self.target = {"source": "installed_package_manager", "action": action, "package": package,
            "component": component, "target_uid": 10382, "app_label": label, "exported": True,
            "activity_enabled": True, "application_enabled": True, "declared_intent_filter_matched": True,
            "required_permission": None, "ordinary_caller_permission_checked": True}
        payload_sha = sha(self.action[parameter].encode("utf-8"))
        attempt_id = sha((TASK + "|1|" + action + "|" + payload_sha).encode("utf-8"))
        identity = {"task_id": TASK, "model_run_id": RUN, "observation_id": OBS,
            "source_package": CURRENT, "source_window_id": 7, "display_id": 0,
            "background_generation": None, "target": self.target, "action": action,
            "payload_sha256": payload_sha, "attempt_id": attempt_id, "attempt_ordinal": 1,
            "attempt_consumed": True, "automatic_retry_allowed": False}
        self.result = {**copy.deepcopy(identity), "schema": "hepta.fixed-intent-result.v1",
            "dispatch_attempted": True, "api_accepted": True, "result": "launch_accepted",
            "requested_outcome": outcome, "goal_independently_verified": False,
            "saved_or_search_results_verified": False}
        self.journal = {**copy.deepcopy(identity), "schema": "hepta.fixed-intent-attempt.v1",
            "stage": "consumed_before_call"}
        self.receipt = {"action": self.action, "accepted": True, "dispatched": True, "stale": False,
            "model_issued": True, "model_run_id": RUN, "fixed_intent": self.result, "background_session": None}
        if background:
            bg = {"mode": "background", "generation": GENERATION, "display_id": 11,
                "allowed_packages": [CURRENT, package], "bootstrap_package": CURRENT,
                "bootstrap_source": "owner_selected_initial_app", "bootstrap_model_issued": False,
                "home_allowed": False, "main_display_fallback": False}
            self.data["background_session"] = copy.deepcopy(bg)
            self.before["background_session"] = copy.deepcopy(bg)
            self.before["window"]["display_id"] = 11
            self.result.update(display_id=11, background_generation=GENERATION)
            self.journal.update(display_id=11, background_generation=GENERATION)
            self.receipt["background_session"] = {"task_id": TASK, "app_uid": 10051,
                "generation": GENERATION, "display_id": 11}
            proof = {"schema": "hepta.background-fixed-intent.v1", "request_id": REQUEST,
                "generation": GENERATION, "display_id": 11, "action": action, "attempt_id": attempt_id,
                "payload_sha256": payload_sha, "target": copy.deepcopy(self.target), "ordinary_caller_uid": 10051,
                "resolved_type": "text/plain" if action == "notes.create" else None,
                "attempt_consumed": True, "goal_independently_verified": False}
            self.result["broker_response"] = {"version": 1, "request_id": REQUEST, "generation": GENERATION,
                "ok": True, "state": "ACTIVE", "display_id": 11, "dispatched": True,
                "display_name": "hepta-bg-" + GENERATION, "operation": action, "fixed_intent": proof}
        self.rebind()

    def rebind(self):
        self.prompt = b"UNTRUSTED_DATA\n" + encoded(self.data) + b"\nOWNER\n" + OWNER.encode("utf-8")
        self.raw = encoded(self.action)
        self.app["prompt_sha256"] = self.native["input_sha256"]["prompt"] = sha(self.prompt)
        self.native.update(raw_text_bytes=len(self.raw), raw_text_sha256=sha(self.raw))

    def valid(self):
        return a.controller_grammar_binding_valid(self.app, self.native, self.grammar,
            {OBS: {CURRENT}}, self.prompt, self.raw)

    def set_attempt_ordinal(self, ordinal):
        attempt_id = sha((TASK + "|" + str(ordinal) + "|" + self.action["action"]
            + "|" + self.result["payload_sha256"]).encode("utf-8"))
        for value in (self.result, self.journal):
            value.update(attempt_ordinal=ordinal, attempt_id=attempt_id)
        if "broker_response" in self.result:
            self.result["broker_response"]["fixed_intent"]["attempt_id"] = attempt_id

    def write(self, root):
        task, run = root / "task", root / "runs" / RUN
        task.mkdir(parents=True); run.mkdir(parents=True)
        def save(path, value):
            path.write_bytes(encoded(value))
        save(task / "owner.json", {"task_id": TASK, "instruction": OWNER,
            "instruction_utf8_sha256": sha(OWNER.encode("utf-8"))})
        save(task / "step-01-before.json", self.before)
        save(task / "step-01-after.json", {"observation_id": "f" * 32, "package": self.package})
        save(task / "step-01-action.json", self.receipt)
        save(task / "step-01-model-0.json", {"run_id": RUN, "observation_id": OBS,
            "original_instruction_sha256": sha(OWNER.encode("utf-8")), "raw_text": self.raw.decode("utf-8")})
        save(task / ("fixed-intent-%02d-attempt.json" % self.journal["attempt_ordinal"]), self.journal)
        save(run / "app-receipt.json", self.app); save(run / "native-result.json", self.native)
        (run / "prompt.txt").write_bytes(self.prompt)
        (run / "grammar.gbnf").write_bytes(self.grammar)
        (run / "raw-text.txt").write_bytes(self.raw)


class FixedPromptTests(unittest.TestCase):
    def test_both_closed_tools_use_their_own_prompt_pairs_not_open_pairs(self):
        for name in ("notes.create", "web.search"):
            f = Fixture(name)
            self.assertTrue(f.valid())
            self.assertEqual(a.fixed_intent_prompt_capability(f.data, f.action), f.capability)
            self.assertNotIn(f.package, f.data["open_allowed_packages"])

    def test_retained_failed_task_has_real_v6_fixed_tool_projection(self):
        path = Path(__file__).resolve().parents[1] / "tests/notes-task-phase/fixtures/v47-notes-scope-trace.json"
        archive = json.loads(path.read_text())
        self.assertTrue(archive["recorded_task_failed"])
        for name in ("step-01-prompt.txt", "step-01-action.json"):
            entry = archive["files"][name]
            raw = entry["raw_utf8"].encode("utf-8")
            self.assertEqual(len(raw), entry["bytes"])
            self.assertEqual(sha(raw), entry["sha256"])
        prompt = archive["files"]["step-01-prompt.txt"]["raw_utf8"]
        data = json.loads(prompt[len("UNTRUSTED_DATA\n"):].split("\nOWNER\n", 1)[0])
        action = json.loads(archive["files"]["step-01-action.json"]["raw_utf8"])["action"]
        self.assertEqual(data["action_schema"], V6)
        self.assertEqual(a.fixed_intent_prompt_capability(data, action)["action"], "notes.create")

    def test_v6_retains_open_and_empty_fixed_domain_semantics(self):
        f = Fixture()
        f.action = {"action": "open", "observation_id": OBS, "app_label": "设置", "package": "org.example.settings"}
        f.data["fixed_intent_tools"] = []; f.rebind()
        self.assertTrue(f.valid())
        f.action["app_label"] = "Moto 笔记"; f.rebind()
        self.assertFalse(f.valid())
        f.action = {"action": "wait", "observation_id": OBS, "package": CURRENT, "duration_ms": 100}
        f.rebind(); self.assertTrue(f.valid())
        f.action["app_label"] = "设置"; f.rebind()
        self.assertFalse(f.valid())
        del f.action["app_label"]; f.action["action"] = "arbitrary.tool"; f.rebind()
        self.assertFalse(f.valid())

    def test_schema_only_upgrade_or_downgrade_cannot_qualify(self):
        for schema in (a.IME_SUBMIT_ACTION_SCHEMA, a.APP_LABEL_ACTION_SCHEMA, a.LABEL_ACTION_SCHEMA, "unknown"):
            f = Fixture(); f.app["grammar_schema"] = schema
            self.assertFalse(f.valid())
            f.data["action_schema"] = schema; f.rebind()
            self.assertFalse(f.valid())

    def test_crossed_label_package_or_payload_field_and_extra_authority_rejected(self):
        for key, value in (("app_label", "设置"), ("package", "com.zui.browser"),
                ("observation_id", "c" * 32), ("query", "wrong parameter"),
                ("title", "not a tool parameter"), ("component", "arbitrary.component"),
                ("uri", "https://example.test"), ("display_id", 0), ("text", "")):
            f = Fixture(); f.action[key] = value; f.rebind()
            self.assertFalse(f.valid(), key)
        f = Fixture(); f.action["app_label"] = f.action.pop("app_label"); f.rebind()
        self.assertFalse(f.valid())
        f = Fixture(); del f.action["app_label"]; f.rebind()
        self.assertFalse(f.valid())

    def test_missing_duplicate_or_forged_prompt_capability_rejected(self):
        for change in ("missing", "duplicate", "omitted", "unknown", "package", "source", "parameter", "outcome", "limit"):
            f = Fixture()
            if change == "missing": del f.data["fixed_intent_tools"]
            elif change == "duplicate": f.data["fixed_intent_tools"].append(copy.deepcopy(f.capability))
            elif change == "omitted": f.data["fixed_intent_tools"] = []
            elif change == "unknown": f.capability["action"] = "arbitrary.tool"
            elif change == "package": f.capability["package"] = CURRENT; f.action["package"] = CURRENT
            elif change == "source": f.capability["source"] = "model_selected"
            elif change == "parameter": f.capability["parameter"] = "title"
            elif change == "outcome": f.capability["requested_outcome"] = "saved"
            else: f.capability["max_code_points"] = True
            f.rebind(); self.assertFalse(f.valid(), change)

    def test_payload_bounds_and_literal_unicode(self):
        for payload in ("x" * 1024, "😀" * 1024, "\t正文\r\n", "\u0085"):
            f = Fixture(); f.action["text"] = payload; f.rebind()
            self.assertTrue(f.valid(), repr(payload[:10]))
        for payload in ("x" * 1025, "😀" * 1025, " ", "\t\n\r\u00a0\u3000", "x\0y"):
            f = Fixture(); f.action["text"] = payload; f.rebind()
            self.assertFalse(f.valid())
        f = Fixture(); f.action["text"] = "\ud800"
        self.assertIsNone(a.fixed_intent_prompt_capability(f.data, f.action))

    def test_native_input_and_label_digest_tampering_stays_rejected(self):
        f = Fixture(); f.prompt += b" "
        self.assertFalse(f.valid())
        f = Fixture(); f.grammar += b" "
        self.assertFalse(f.valid())
        f = Fixture(); f.app["app_label_contract"]["sha256"] = "0" * 64
        self.assertFalse(f.valid())


class FixedSequenceTests(unittest.TestCase):
    def run_fixture(self, f, mutate=None):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); f.write(root)
            if mutate:
                mutate(root)
            return s.action_sequence(root, [{"action": f.action["action"], "package": f.package}])

    def rejected(self, f, mutate=None):
        result = self.run_fixture(f, mutate)
        self.assertFalse(result["passed"], result)
        self.assertFalse(result["evidence_complete"], result)

    def test_foreground_and_background_launches_prove_effect_only(self):
        for action in ("notes.create", "web.search"):
            for background in (False, True):
                f = Fixture(action, background)
                result = self.run_fixture(f)
                self.assertTrue(result["passed"], result)
                binding = result["model_action_bindings"][0]
                self.assertTrue(binding["fixed_intent_binding_valid"])
                self.assertFalse(binding["fixed_intent_goal_independently_verified"])
                self.assertFalse(binding["fixed_intent_saved_or_search_results_verified"])

    def test_full_installed_label_must_project_to_the_native_label_exactly(self):
        raw = "长" * 47 + "😀尾部"
        f = Fixture(raw_label=raw, projected_label="长" * 47 + "…")
        self.assertTrue(self.run_fixture(f)["passed"])
        f.result["target"]["app_label"] = "另一应用"
        self.rejected(f)

    def test_payload_result_and_owner_identity_cannot_be_borrowed(self):
        for key, value in (("task_id", "f" * 32), ("model_run_id", "f" * 32),
                ("observation_id", "f" * 32), ("source_package", f"{CURRENT}.other"),
                ("source_window_id", True), ("display_id", False), ("payload_sha256", "0" * 64),
                ("attempt_ordinal", True), ("attempt_ordinal", 1.0), ("attempt_id", "0" * 64),
                ("requested_outcome", "saved"), ("goal_independently_verified", True),
                ("saved_or_search_results_verified", True), ("automatic_retry_allowed", True),
                ("api_accepted", 1), ("result", "unknown")):
            f = Fixture(); f.result[key] = value
            self.rejected(f)
        f = Fixture(); f.action["text"] += " changed"; f.rebind()
        self.rejected(f)

    def test_installed_target_identity_flags_and_component_remain_closed(self):
        for key, value in (("package", "com.zui.browser"), ("component", "com.motorola.stylus/Other"),
                ("target_uid", True), ("target_uid", 2000), ("app_label", "浏览器"),
                ("exported", False), ("activity_enabled", False), ("application_enabled", False),
                ("declared_intent_filter_matched", False), ("ordinary_caller_permission_checked", False),
                ("source", "model"), ("required_permission", "")):
            f = Fixture()
            f.result["target"][key] = value; f.journal["target"][key] = value
            self.rejected(f)

    def test_durable_journal_is_mandatory_and_cannot_reuse_a_tool(self):
        f = Fixture()
        self.rejected(f, lambda root: (root / "task/fixed-intent-01-attempt.json").unlink())
        for key, value in (("model_run_id", "c" * 32), ("stage", "after_call"),
                ("attempt_consumed", False), ("automatic_retry_allowed", True)):
            f = Fixture(); f.journal[key] = value
            self.rejected(f)
        def duplicate(root):
            journal = copy.deepcopy(f.journal)
            journal["attempt_ordinal"] = 2
            journal["attempt_id"] = sha((TASK + "|2|" + journal["action"] + "|" + journal["payload_sha256"]).encode())
            (root / "task/fixed-intent-02-attempt.json").write_bytes(encoded(journal))
        f = Fixture(); self.rejected(f, duplicate)

    def test_second_consumed_journal_cannot_hide_missing_first_attempt(self):
        for background in (False, True):
            with self.subTest(background=background):
                f = Fixture(background=background); f.set_attempt_ordinal(2)
                self.rejected(f)

    def test_two_distinct_tools_with_contiguous_ordinals_are_valid(self):
        for action, earlier in (("notes.create", "web.search"), ("web.search", "notes.create")):
            for background in (False, True):
                with self.subTest(action=action, background=background):
                    f = Fixture(action, background); f.set_attempt_ordinal(2)
                    prior = Fixture(earlier, background)
                    prior.journal.update(model_run_id="c" * 32, observation_id="d" * 32)
                    if background:
                        for value in (f.data, f.before):
                            value["background_session"]["allowed_packages"].append(prior.package)
                        f.rebind()
                    def add_first(root):
                        (root / "task/fixed-intent-01-attempt.json").write_bytes(encoded(prior.journal))
                    self.assertTrue(self.run_fixture(f, add_first)["passed"])

    def test_skipped_or_repeated_consumed_ordinals_are_rejected(self):
        for ordinal, filename in ((3, "fixed-intent-03-attempt.json"),
                (1, "fixed-intent-02-attempt.json")):
            with self.subTest(ordinal=ordinal, filename=filename):
                f, other = Fixture(), Fixture("web.search")
                other.set_attempt_ordinal(ordinal)
                def add_other(root):
                    (root / "task" / filename).write_bytes(encoded(other.journal))
                self.rejected(f, add_other)

    def test_background_receipt_cannot_use_foreground_or_other_caller(self):
        for key, value in (("display_id", 0), ("generation", "cccccccc-cccc-cccc-cccc-cccccccccccc"),
                ("operation", "web.search"), ("dispatched", False), ("ok", False), ("state", "RELEASED")):
            f = Fixture(background=True); f.result["broker_response"][key] = value
            self.rejected(f)
        for key, value in (("ordinary_caller_uid", 2000), ("resolved_type", None),
                ("attempt_id", "f" * 64), ("payload_sha256", "f" * 64), ("attempt_consumed", False)):
            f = Fixture(background=True); f.result["broker_response"]["fixed_intent"][key] = value
            self.rejected(f)
        f = Fixture(background=True); del f.result["broker_response"]
        self.rejected(f)
        f = Fixture(background=True); f.result["broker_response"]["fixed_intent"]["target"]["target_uid"] = 10382.0
        self.rejected(f)
        f = Fixture(); f.result["broker_response"] = {}
        self.rejected(f)

    def test_current_display_target_and_native_decision_are_not_replaceable(self):
        f = Fixture(background=True); f.before["background_session"]["main_display_fallback"] = True
        self.rejected(f)
        f = Fixture(background=True); f.data["background_session"]["allowed_packages"] = [CURRENT]; f.rebind()
        self.rejected(f)
        f = Fixture(); f.receipt["action"] = {**f.action, "text": "替换正文"}
        self.rejected(f)
        f = Fixture(); f.prompt = f.prompt.replace(OWNER.encode(), "另一个任务".encode())
        f.app["prompt_sha256"] = f.native["input_sha256"]["prompt"] = sha(f.prompt)
        self.rejected(f)


if __name__ == "__main__":
    unittest.main(verbosity=2)
