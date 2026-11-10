"""Exercise the actual collector with synthetic app files; never calls ADB."""
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import types
import unittest
from unittest.mock import patch
from test_phone_acceptance import FakeAdb, TASK, RUN, OBS, m, xml_view
from test_warm_receipts import fixture, G


class WarmFakeAdb(FakeAdb):
    damage = None

    def command(self, command, **kwargs):
        result = super().command(command, **kwargs)
        if kwargs.get("label") != "launch-once":
            return result
        root = "files/runs/" + RUN + "/"
        app, native = json.loads(self.files[root + "app-receipt.json"]), json.loads(self.files[root + "native-result.json"])
        terminal, native_terminal, _, final, pairs, _, _ = fixture()
        app.update(pairs[0][0]); native.update(pairs[0][1])
        app.update(task_id=TASK, run_id=RUN, app_uid=10042)
        native.update(task_id=TASK, request_id=RUN)
        prompt = ("UNTRUSTED_DATA\n" + json.dumps({"screen": {"observation_id": OBS}})
                  + "\nOWNER\n" + self.instruction).encode()
        self.files[root + "prompt.txt"] = prompt
        app.update(prompt_sha256=m.digest(prompt), raw_text_sha256_read=m.digest(self.files[root + "raw-text.txt"]))
        native["input_sha256"].update(prompt=m.digest(prompt), system=None)
        app["native_receipt"] = copy.deepcopy(native)
        terminal.update(task_id=TASK, app_uid=10042, requests_sent=1, requests_accepted=1)
        native_terminal.update(task_id=TASK, requests_received=1, requests_completed=1, model_reset_count=1)
        terminal["native_session_receipt"] = copy.deepcopy(native_terminal)
        summary = final["model_session"]; summary["task_id"] = TASK
        if self.damage == "request_claims_exit":
            app["process_exit_observed"] = True; app["exit_code"] = 0
        if self.damage == "late_uncommitted":
            app["request_committed"] = False
        if self.damage == "missing_exit":
            terminal["process_exit_observed"] = False; terminal["exit_code"] = None
        if self.damage == "wrong_generation":
            native["worker_generation"] = "f" * 32; app["native_receipt"] = copy.deepcopy(native)
        self.files[root + "app-receipt.json"] = json.dumps(app).encode()
        self.files[root + "native-result.json"] = json.dumps(native).encode()
        generation = "files/runs/" + G + "/"
        terminal_bytes = json.dumps(terminal).encode()
        self.files[generation + "app-session-receipt.json"] = terminal_bytes
        self.files[generation + "native-session-result.json"] = json.dumps(native_terminal).encode()
        self.files[generation + "stderr.log"] = self.files.pop(root + "stderr.log")
        summary["app_receipt_sha256"] = m.digest(terminal_bytes)
        final_path = "files/control-tasks/" + TASK + "/result.json"
        task_final = json.loads(self.files[final_path]); task_final["model_session"] = summary
        self.files[final_path] = json.dumps(task_final).encode()
        if self.damage == "missing_terminal":
            del self.files[generation + "app-session-receipt.json"]
        if self.damage == "missing_log":
            del self.files[generation + "stderr.log"]
        if self.damage == "corrupt_output":
            self.files[root + "raw-text.txt"] = b"wrong"
        return result


class WarmCollectionTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        WarmFakeAdb.damage = None
        FakeAdb.native_overrides = {}; FakeAdb.app_overrides = {}
        FakeAdb.reject = False; FakeAdb.missing_native = False; FakeAdb.corrupt_raw = False; FakeAdb.missing_offload_log = False

    def run_case(self, name):
        args = types.SimpleNamespace(case_id=name, instruction="计算 37 加 58。", evidence_root=Path(self.temp.name),
            adb="/not/executed", adb_host="127.0.0.1", adb_port=12345, serial="FAKE", command_timeout=1,
            timeout=1, poll=.01, stop_grace=0, setup_home=False, include_screenshots=False,
            expected_package="com.example.calculator", expected_visible_text=["95"], text_match="exact",
            expected_compute="npu", expected_context=4096)
        with patch.object(m, "Adb", WarmFakeAdb), patch.object(m, "capture_ui", return_value=xml_view()), contextlib.redirect_stdout(io.StringIO()):
            code = m.run_task(args)
        return code, json.loads((args.evidence_root / name / "acceptance.json").read_bytes())

    def test_collector_fetches_exact_generation_terminal_and_shared_log(self):
        code, report = self.run_case("valid")
        self.assertEqual(code, 0, report)
        self.assertTrue(report["native_receipts_verified"])
        self.assertTrue(report["collection"]["task_model_sessions_valid"])
        row = report["collection"]["associated_runs"][0]
        self.assertFalse(row["process_exit_observed"])
        self.assertIsNone(row["exit_code"])
        self.assertEqual(row["accelerator_log_scope"], "same_owned_task_generation")
        self.assertTrue((Path(self.temp.name) / "valid/runs" / G / "app-session-receipt.json").is_file())

    def test_visible_goal_cannot_override_missing_exit_or_bad_request_evidence(self):
        for damage in ("request_claims_exit", "late_uncommitted", "missing_exit", "wrong_generation",
                       "missing_terminal", "missing_log", "corrupt_output"):
            WarmFakeAdb.damage = damage
            code, report = self.run_case(damage)
            self.assertEqual(code, 3, (damage, report))
            self.assertFalse(report["native_receipts_verified"], damage)


if __name__ == "__main__":
    unittest.main()
