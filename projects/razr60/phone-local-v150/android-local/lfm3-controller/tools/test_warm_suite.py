"""Actual collector files -> suite effect binding; all phone/SDK data are fixtures."""
import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import phone_acceptance as a
import phone_suite as s
from test_phone_acceptance import FakeAdb, TASK, RUN, OBS
from test_warm_collection import WarmFakeAdb
from test_warm_receipts import G


def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False) + "\n")


def fixture(root):
    instruction = "打开系统设置，不修改设置。"
    fake = WarmFakeAdb(SimpleNamespace(instruction=instruction, expected_compute="npu", expected_context=4096))
    fake.damage = None; fake.request = json.dumps({"nonce": "a" * 64}).encode()
    fake.command([], label="launch-once")
    task = "files/control-tasks/" + TASK + "/"; run = "files/runs/" + RUN + "/"
    action = dict(action="open", observation_id=OBS, package="com.android.settings")
    raw = (json.dumps(action) + "\n").encode()
    prompt = ("UNTRUSTED_DATA\n" + json.dumps({"screen": {"observation_id": OBS}}) + "\nOWNER\n" + instruction).encode()
    app, native = json.loads(fake.files[run + "app-receipt.json"]), json.loads(fake.files[run + "native-result.json"])
    fake.files[run + "prompt.txt"] = prompt; fake.files[run + "system.txt"] = b"host fixture system"
    native.update(raw_text_bytes=len(raw), raw_text_sha256=a.digest(raw))
    native["input_sha256"].update(prompt=a.digest(prompt), system=a.digest(fake.files[run + "system.txt"]))
    app.update(expected_parent_pid=app["app_pid"], parent_death_guard_requested=True,
        parent_death_guard_is_cleanup_proof=False, raw_text_sha256_read=a.digest(raw),
        prompt_sha256=a.digest(prompt), grammar_current_package="com.launcher", native_receipt=copy.deepcopy(native))
    fake.files[run + "raw-text.txt"] = raw
    fake.files[run + "app-receipt.json"] = json.dumps(app).encode()
    fake.files[run + "native-result.json"] = json.dumps(native).encode()
    rows = {
        "step-01-before.json": dict(observation_id=OBS, package="com.launcher"),
        "step-01-after.json": dict(observation_id="d" * 32, package="com.android.settings"),
        "step-01-model-0.json": dict(run_id=RUN, observation_id=OBS, raw_text=raw.decode(),
            original_instruction_sha256=a.digest(instruction.encode())),
        "step-01-action.json": dict(action=action, accepted=True, dispatched=True, stale=False,
            model_run_id=RUN, model_issued=True),
    }
    fake.files.update({task + name: json.dumps(value).encode() for name, value in rows.items()})
    collected = a.collect_evidence(fake, root, TASK, instruction, set(), False, 10042)
    assert not collected["errors"] and collected["task_model_sessions_valid"]
    return {"raw": root / "runs" / RUN / "raw-text.txt", "app": root / "runs" / RUN / "app-receipt.json",
        "native": root / "runs" / RUN / "native-result.json", "terminal": root / "runs" / G / "app-session-receipt.json",
        "native_terminal": root / "runs" / G / "native-session-result.json", "final": root / "task/result.json"}


def refresh_collection_hash(root, path):
    """Keep cached positive collection flags to prove the suite rechecks contracts."""
    document = json.loads((root / "collection.json").read_bytes())
    for row in document["associated_runs"] + document["task_model_sessions"]:
        for file in row["files"]:
            if file["path"] == path.relative_to(root).as_posix():
                data = path.read_bytes(); file.update(bytes=len(data), sha256=a.digest(data))
    write_json(root / "collection.json", document)


class WarmSuiteTest(unittest.TestCase):
    def setUp(self):
        FakeAdb.native_overrides = {}; FakeAdb.app_overrides = {}
        FakeAdb.reject = False; FakeAdb.missing_native = False
        FakeAdb.corrupt_raw = False; FakeAdb.missing_offload_log = False
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.paths = fixture(self.root)

    def sequence(self):
        return s.action_sequence(self.root, [{"action": "open", "package": "com.android.settings"}])

    def denied(self):
        result = self.sequence()
        self.assertFalse(result["passed"]); self.assertFalse(result["evidence_complete"])
        self.assertFalse(result["model_action_bindings"][0]["verified"])
        return result

    def test_actual_collector_files_qualify_a_warm_dispatched_effect(self):
        result = self.sequence()
        self.assertTrue(result["passed"], result); self.assertTrue(result["evidence_complete"])
        proof = result["model_action_bindings"][0]
        self.assertTrue(proof["task_session_binding_valid"])
        self.assertEqual((proof["task_id"], proof["worker_generation"], proof["app_uid"]), (TASK, G, 10042))
        self.assertEqual(proof["app_session_receipt_sha256"], a.digest(self.paths["terminal"].read_bytes()))
        self.assertFalse(json.loads(self.paths["app"].read_bytes())["process_exit_observed"])

    def test_foreign_generation_cannot_borrow_a_valid_terminal(self):
        app, native = (json.loads(self.paths[key].read_bytes()) for key in ("app", "native"))
        app["worker_generation"] = native["worker_generation"] = "f" * 32; app["native_receipt"] = native
        for key, value in (("app", app), ("native", native)):
            write_json(self.paths[key], value); refresh_collection_hash(self.root, self.paths[key])
        self.denied()

    def test_missing_terminal_cannot_borrow_cached_collection_success(self):
        self.paths["terminal"].unlink(); self.denied()

    def test_changed_raw_or_step_model_output_is_rejected(self):
        self.paths["raw"].write_bytes(self.paths["raw"].read_bytes() + b" ")
        self.denied()

    def test_real_exit_is_required_even_with_updated_terminal_hashes(self):
        terminal = json.loads(self.paths["terminal"].read_bytes())
        terminal.update(process_exit_observed=False, exit_code=None, cleanup_known=False)
        write_json(self.paths["terminal"], terminal); refresh_collection_hash(self.root, self.paths["terminal"])
        final = json.loads(self.paths["final"].read_bytes())
        final["model_session"].update(app_receipt_sha256=a.digest(self.paths["terminal"].read_bytes()),
            process_exit_observed=False, exit_code=None)
        write_json(self.paths["final"], final)
        self.denied()

    def test_uid_and_parent_pid_must_bind_to_the_current_app(self):
        original = self.paths["app"].read_bytes()
        for key, value in (("app_uid", 10043), ("expected_parent_pid", 999)):
            app = json.loads(original); app[key] = value
            write_json(self.paths["app"], app); refresh_collection_hash(self.root, self.paths["app"])
            self.denied()

    def test_task_worker_cannot_masquerade_as_one_shot(self):
        native = json.loads(self.paths["native"].read_bytes()); native["schema"] = "hepta.geniex-once.result.v1"
        write_json(self.paths["native"], native); refresh_collection_hash(self.root, self.paths["native"])
        self.denied()

    def test_current_model_run_must_belong_to_the_collected_task(self):
        document = json.loads((self.root / "collection.json").read_bytes()); document["task_id"] = "f" * 32
        write_json(self.root / "collection.json", document); self.denied()


if __name__ == "__main__":
    unittest.main()
