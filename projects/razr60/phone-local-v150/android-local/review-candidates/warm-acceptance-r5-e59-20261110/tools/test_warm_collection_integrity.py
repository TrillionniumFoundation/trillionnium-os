"""Run the real collector against adversarial multi-request files; no ADB/network."""
import contextlib
import copy
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

if os.environ.get("HEPTA_WARM_ACCEPTANCE_SOURCE"):
    sys.path.insert(0, str(Path(os.environ["HEPTA_WARM_ACCEPTANCE_SOURCE"]) / "tools"))
from test_phone_acceptance import FakeAdb, TASK, RUN, OBS, m, xml_view
from test_warm_collection import WarmFakeAdb
from test_warm_receipts import G

SECOND = "0" * 32  # Collection order must not be mistaken for protocol order.


class EvidenceAdb(WarmFakeAdb):
    scenario = None
    damage = None

    def __init__(self, args, evidence=None):
        super().__init__(args, evidence)
        self.final_reads = 0

    def list_children(self, path, directories=False):
        if directories and path == "files/runs":
            return sorted({key[len(path) + 1:].split("/", 1)[0]
                           for key in self.files if key.startswith(path + "/")})
        return super().list_children(path, directories)

    def write_request(self, run_id, app, native):
        root = "files/runs/" + run_id + "/"
        app["native_receipt"] = copy.deepcopy(native)
        self.files[root + "app-receipt.json"] = json.dumps(app).encode()
        self.files[root + "native-result.json"] = json.dumps(native).encode()

    def update_terminal(self, count):
        root = "files/runs/" + G + "/"
        app = json.loads(self.files[root + "app-session-receipt.json"])
        native = json.loads(self.files[root + "native-session-result.json"])
        app.update(requests_sent=count, requests_accepted=count)
        native.update(requests_received=count, requests_completed=count, model_reset_count=count)
        app["native_session_receipt"] = copy.deepcopy(native)
        data = json.dumps(app).encode()
        self.files[root + "app-session-receipt.json"] = data
        self.files[root + "native-session-result.json"] = json.dumps(native).encode()
        path = "files/control-tasks/" + TASK + "/result.json"
        final = json.loads(self.files[path])
        final["model_session"]["app_receipt_sha256"] = m.digest(data)
        self.files[path] = json.dumps(final).encode()

    def command(self, command, **kwargs):
        result = super().command(command, **kwargs)
        if kwargs.get("label") != "launch-once":
            return result
        root = "files/runs/" + RUN + "/"
        app = json.loads(self.files[root + "app-receipt.json"])
        native = json.loads(self.files[root + "native-result.json"])
        prompt = ("UNTRUSTED_DATA\n" + json.dumps({"screen": {"observation_id": OBS}})
                  + "\nOWNER\n" + self.instruction).encode()
        system = b"offline fixture system"
        self.files[root + "prompt.txt"], self.files[root + "system.txt"] = prompt, system
        app.update(prompt_sha256=m.digest(prompt), raw_text_sha256_read=m.digest(self.files[root + "raw-text.txt"]))
        native["input_sha256"].update(prompt=m.digest(prompt), system=m.digest(system))
        self.write_request(RUN, app, native)

        damaged_schema = self.scenario is not None and self.scenario.startswith("hidden_bad_")
        if self.scenario in {"two_requests", "hidden_uncommitted", "missing_sequence", "duplicate_sequence", "unrelated_receipt"} or damaged_schema:
            second = "files/runs/" + SECOND + "/"
            for name in ("prompt.txt", "system.txt", "grammar.gbnf", "raw-text.txt"):
                self.files[second + name] = self.files[root + name]
            next_app, next_native = copy.deepcopy(app), copy.deepcopy(native)
            sequence = 3 if self.scenario == "missing_sequence" else 1 if self.scenario == "duplicate_sequence" else 2
            next_app.update(run_id=SECOND, request_sequence=sequence, worker_started_this_request=sequence == 1)
            next_native.update(request_id=SECOND, request_sequence=sequence,
                               model_reset_count=sequence, model_hash_performed_this_request=sequence == 1)
            if self.scenario in {"hidden_uncommitted", "unrelated_receipt"} or damaged_schema:
                # A receipt that belongs to this task cannot be silently omitted
                # just because its prompt or step-model publication is unavailable.
                next_app.update(request_committed=False, inference_completed=False, status="native_failed")
                del self.files[second + "prompt.txt"]
            else:
                self.update_terminal(2)
            self.write_request(SECOND, next_app, next_native)
            if damaged_schema:
                origin, schema_kind, binding = self.scenario[len("hidden_bad_"):].split("_")
                record = next_app if origin == "app" else next_native
                if schema_kind == "missing":
                    record.pop("schema")
                else:
                    record["schema"] = ("unknown.schema" if schema_kind == "unknown" else
                        "hepta.local-model.receipt.v2" if origin == "app" else "hepta.geniex-once.result.v1")
                if binding == "generation":
                    record["task_id"] = "f" * 32
                else:
                    record["worker_generation"] = "e" * 32
                retained = "app-receipt.json" if origin == "app" else "native-result.json"
                removed = "native-result.json" if origin == "app" else "app-receipt.json"
                self.files[second + retained] = json.dumps(record).encode()
                del self.files[second + removed]
            elif self.scenario == "unrelated_receipt":
                next_app.update(schema="hepta.local-model.receipt.v2", task_id="f" * 32, worker_generation="e" * 32)
                self.files[second + "app-receipt.json"] = json.dumps(next_app).encode()
                del self.files[second + "native-result.json"]

        if self.scenario == "no_requests":
            for path in list(self.files):
                if path.startswith(root):
                    del self.files[path]
        elif self.scenario == "schema_downgrade":
            app.update(schema="hepta.local-model.receipt.v2", process_exit_observed=True, exit_code=0)
            native["schema"] = "hepta.geniex-once.result.v1"
            self.write_request(RUN, app, native)
            self.files[root + "stderr.log"] = self.files["files/runs/" + G + "/stderr.log"]
        elif self.scenario == "prompt_changed":
            self.files[root + "prompt.txt"] = prompt + b" changed owner"
        elif self.scenario == "system_changed":
            self.files[root + "system.txt"] = b"different system"
        elif self.scenario == "app_raw_hash_changed":
            app["raw_text_sha256_read"] = "f" * 64
            self.write_request(RUN, app, native)
        elif self.scenario == "foreign_log":
            data = self.files.pop("files/runs/" + G + "/stderr.log")
            self.files["files/runs/" + "f" * 32 + "/stderr.log"] = data
        return result

    def app_bytes(self, path, optional=False):
        data = super().app_bytes(path, optional)
        if data is not None and path == "files/control-tasks/" + TASK + "/result.json":
            self.final_reads += 1
            if self.scenario in {"terminal_changed", "terminal_type_changed"} and self.final_reads >= 3:
                changed = json.loads(data)
                if self.scenario == "terminal_changed":
                    changed["status"] = "partial"
                else:
                    changed["external_model"] = 0  # False == 0 in Python, unlike JSON types.
                return json.dumps(changed).encode()
        return data


class WarmCollectionIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        EvidenceAdb.scenario = None
        WarmFakeAdb.damage = None
        FakeAdb.native_overrides = {}; FakeAdb.app_overrides = {}
        FakeAdb.reject = False; FakeAdb.missing_native = False
        FakeAdb.corrupt_raw = False; FakeAdb.missing_offload_log = False

    def run_case(self, scenario):
        EvidenceAdb.scenario = scenario
        args = types.SimpleNamespace(case_id=scenario, instruction="计算 37 加 58。", evidence_root=Path(self.temp.name),
            adb="/never/executed", adb_host="127.0.0.1", adb_port=12345, serial="FAKE", command_timeout=1,
            timeout=1, poll=.01, stop_grace=0, setup_home=False, include_screenshots=False,
            expected_package="com.example.calculator", expected_visible_text=["95"], text_match="exact",
            expected_compute="npu", expected_context=4096)
        with patch.object(m, "Adb", EvidenceAdb), patch.object(m, "capture_ui", return_value=xml_view()), contextlib.redirect_stdout(io.StringIO()):
            code = m.run_task(args)
        return code, json.loads((args.evidence_root / scenario / "acceptance.json").read_bytes())

    def test_two_requests_one_exit_with_reverse_filename_order(self):
        code, report = self.run_case("two_requests")
        self.assertEqual(code, 0, report)
        rows = report["collection"]["associated_runs"]
        self.assertEqual([row["request_sequence"] for row in rows], [2, 1])
        self.assertTrue(all(row["process_exit_observed"] is False for row in rows))
        self.assertTrue(report["collection"]["task_model_sessions_valid"])

    def test_terminal_and_log_are_collected_even_if_all_request_receipts_are_lost(self):
        code, report = self.run_case("no_requests")
        self.assertEqual(code, 3, report)
        self.assertFalse(report["native_receipts_verified"])
        evidence = Path(self.temp.name) / "no_requests/runs" / G
        self.assertTrue((evidence / "app-session-receipt.json").is_file())
        self.assertTrue((evidence / "native-session-result.json").is_file())
        self.assertTrue((evidence / "stderr.log").is_file())
        self.assertFalse(report["collection"]["task_model_sessions_valid"])

    def test_unjournaled_incomplete_owned_request_is_not_ignored(self):
        code, report = self.run_case("hidden_uncommitted")
        self.assertEqual(code, 3, report)
        self.assertFalse(report["native_receipts_verified"])
        self.assertEqual({row["run_id"] for row in report["collection"]["associated_runs"]}, {RUN, SECOND})

    def test_hidden_owned_receipt_is_discovered_before_schema_validation(self):
        for origin in ("app", "native"):
            for schema_kind in ("unknown", "old", "missing"):
                for binding in ("task", "generation"):
                    scenario = "hidden_bad_" + "_".join((origin, schema_kind, binding))
                    with self.subTest(scenario=scenario):
                        code, report = self.run_case(scenario)
                        self.assertEqual(code, 3, report)
                        self.assertFalse(report["native_receipts_verified"])
                        rows = report["collection"]["associated_runs"]
                        self.assertEqual({row["run_id"] for row in rows}, {RUN, SECOND})
                        self.assertEqual(next(row for row in rows if row["run_id"] == SECOND)["association"],
                                         "task_or_generation_receipt")

    def test_unrelated_old_schema_receipt_does_not_contaminate_this_task(self):
        code, report = self.run_case("unrelated_receipt")
        self.assertEqual(code, 0, report)
        self.assertEqual([row["run_id"] for row in report["collection"]["associated_runs"]], [RUN])

    def test_warm_terminal_cannot_be_qualified_as_oneshot(self):
        code, report = self.run_case("schema_downgrade")
        self.assertEqual(code, 3, report)
        self.assertFalse(report["native_receipts_verified"])

    def test_changed_terminal_cannot_reuse_earlier_ui_success(self):
        for scenario in ("terminal_changed", "terminal_type_changed"):
            with self.subTest(scenario=scenario):
                code, report = self.run_case(scenario)
                self.assertEqual(code, 3, report)
                self.assertFalse(report["native_receipts_verified"])

    def test_prompt_system_and_app_output_hashes_are_bound(self):
        for scenario in ("prompt_changed", "system_changed", "app_raw_hash_changed"):
            with self.subTest(scenario=scenario):
                code, report = self.run_case(scenario)
                self.assertEqual(code, 3, report)
                self.assertFalse(report["native_receipts_verified"])

    def test_sequence_gaps_duplicates_and_foreign_offload_log_fail(self):
        for scenario in ("missing_sequence", "duplicate_sequence", "foreign_log"):
            with self.subTest(scenario=scenario):
                code, report = self.run_case(scenario)
                self.assertEqual(code, 3, report)
                self.assertFalse(report["native_receipts_verified"])


if __name__ == "__main__":
    unittest.main()
