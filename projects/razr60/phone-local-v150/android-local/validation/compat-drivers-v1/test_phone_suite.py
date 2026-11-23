#!/usr/bin/env python3
"""Host-only regressions for the suite ledger and dispatch evidence gates."""
import copy
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import phone_acceptance as a
import phone_suite as s


def plan():
    case = {"case_id": "settings-01", "instruction": "打开系统设置，不修改设置。",
            "expected_package": "com.android.settings", "expected_visible_text": [], "text_match": "exact",
            "required_actions": [{"action": "open", "package": "com.android.settings"}],
            "setup_home": True, "timeout_seconds": 540}
    return {"schema": s.SCHEMA, "suite_id": "navigation-r3", "candidate": {
        "package": a.PACKAGE, "apk_sha256": "1"*64, "version_code": 3, "model_sha256": a.MODEL_SHA256,
        "compute": "npu", "context_tokens": 4096, "threads": 4}, "cases": [case]}


class FakeAdb:
    calls = []
    wrong_sha = False
    permission = False
    active = False
    config = None
    interrupted_latch = False
    files_readable = True
    latch_output = b""

    def __init__(self, *args, **kwargs):
        pass

    def command(self, command, **kwargs):
        self.calls.append(command)
        if command[:2] == ["pm", "path"]:
            return 0, b"package:/data/app/com.example-unique/base.apk\n"
        if command[0] == "sha256sum":
            return 0, (("2" if self.wrong_sha else "1")*64 + "  " + command[1] + "\n").encode()
        if command[:2] == ["dumpsys", "package"]:
            return 0, ("versionCode=3 minSdk=30\n" + ("android.permission.INTERNET\n" if self.permission else "")).encode()
        if command == ["run-as", a.PACKAGE, "sh", "-c", s.INTERRUPTED_LATCH_PROBE]:
            code = 41 if not self.files_readable else 0 if self.interrupted_latch else 40
            return code, self.latch_output
        raise AssertionError("unexpected phone command " + repr(command))

    def app_json(self, relative, **kwargs):
        self.calls.append(["read", relative])
        if relative.endswith("runtime-config.json"):
            return self.config
        if relative.endswith("control-session.json"):
            return {"running": self.active, "pending": False, "cleanup_known": True}
        return None


class SuiteTests(unittest.TestCase):
    def setUp(self):
        FakeAdb.calls = []
        FakeAdb.wrong_sha = FakeAdb.permission = FakeAdb.active = False
        FakeAdb.config = None
        FakeAdb.interrupted_latch = False
        FakeAdb.files_readable = True
        FakeAdb.latch_output = b""

    def test_valid_plan_never_contacts_phone(self):
        with patch.object(a, "Adb", side_effect=AssertionError("phone access")):
            self.assertTrue(s.validate_plan(plan())["runnable"])

    def test_unbuilt_candidate_draft_not_runnable(self):
        p = plan(); p["candidate"]["apk_sha256"] = None
        self.assertFalse(s.validate_plan(p)["runnable"])
        with self.assertRaises(a.DriverError): s.validate_plan(p, True)

    def test_rejects_duplicate_attempt_identity(self):
        p = plan(); p["cases"].append(copy.deepcopy(p["cases"][0]))
        with self.assertRaises(a.DriverError): s.validate_plan(p)

    def test_boolean_does_not_count_as_numeric_configuration(self):
        p = plan(); p["candidate"]["threads"] = True
        with self.assertRaises(a.DriverError): s.validate_plan(p)

    def test_rejects_model_substitution(self):
        p = plan(); p["candidate"]["model_sha256"] = "0"*64
        with self.assertRaises(a.DriverError): s.validate_plan(p)

    def test_requires_real_effect_and_final_predicate(self):
        for field, value in [("required_actions", []), ("expected_package", None)]:
            p = plan(); p["cases"][0][field] = value
            with self.subTest(field=field), self.assertRaises(a.DriverError): s.validate_plan(p)

    def test_refuses_arbitrary_command_fields(self):
        p = plan(); p["cases"][0]["shell"] = "anything"
        with self.assertRaises(a.DriverError): s.validate_plan(p)

    def test_preflight_matches_actual_apk_and_default_config(self):
        r = s.preflight(FakeAdb(), plan()["candidate"])
        self.assertFalse(r["device_offline_proven"])
        self.assertFalse(r["inference_has_run"])
        self.assertFalse(r["interrupted_session_latch_present"])
        self.assertTrue(all(c[0] in ("pm", "sha256sum", "dumpsys", "read", "run-as") for c in FakeAdb.calls))

    def test_preflight_rejects_changed_binary(self):
        FakeAdb.wrong_sha = True
        with self.assertRaises(a.DriverError): s.preflight(FakeAdb(), plan()["candidate"])

    def test_preflight_rejects_network_permission(self):
        FakeAdb.permission = True
        with self.assertRaises(a.DriverError): s.preflight(FakeAdb(), plan()["candidate"])

    def test_preflight_refuses_active_task(self):
        FakeAdb.active = True
        with self.assertRaises(a.DriverError): s.preflight(FakeAdb(), plan()["candidate"])

    def test_preflight_does_not_change_compute(self):
        p = plan(); p["candidate"]["compute"] = "gpu"
        with self.assertRaises(a.DriverError): s.preflight(FakeAdb(), p["candidate"])
        self.assertFalse(any("write" in c for c in FakeAdb.calls))

    def test_preflight_blocks_interrupted_latch_despite_clean_session(self):
        for kind in ("ordinary", "empty", "corrupt", "dangling_symlink", "directory"):
            FakeAdb.interrupted_latch = kind
            with self.subTest(kind=kind), self.assertRaisesRegex(a.DriverError,"latch exists"):
                s.preflight(FakeAdb(), plan()["candidate"])
        self.assertNotIn(["read", "files/control-session.interrupted.json"],FakeAdb.calls)

    def test_preflight_requires_distinct_verified_latch_absence(self):
        FakeAdb.files_readable = False
        with self.assertRaisesRegex(a.DriverError,"absence could not be established"):
            s.preflight(FakeAdb(), plan()["candidate"])
        FakeAdb.files_readable = True; FakeAdb.latch_output = b"unexpected"
        with self.assertRaisesRegex(a.DriverError,"absence could not be established"):
            s.preflight(FakeAdb(), plan()["candidate"])

    def test_fixed_latch_shell_probe_distinguishes_absence_from_any_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            def probe():
                result=subprocess.run(["sh","-c",s.INTERRUPTED_LATCH_PROBE],cwd=root,capture_output=True,timeout=5)
                self.assertEqual(result.stdout,b"");self.assertEqual(result.stderr,b"")
                return result.returncode
            self.assertEqual(probe(),41)  # Missing app files directory is not a missing latch.
            (root/"files").mkdir();self.assertEqual(probe(),40)
            latch=root/"files/control-session.interrupted.json"
            for payload in (b"",b"not valid JSON",b'{}'):
                latch.write_bytes(payload);self.assertEqual(probe(),0)
                self.assertEqual(latch.read_bytes(),payload)  # The probe never modifies or parses it.
                latch.unlink()
            latch.symlink_to("missing-target");self.assertEqual(probe(),0);latch.unlink()
            latch.mkdir();self.assertEqual(probe(),0)

    def write_action(self, root, number, action, dispatched=True, after=True):
        task = root/"task"; task.mkdir(exist_ok=True)
        prefix = task/("step-%02d" % number)
        observation = ("%032x" % number)
        data = {"action": action, "package": "com.android.settings", "observation_id": observation}
        if action in ("click","type","scroll"):data["node_id"]="n1"
        if action=="type":data["text"]="中文😀\nsecond line"
        if action=="scroll":data["direction"]="down"
        if action=="find_app":data.update(query="settings",offset=0)
        run_id="%032x" % (1000+number)
        instruction=plan()["cases"][0]["instruction"]
        owner_sha=a.digest(instruction.encode())
        a.write_json(task/"owner.json",{"instruction":instruction,"instruction_utf8_sha256":owner_sha})
        before_path=Path(str(prefix)+"-before.json")
        action_path=Path(str(prefix)+"-action.json")
        model_path=Path(str(prefix)+"-model-0.json")
        a.write_json(before_path,{"observation_id":observation,"package":"com.launcher" if action=="open" else "com.android.settings"})
        a.write_json(action_path,{"action":data,"accepted":True,"dispatched":dispatched,"stale":False,
                                 "model_run_id":run_id,"model_issued":True})
        if after:
            a.write_json(Path(str(prefix)+"-after.json"),{"observation_id":"%032x" % (100+number),"package":"com.launcher" if action=="home" else "com.android.settings"})
        run_directory=root/"runs"/run_id;run_directory.mkdir(parents=True,exist_ok=True)
        paths={"action":action_path,"before":before_path,"model":model_path,
               "raw":run_directory/"raw-text.txt","native":run_directory/"native-result.json"}
        a.write_json(model_path,{"run_id":run_id,"observation_id":observation,"original_instruction_sha256":owner_sha})
        a.write_json(paths["native"],{"schema":"hepta.geniex-once.result.v1","request_id":run_id,
                "generation_complete":True,"raw_text_utf8":True,"raw_text_truncated":False,"error":None})
        self.replace_raw(paths,json.dumps(data,ensure_ascii=False).encode()+b"\n")
        return paths

    def replace_raw(self, paths, raw):
        paths["raw"].write_bytes(raw)
        model=json.loads(paths["model"].read_text());model["raw_text"]=raw.decode("utf-8")
        a.write_json(paths["model"],model)
        native=json.loads(paths["native"].read_text());native.update(raw_text_bytes=len(raw),raw_text_sha256=a.digest(raw))
        a.write_json(paths["native"],native)

    def assert_unverified_action(self, root):
        result=s.action_sequence(root,[{"action":"open"}])
        self.assertFalse(result["evidence_complete"])
        self.assertFalse(result["passed"])
        self.assertTrue(result["missing_evidence"])
        return result

    def test_effect_binding_reports_exact_run_and_native_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=self.write_action(root,1,"open")
            result=s.action_sequence(root,[{"action":"open"}])
            self.assertTrue(result["passed"]);self.assertTrue(result["evidence_complete"])
            binding=result["model_action_bindings"][0]
            self.assertTrue(binding["verified"])
            self.assertEqual(binding["model_run_id"],"%032x" % 1001)
            self.assertEqual(binding["raw_text_sha256"],a.digest(paths["raw"].read_bytes()))

    def test_each_effect_requires_model_issued_true_and_exact_run_id(self):
        for key,value in [("model_issued",False),("model_issued",1),("model_issued",None),
                          ("model_run_id",None),("model_run_id","../foreign"),("model_run_id","f"*32)]:
            with self.subTest(key=key,value=value), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);paths=self.write_action(root,1,"open")
                receipt=json.loads(paths["action"].read_text());receipt[key]=value;a.write_json(paths["action"],receipt)
                self.assert_unverified_action(root)

    def test_same_step_model_receipt_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=self.write_action(root,1,"open")
            paths["model"].rename(paths["model"].with_name("step-02-model-0.json"))
            self.assert_unverified_action(root)

    def test_duplicate_matching_model_attempts_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=self.write_action(root,1,"open")
            paths["model"].with_name("step-01-model-1.json").write_bytes(paths["model"].read_bytes())
            self.assert_unverified_action(root)

    def test_corrected_second_attempt_binds_by_run_id(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=self.write_action(root,1,"open")
            paths["model"].rename(paths["model"].with_name("step-01-model-1.json"))
            a.write_json(paths["model"],{"run_id":"f"*32,"raw_text":"rejected first output"})
            result=s.action_sequence(root,[{"action":"open"}])
            self.assertTrue(result["passed"])
            self.assertTrue(result["model_action_bindings"][0]["step_model_receipt"].endswith("-model-1.json"))

    def test_model_receipt_and_native_raw_must_match_exact_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=self.write_action(root,1,"open")
            model=json.loads(paths["model"].read_text());model["raw_text"]+=" "
            a.write_json(paths["model"],model);self.assert_unverified_action(root)

    def test_action_cannot_substitute_a_different_generated_decision(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=self.write_action(root,1,"open")
            receipt=json.loads(paths["action"].read_text());receipt["action"]["package"]="com.other.application"
            a.write_json(paths["action"],receipt);self.assert_unverified_action(root)

    def test_native_receipt_must_bind_this_complete_output(self):
        changes=[("request_id","f"*32),("raw_text_sha256","0"*64),("raw_text_bytes",1),
                 ("generation_complete",False),("raw_text_truncated",True),("raw_text_utf8",False),("error","incomplete")]
        for key,value in changes:
            with self.subTest(key=key), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);paths=self.write_action(root,1,"open")
                native=json.loads(paths["native"].read_text());native[key]=value
                a.write_json(paths["native"],native);self.assert_unverified_action(root)

    def test_missing_or_malformed_model_evidence_is_unverified_not_a_phone_failure(self):
        for field in ("model","raw","native"):
            with self.subTest(missing=field), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);paths=self.write_action(root,1,"open");paths[field].unlink()
                self.assert_unverified_action(root)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=self.write_action(root,1,"open")
            raw=paths["raw"].read_bytes().rstrip()[:-1]+b',"action":"open"}'
            self.replace_raw(paths,raw);self.assert_unverified_action(root)

    def test_step_observation_and_original_owner_are_bound(self):
        for key,value in [("observation_id","f"*32),("original_instruction_sha256","f"*64)]:
            with self.subTest(key=key),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);paths=self.write_action(root,1,"open")
                model=json.loads(paths["model"].read_text());model[key]=value
                a.write_json(paths["model"],model);self.assert_unverified_action(root)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.write_action(root,1,"open")
            result=s.action_sequence(root,[{"action":"open"}],"f"*64)
            self.assertFalse(result["evidence_complete"])

    def test_semantic_json_binding_preserves_unicode_and_only_omits_empty_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);paths=self.write_action(root,1,"type")
            raw_action=json.loads(paths["raw"].read_bytes());raw_action["reason"]=""
            self.replace_raw(paths,json.dumps(raw_action,ensure_ascii=True,indent=2).encode())
            self.assertTrue(s.action_sequence(root,[{"action":"type"}])["passed"])
            raw_action["reason"]="nonempty reason cannot disappear"
            self.replace_raw(paths,json.dumps(raw_action,ensure_ascii=False).encode())
            self.assertFalse(s.action_sequence(root,[{"action":"type"}])["evidence_complete"])

    def test_one_model_output_cannot_be_counted_for_two_action_steps(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);first=self.write_action(root,1,"open");second=self.write_action(root,2,"open")
            second["action"].write_bytes(first["action"].read_bytes())
            second["before"].write_bytes(first["before"].read_bytes())
            second["model"].write_bytes(first["model"].read_bytes())
            result=s.action_sequence(root,[{"action":"open"},{"action":"open"}])
            self.assertFalse(result["passed"]);self.assertFalse(result["evidence_complete"])

    def test_read_only_discovery_cannot_claim_dispatched_ui_effect(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);self.write_action(root,1,"find_app",dispatched=True)
            self.assert_unverified_action(root)

    def test_corrupt_action_or_observation_is_unverified_evidence(self):
        for field in ("action","before"):
            with self.subTest(field=field),tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp);paths=self.write_action(root,1,"open")
                paths[field].write_text("not JSON");self.assert_unverified_action(root)

    def test_missing_native_binding_preserves_known_launch_and_underlying_failure(self):
        for original,expected in (("pass","unverified"),("fail","fail"),("unverified","unverified")):
            with self.subTest(original=original),tempfile.TemporaryDirectory() as tmp:
                p=plan();root=Path(tmp)/"new"
                args=SimpleNamespace(output=root,adb="/mock/adb",adb_host="127.0.0.1",adb_port=5061,serial="TEST_ONLY",command_timeout=20)
                def execute(case):
                    directory=case.evidence_root/case.case_id;directory.mkdir(parents=True)
                    paths=self.write_action(directory,1,"open");paths["raw"].unlink()
                    a.write_json(directory/"acceptance.json",{"case_id":case.case_id,
                        "instruction_sha256":a.digest(case.instruction.encode()),"launch_attempt_count":1,
                        "verdict":original,"cleanup_unknown":False,"task_id":"a"*32})
                    return 0 if original=="pass" else 2
                with patch.object(s,"require_existing_adb_server",return_value={}),patch.object(a,"Adb",FakeAdb),patch.object(a,"run_task",side_effect=execute) as submitted,contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(s.run_suite(args,p,json.dumps(p).encode()),2)
                result=json.loads((root/"suite-result.json").read_text())
                self.assertEqual(submitted.call_count,1)
                self.assertEqual(result["counts"][expected],1)
                self.assertEqual(result["counts"]["unknown"],0)
                self.assertEqual(result["actual_launches"],1)
                self.assertEqual(result["cases"][0]["original_case_verdict"],original)

    def test_fully_bound_effect_preserves_underlying_case_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=plan();root=Path(tmp)/"new"
            args=SimpleNamespace(output=root,adb="/mock/adb",adb_host="127.0.0.1",adb_port=5061,serial="TEST_ONLY",command_timeout=20)
            def execute(case):
                directory=case.evidence_root/case.case_id;directory.mkdir(parents=True)
                self.write_action(directory,1,"open")
                a.write_json(directory/"acceptance.json",{"case_id":case.case_id,
                    "instruction_sha256":a.digest(case.instruction.encode()),"launch_attempt_count":1,
                    "verdict":"pass","cleanup_unknown":False,"task_id":"a"*32})
                return 0
            with patch.object(s,"require_existing_adb_server",return_value={}),patch.object(a,"Adb",FakeAdb),patch.object(a,"run_task",side_effect=execute),contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(s.run_suite(args,p,json.dumps(p).encode()),0)
            result=json.loads((root/"suite-result.json").read_text())
            self.assertEqual(result["counts"]["pass"],1)
            self.assertEqual(result["actual_launches"],1)
            self.assertEqual(result["full_phone_acceptance"],"not_assessed")

    def test_required_action_is_dispatched_not_only_generated(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.write_action(root, 1, "open", dispatched=False)
            self.assertFalse(s.action_sequence(root, plan()["cases"][0]["required_actions"])["passed"])

    def test_action_order_is_required(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self.write_action(root, 1, "open"); self.write_action(root, 2, "home"); self.write_action(root, 3, "open")
            expected = [{"action": "open"}, {"action": "home"}, {"action": "open"}]
            self.assertTrue(s.action_sequence(root, expected)["passed"])
            self.assertFalse(s.action_sequence(root, [{"action":"home"},{"action":"open"},{"action":"home"}])["passed"])

    def test_missing_observation_is_unverified_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp); self.write_action(root, 1, "open", after=False)
            self.assertFalse(s.action_sequence(root, [{"action":"open"}])["evidence_complete"])

    def test_no_action_alone_cannot_qualify(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertFalse(s.action_sequence(Path(tmp), [{"action":"open"}])["passed"])

    def test_original_failure_survives_partial_suite(self):
        r = s.summarize({"cases":[{"verdict":"fail","launch_attempt_count":1},{"verdict":"not_run","launch_attempt_count":0}]})
        self.assertEqual(r["suite_verdict"], "fail")
        self.assertEqual(r["completion_status"], "incomplete")
        self.assertEqual(r["planned_attempts"], 2)

    def test_unknown_launch_is_not_zero_launches(self):
        r = s.summarize({"cases":[{"verdict":"unknown","launch_attempt_count":None},{"verdict":"not_run","launch_attempt_count":0}]})
        self.assertIsNone(r["actual_launches"])
        self.assertEqual(r["unknown_submission_outcomes"], 1)

    def test_navigational_pass_is_not_full_phone_acceptance(self):
        r = s.summarize({"cases":[{"verdict":"pass","launch_attempt_count":1}]})
        self.assertEqual(r["suite_verdict"], "pass")
        self.assertEqual(r["full_phone_acceptance"], "not_assessed")

    def test_existing_directory_refused_before_device_contact(self):
        with tempfile.TemporaryDirectory() as tmp, patch.object(a, "Adb", side_effect=AssertionError("phone")):
            with self.assertRaises(FileExistsError): s.run_suite(SimpleNamespace(output=Path(tmp)), plan(), b"{}")

    def test_uncertain_submission_halts_without_replay(self):
        p = plan(); second = copy.deepcopy(p["cases"][0]); second["case_id"] = "settings-02"; p["cases"].append(second)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)/"new"
            args = SimpleNamespace(output=root, adb="/mock/adb", adb_host="127.0.0.1", adb_port=5061, serial="TEST_ONLY", command_timeout=20)
            with patch.object(s, "require_existing_adb_server", return_value={}) as existing, patch.object(a, "Adb", FakeAdb), patch.object(a, "run_task", side_effect=KeyboardInterrupt()) as execute, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(s.run_suite(args, p, json.dumps(p).encode()), 2)
            r = json.loads((root/"suite-result.json").read_text())
            self.assertEqual(execute.call_count, 1)
            self.assertEqual(existing.call_count, 2)
            self.assertEqual(r["counts"]["unknown"], 1)
            self.assertEqual(r["counts"]["not_run"], 1)
            self.assertIsNone(r["actual_launches"])

    def test_server_identity_failure_prevents_phone_submission(self):
        p = plan()
        with tempfile.TemporaryDirectory() as tmp:
            args = SimpleNamespace(output=Path(tmp)/"new", adb="/mock/adb", adb_host="127.0.0.1", adb_port=5061, serial="TEST_ONLY", command_timeout=20)
            with patch.object(s, "require_existing_adb_server", side_effect=a.DriverError("existing server unavailable")), patch.object(a, "Adb", side_effect=AssertionError("phone command")), patch.object(a, "run_task") as execute, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(s.run_suite(args, p, json.dumps(p).encode()), 2)
            execute.assert_not_called()
            r = json.loads((args.output/"suite-result.json").read_text())
            self.assertEqual(r["actual_launches"], 0)
            self.assertEqual(r["counts"]["not_run"], 1)

    def test_interrupted_latch_prevents_submission_without_clearing_it(self):
        p=plan();FakeAdb.interrupted_latch=True
        with tempfile.TemporaryDirectory() as tmp:
            args=SimpleNamespace(output=Path(tmp)/"new",adb="/mock/adb",adb_host="127.0.0.1",adb_port=5061,serial="TEST_ONLY",command_timeout=20)
            with patch.object(s,"require_existing_adb_server",return_value={}),patch.object(a,"Adb",FakeAdb),patch.object(a,"run_task") as execute,contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(s.run_suite(args,p,json.dumps(p).encode()),2)
            execute.assert_not_called()
            result=json.loads((args.output/"suite-result.json").read_text())
            self.assertEqual(result["actual_launches"],0)
            self.assertEqual(result["counts"]["not_run"],1)
            self.assertTrue(FakeAdb.interrupted_latch)


if __name__ == "__main__":
    unittest.main()
