#!/usr/bin/env python3
"""Host-only regression cases for the original-attempt admission hold.

Import this module and call load_suite() from tools/tests to include these in
the existing unittest workflow. Direct invocation optionally writes a new JSON
report. Fixtures exercise the actual derived entry functions and local CLI
processes; no phone/runtime job is created and no original request is replayed.
"""
import argparse
import ast
import copy
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

BASE = Path(__file__).resolve().parents[1]
ROOT_NAME = "run_component_root_once.py"
PREPARER_NAME = "prepare_native_bound_components_r6_fc33_successor02.py"


def module_from(path, name):
    module = types.ModuleType(name)
    module.__file__ = str(path)
    old_bytecode = sys.dont_write_bytecode
    try:
        exec(compile(path.read_bytes(), str(path), "exec"), module.__dict__)
    finally:
        sys.dont_write_bytecode = old_bytecode
    return module


CLI_HARNESS = r'''
import json,os,sys,types
from pathlib import Path
entry=Path(sys.argv[1]);mode=sys.argv[2]
forbidden=[]
def audit(event,args):
    blocked=(event in {'subprocess.Popen','os.system','os.posix_spawn','os.fork',
                      'socket.connect','socket.connect_ex','socket.getaddrinfo',
                      'os.mkdir','os.remove','os.rmdir','os.rename','os.link',
                      'os.symlink','os.truncate','os.kill','os.killpg'})
    if event=='open':
        flags=args[2] if len(args)>2 else 0
        blocked=bool(isinstance(flags,int) and flags & (os.O_WRONLY|os.O_RDWR|os.O_CREAT|os.O_TRUNC|os.O_APPEND))
    if blocked:
        forbidden.append(event)
        raise AssertionError('candidate attempted forbidden fixture effect: '+event)
sys.addaudithook(audit)
m=types.ModuleType('actual_candidate_entry_fixture');m.__file__=str(entry)
exec(compile(entry.read_bytes(),str(entry),'exec'),m.__dict__)
if entry.name=='run_component_root_once.py':
    argv=[str(entry),'--plan','/fixture-original-plan-intentionally-not-read.json','--plan-sha256','0'*64]
    if mode=='execute':argv+=['--execute-root-chain-once']
    expected='coordinator.main'
else:
    import hashlib
    argv=[str(entry),'--reviewed-source-sha256',hashlib.sha256(entry.read_bytes()).hexdigest(),
          '--case','NEG-01','--previous','/fixture/final04/ACTUAL-PREVIOUS-INPUT.json',
          '--previous-bytes','1','--previous-sha256','fcdf8a456f663d6963d3cd9caf231a210aad92d8f5e192a71917381d10ea10f0']
    if mode=='execute':argv+=['--create-host-plan-once']
    expected='preparer.main'
sys.argv=argv
try:
    m.main()
except BaseException as e:
    result={'exception_type':type(e).__name__,'stage':getattr(e,'stage',None),
            'decision':getattr(e,'decision',None),'forbidden_candidate_events':forbidden}
    print(json.dumps(result,sort_keys=True))
    raise SystemExit(0 if type(e).__name__=='AdmissionBlocked' and result['stage']==expected and not forbidden else 1)
raise SystemExit('entry unexpectedly returned without the original-attempt hold')
'''


class OriginalAttemptAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.guard = module_from(BASE / "original_attempt_admission.py", "guard_fixture")
        cls.derivation = module_from(BASE / "derive_guarded_sources.py", "derive_fixture")
        cls.checker = module_from(BASE / "current_check.py", "checker_fixture")

    def decision(self, document=None):
        return self.guard.evaluate(self.guard.required_register() if document is None else document)

    def assert_unknown_blocked(self, decision):
        self.assertFalse(decision["successor_execution_eligible"])
        self.assertEqual(decision["state"], "BLOCKED_ORIGINAL_ATTEMPT_UNRESOLVED")
        original = decision["known_original"]
        self.assertEqual(original["identity"], self.guard.known_identity())
        self.assertEqual(original["observation"]["original_task_outcome"], "UNKNOWN_UNCHANGED")
        self.assertIsNone(original["observation"]["original_terminal"])
        self.assertTrue(all(value is None for value in original["observation"]["effect_counts"].values()))
        self.assertFalse(original["observation"]["producer_fencing_proven"])
        self.assertIsNone(original["observation"]["cancellation_observation"]["signals_sent"])

    def assert_entry_blocked(self, stage, fn):
        with self.assertRaises(RuntimeError) as caught:
            fn()
        error = caught.exception
        self.assertEqual(type(error).__name__, "AdmissionBlocked")
        self.assertEqual(error.stage, stage)
        self.assertEqual(error.decision, self.guard.evaluate_current())
        self.assert_unknown_blocked(error.decision)
        return error

    def test_exact_register_is_valid_evidence_and_still_blocks(self):
        actual = self.guard.evaluate_current()
        self.assertTrue(actual["evidence_valid"])
        self.assertEqual(actual, self.decision())
        self.assert_unknown_blocked(actual)

    def test_known_bound02_record_cannot_be_deleted_or_duplicated(self):
        for rows in ([], [self.guard.required_register()["attempts"][0]] * 2):
            with self.subTest(records=len(rows)):
                document = self.guard.required_register()
                document["attempts"] = rows
                result = self.decision(document)
                self.assertIn("MANDATORY_BOUND02_RECORD_MISSING_OR_DUPLICATED", result["evidence_errors"])
                self.assert_unknown_blocked(result)

    def test_every_original_identity_field_is_bound(self):
        for field, value in self.guard.known_identity().items():
            with self.subTest(field=field):
                document = self.guard.required_register()
                document["attempts"][0]["identity"][field] = value + 1 if type(value) is int else value + "-changed"
                result = self.decision(document)
                self.assertIn("BOUND02_ORIGINAL_IDENTITY_DIFFERS", result["evidence_errors"])
                self.assert_unknown_blocked(result)

    def test_bound01_recovery_cannot_settle_bound02(self):
        for recovery_job in ("1a1b33a7191-fc05-813f", "1a1b3426151-fc05-8186"):
            with self.subTest(recovery_job=recovery_job):
                document = self.guard.required_register()
                row = document["attempts"][0]
                row["identity"]["job_id"] = recovery_job
                row["identity"]["nonce"] = "5f94c6a88805eefb0e2320cae5265d46"
                row["accepted_disposition"] = {"state": "EXACT_OWNED_RECOVERY_CLOSED", "terminal": True, "effects": 0}
                result = self.decision(document)
                self.assertIn("BOUND02_ORIGINAL_IDENTITY_DIFFERS", result["evidence_errors"])
                self.assertIn("NO_BOUND02_DISPOSITION_VERIFIER_IN_THIS_SOURCE", result["evidence_errors"])
                self.assert_unknown_blocked(result)

    def test_caller_terminal_and_effect_booleans_cannot_unlock(self):
        variants = [
            ("original_terminal", {"state": "succeeded", "exit_code": 0}),
            ("original_task_outcome", "confirmed_not_executed"),
            ("producer_fencing_proven", True),
            ("effect_counts", {name: 0 for name in self.guard._EFFECT_FIELDS}),
        ]
        for field, value in variants:
            with self.subTest(field=field):
                document = self.guard.required_register()
                document["attempts"][0]["observation"][field] = value
                result = self.decision(document)
                self.assertIn("ORIGINAL_UNKNOWN_OBSERVATION_WAS_REWRITTEN", result["evidence_errors"])
                self.assert_unknown_blocked(result)
        document = self.guard.required_register()
        document["known_all_dispatched_tools_confirmed_terminal"] = True
        document["execution_eligible"] = True
        result = self.decision(document)
        self.assertIn("REGISTER_SCHEMA_OR_FIELDS_DIFFER", result["evidence_errors"])
        self.assert_unknown_blocked(result)

    def test_zero_send_does_not_clear_independent_draft_pending(self):
        actual = self.guard.evaluate_current()
        draft = actual["independent_pending_drafts"][0]
        self.assertEqual(draft["send_attempt_count"], 0)
        self.assertEqual(draft["draft_restore"]["restore_attempts"], 0)
        self.assertEqual(draft["draft_restore"]["state"], "RESTORE_NOT_AUTOMATED_INPUT_OUTCOME_UNCONFIRMED")
        self.assertIsNone(draft["ui_effect_count"])
        self.assertFalse(draft["current_draft_verified"])
        document = self.guard.required_register()
        document["independent_pending_drafts"][0]["current_draft_verified"] = True
        document["independent_pending_drafts"][0]["accepted_draft_disposition"] = {"restored": True}
        result = self.decision(document)
        self.assertIn("INDEPENDENT_BOUND01_DRAFT_RECORD_DIFFERS", result["evidence_errors"])
        self.assertFalse(result["independent_pending_drafts"][0]["current_draft_verified"])
        self.assert_unknown_blocked(result)

    def test_cancel_timeout_preserves_request_and_unknown_signals(self):
        observation = self.guard.evaluate_current()["known_original"]["observation"]
        cancellation = observation["cancellation_observation"]
        self.assertEqual(cancellation["request_attempts"], 1)
        self.assertEqual(cancellation["observed_result"], "TIMEOUT_NO_CANCELLATION_RECEIPT")
        self.assertEqual(cancellation["response_original"]["sha256"], "5f0646f9deefaa026258095a3fe49ef5defc1475ef87bec6119962d1dd4fc639")
        self.assertIsNone(cancellation["signals_sent"])
        self.assertFalse(cancellation["cancellation_proven"])
        self.assertFalse(cancellation["termination_proven"])

    def test_missing_register_and_missing_worker_path_remain_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "missing-worker" / "ORIGINAL-ATTEMPTS.json"
            result = self.guard.evaluate_current(path)
        self.assertIn("KNOWN_ATTEMPT_REGISTER_UNAVAILABLE", result["evidence_errors"])
        self.assert_unknown_blocked(result)

    def test_empty_modified_and_duplicate_json_registers_fail_closed(self):
        samples = [b"", b"{}\n", b'{"attempts":[],"attempts":[]}\n',
                   self.guard.encoded(self.guard.required_register()) + b" ",
                   b'{"attempts":NaN}\n']
        with tempfile.TemporaryDirectory() as directory:
            for index, raw in enumerate(samples):
                with self.subTest(sample=index):
                    path = Path(directory) / str(index)
                    path.write_bytes(raw)
                    result = self.guard.evaluate_current(path)
                    self.assertFalse(result["evidence_valid"])
                    self.assert_unknown_blocked(result)

    def test_symlink_and_multilink_registers_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "original.json"
            path.write_bytes((BASE / "ORIGINAL-ATTEMPTS.json").read_bytes())
            alias = Path(directory) / "alias.json"
            alias.symlink_to(path)
            self.assertFalse(self.guard.evaluate_current(alias)["evidence_valid"])
            hard = Path(directory) / "hard.json"
            os.link(path, hard)
            self.assertFalse(self.guard.evaluate_current(hard)["evidence_valid"])

    def test_new_nonce_and_final04_previous_are_blocked_before_plan_reads(self):
        root = module_from(BASE / ROOT_NAME, "root_plan_fixture")
        plan = {
            "case_id": "NEG-01", "label": "root-r10-neg01-new-successor-label",
            "nonce": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            "out": "/fixture/new-output-must-not-be-created",
            "previous": {"path": "/fixture/root-r10-neg01-a1055-final04/ACTUAL-PREVIOUS-INPUT.json",
                         "bytes": 1,
                         "sha256": "fcdf8a456f663d6963d3cd9caf231a210aad92d8f5e192a71917381d10ea10f0"},
            "known_all_dispatched_tools_confirmed_terminal": True,
        }
        reads = []
        real_read = root.read

        def permitted_read(path, *args):
            reads.append(str(path))
            self.assertEqual(Path(path), BASE / "original_attempt_admission.py")
            return real_read(path, *args)

        with mock.patch.object(root, "read", side_effect=permitted_read), \
                mock.patch.object(root, "validate_current_prior", side_effect=AssertionError("old prior validation reached")) as old_prior:
            self.assert_entry_blocked("coordinator.validate_plan", lambda: root.validate_plan(self.guard.encoded(plan)))
        self.assertEqual(reads, [str(BASE / "original_attempt_admission.py")])
        old_prior.assert_not_called()

    def test_actual_root_constructor_rejects_before_output_creation(self):
        root = module_from(BASE / ROOT_NAME, "root_constructor_fixture")
        with mock.patch.object(root, "newdir", side_effect=AssertionError("output creation reached")) as newdir, \
                mock.patch.object(root, "put", side_effect=AssertionError("write reached")) as put:
            self.assert_entry_blocked("coordinator.output_reservation", lambda: root.Chain({}, b"{}"))
        newdir.assert_not_called()
        put.assert_not_called()

    def test_actual_root_run_rejects_before_lease_and_dispatch(self):
        root = module_from(BASE / ROOT_NAME, "root_dispatch_fixture")
        chain = root.Chain.__new__(root.Chain)
        with mock.patch.object(root.time, "time_ns", side_effect=AssertionError("fresh lease reached")) as lease, \
                mock.patch.object(root.Chain, "execute_process", side_effect=AssertionError("dispatch reached")) as dispatch:
            self.assert_entry_blocked("coordinator.dispatch", chain.run)
        lease.assert_not_called()
        dispatch.assert_not_called()

    def test_actual_preparer_rejects_before_context_helper(self):
        preparer = module_from(BASE / PREPARER_NAME, "preparer_context_fixture")
        with mock.patch.object(preparer, "verify_freeze", side_effect=AssertionError("helper reached")) as verify:
            self.assert_entry_blocked("preparer.selected_context", lambda: preparer.selected_context(None, None, None))
        verify.assert_not_called()

    def test_actual_preparer_rejects_before_nonce_reservation_and_write(self):
        preparer = module_from(BASE / PREPARER_NAME, "preparer_create_fixture")
        helper = mock.Mock()
        observer = mock.Mock()
        with mock.patch.object(preparer.secrets, "token_hex", side_effect=AssertionError("nonce generation reached")) as nonce:
            self.assert_entry_blocked("preparer.before_nonce_and_reservation",
                                      lambda: preparer.create(helper, observer, {}, {}, b"", {}))
        nonce.assert_not_called()
        self.assertEqual(helper.mock_calls, [])
        self.assertEqual(observer.mock_calls, [])

    def test_actual_cli_preview_and_execute_have_no_candidate_side_effects(self):
        with tempfile.TemporaryDirectory() as directory:
            harness = Path(directory) / "entry_fixture.py"
            harness.write_text(CLI_HARNESS)
            for name in (ROOT_NAME, PREPARER_NAME):
                for mode in ("preview", "execute"):
                    with self.subTest(entry=name, mode=mode):
                        result = subprocess.run([sys.executable, "-I", "-B", str(harness), str(BASE / name), mode],
                                                capture_output=True, text=True, timeout=15, check=False)
                        self.assertEqual(result.returncode, 0, result.stderr)
                        original = json.loads(result.stdout)
                        self.assertEqual(original["exception_type"], "AdmissionBlocked")
                        self.assertEqual(original["forbidden_candidate_events"], [])
                        self.assert_unknown_blocked(original["decision"])

    def test_sidecar_source_pin_tampering_is_rejected_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            (target / ROOT_NAME).write_bytes((BASE / ROOT_NAME).read_bytes())
            (target / "original_attempt_admission.py").write_bytes((BASE / "original_attempt_admission.py").read_bytes() + b"\n")
            root = module_from(target / ROOT_NAME, "tampered_sidecar_fixture")
            with mock.patch.object(root, "newdir", side_effect=AssertionError("output creation reached")) as newdir:
                with self.assertRaisesRegex(ValueError, "exact reviewed original-attempt guard source required"):
                    root.Chain({}, b"{}")
            newdir.assert_not_called()

    def test_current_checker_calls_same_pinned_decision_and_stays_nonzero(self):
        current = {"execution_eligible": False, "original_attempt_admission": self.guard.evaluate_current()}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "CURRENT.json"
            path.write_bytes(self.guard.encoded(current))
            result, status = self.checker.check_current(path)
            self.assertEqual(status, 2)
            self.assertTrue(result["current_document_valid"])
            self.assertEqual(result["original_attempt_admission"], self.guard.evaluate_current())
            cli = subprocess.run([sys.executable, "-I", "-B", str(BASE / "current_check.py"), "--current", str(path)],
                                 capture_output=True, text=True, timeout=15, check=False)
            self.assertEqual(cli.returncode, 2, cli.stderr)
            self.assertEqual(json.loads(cli.stdout), result)

    def test_current_cannot_drop_identity_claim_pass_or_mutate_unknown_counts(self):
        variants = []
        for flag in (True, "false", 0, None):
            variants.append({"execution_eligible": flag, "original_attempt_admission": self.guard.evaluate_current()})
        variants.append({"execution_eligible": False})
        changed = {"execution_eligible": False, "original_attempt_admission": self.guard.evaluate_current()}
        changed["original_attempt_admission"]["known_original"]["observation"]["effect_counts"]["phone_calls"] = 0
        variants.append(changed)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "CURRENT.json"
            for index, document in enumerate(variants):
                with self.subTest(variant=index):
                    path.write_bytes(self.guard.encoded(document))
                    result, status = self.checker.check_current(path)
                    self.assertEqual(status, 3)
                    self.assertFalse(result["execution_eligible"])
                    self.assert_unknown_blocked(result["original_attempt_admission"])

    def test_current_register_missing_cannot_silently_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory)
            for name in ("original_attempt_admission.py", "current_check.py"):
                (target / name).write_bytes((BASE / name).read_bytes())
            current = target / "CURRENT.json"
            current.write_bytes(self.guard.encoded({"execution_eligible": False,
                                                    "original_attempt_admission": self.guard.evaluate_current()}))
            checker = module_from(target / "current_check.py", "missing_register_checker")
            result, status = checker.check_current(current)
        self.assertEqual(status, 3)
        self.assertIn("ADMISSION_REGISTER_INVALID_OR_MISSING", result["errors"])
        self.assert_unknown_blocked(result["original_attempt_admission"])

    def test_derivation_is_exact_and_original_prior_gate_is_byte_identical(self):
        inputs = {name: (BASE / ("reference" if name in (ROOT_NAME, PREPARER_NAME) else "") / name).read_bytes()
                  for name in self.derivation.INPUTS}
        outputs, checks = self.derivation.derive(inputs)
        for name, raw in outputs.items():
            self.assertEqual(raw, (BASE / name).read_bytes())
        self.assertTrue(checks["coordinator"]["existing_program_ast_unchanged_after_removing_guard"])
        self.assertTrue(checks["preparer"]["existing_program_ast_unchanged_after_removing_guard"])
        self.assertTrue(checks["validate_current_prior"]["byte_identical"])
        self.assertEqual(checks["validate_current_prior"]["sha256"], "e61d28c825c20cc92da82f2be29fbd64aafbd94221a90e28cb27076b30e973f3")

    def test_derivation_rejects_other_preparer_or_modified_baseline(self):
        inputs = {name: (BASE / ("reference" if name in (ROOT_NAME, PREPARER_NAME) else "") / name).read_bytes()
                  for name in self.derivation.INPUTS}
        for name in inputs:
            with self.subTest(input=name):
                altered = dict(inputs)
                altered[name] += b"\n"
                with self.assertRaisesRegex(ValueError, "unreviewed baseline/input"):
                    self.derivation.derive(altered)

    def test_guard_refuses_unknown_override_arguments(self):
        with self.assertRaises(TypeError):
            self.guard.require_successor_admission(stage="test", force=True)
        with self.assertRaises(TypeError):
            self.guard.require_successor_admission(stage="test", known_all_dispatched_tools_confirmed_terminal=True)


def load_suite():
    return unittest.defaultTestLoader.loadTestsFromTestCase(OriginalAttemptAdmissionTests)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    started = time.monotonic()
    result = unittest.TextTestRunner(verbosity=2).run(load_suite())
    report = {
        "schema": "hepta.r6.original-attempt-guard-host-tests.v1",
        "state": "PASS" if result.wasSuccessful() else "FAIL",
        "test_count": result.testsRun,
        "failures": [{"test": str(test), "traceback": detail} for test, detail in result.failures],
        "errors": [{"test": str(test), "traceback": detail} for test, detail in result.errors],
        "skipped": [{"test": str(test), "reason": reason} for test, reason in result.skipped],
        "elapsed_seconds": round(time.monotonic() - started, 6),
        "test_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "qualification": "HOST_SOURCE_ENTRY_REGRESSION_ONLY",
        "remote_runtime_jobs_created": 0,
        "phone_calls": 0,
        "original_bound02_outcome": "UNKNOWN_UNCHANGED",
        "live_guard_enforcement_proven": False,
    }
    if args.report:
        raw = (json.dumps(report, sort_keys=True, indent=2) + "\n").encode()
        fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
