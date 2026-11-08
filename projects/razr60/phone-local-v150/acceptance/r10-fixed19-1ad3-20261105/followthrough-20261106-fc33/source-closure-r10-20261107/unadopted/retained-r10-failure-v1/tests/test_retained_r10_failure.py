"""Fail-closed parsing and exact-original relationship tests.

Real retained-byte tests require --fixture and are explicitly skipped in CI
when private originals are absent. Portable fixtures are labeled as synthetic.
"""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import unittest


BASE = Path(__file__).resolve().parents[1]
FIXTURE = None
CASES = []


def load():
    source = (BASE / "candidate/retained_r10_failure.py").read_bytes()
    path = BASE / "candidate/bound_loader.py"
    spec = importlib.util.spec_from_file_location("r10_failure_test_bound_loader", path)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    return loader, loader.load(source), source


def encoded(value):
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, allow_nan=False) + "\n").encode()


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.loader, self.module, self.source = load()
        self.expectation = (BASE / "EXPECTED-ORIGINALS.json").read_bytes()

    def rejects(self, name, callback):
        with self.subTest(name=name):
            with self.assertRaises((ValueError, UnicodeError, json.JSONDecodeError)):
                callback()
        CASES.append(name)

    def test_json_has_no_ambiguous_or_nonfinite_values(self):
        self.assertEqual(self.module.strict(b'{"ns":1794087438591201340}')["ns"], 1794087438591201340)
        for label, raw in (("duplicate", b'{"a":1,"a":2}'), ("NaN", b'NaN'), ("Infinity", b'Infinity'),
                           ("negative-Infinity", b'-Infinity'), ("overflow-float", b'1e9999'),
                           ("utf8", b'"\xff"'), ("truncated", b'{"a":'), ("two-values", b'{}{}')):
            self.rejects("json-" + label, lambda raw=raw: self.module.strict(raw))

    def test_canonical_paths(self):
        self.assertEqual(str(self.module.canonical_path('/retained/a.json', True)), '/retained/a.json')
        self.assertEqual(str(self.module.canonical_path('originals/a.json', False)), 'originals/a.json')
        for path, absolute in (("", True), ("/a\0b", True), ("//a", True), ("/a//b", True),
                               ("/a/../b", True), ("/a/./b", True), ("/a/", True),
                               ("/a\\b", True), ("a/b", True), ("/a/b", False), ("../a", False)):
            self.rejects("path-" + repr(path), lambda p=path, a=absolute: self.module.canonical_path(p, a))

    def test_full9_rejects_boolean_and_wrong_inode_shapes(self):
        row = [1, 2, stat.S_IFREG | 0o600, 501, 20, 1, 3, 1234567890123456789, 1234567890123456789]
        self.assertEqual(self.module.full9(row, "file", 3), row)
        for i in range(9):
            changed = list(row)
            changed[i] = True
            self.rejects("full9-bool-" + str(i), lambda x=changed: self.module.full9(x, "file", 3))
        for name, changed in (("short", row[:-1]), ("hardlink", row[:5] + [2] + row[6:]),
                              ("size", row[:6] + [4] + row[7:]), ("negative", [-1] + row[1:]),
                              ("symlink", row[:2] + [stat.S_IFLNK | 0o777] + row[3:])):
            self.rejects("full9-" + name, lambda x=changed: self.module.full9(x, "file", 3))

    def test_descriptor_types_and_fields(self):
        valid = {"path": "/retained/a", "bytes": 0, "sha256": hashlib.sha256(b'').hexdigest()}
        self.assertEqual(self.module.descriptor(valid), valid)
        for name, changes in (("bool-bytes", {"bytes": False}), ("negative", {"bytes": -1}),
                               ("uppercase-hash", {"sha256": valid["sha256"].upper()}),
                               ("short-hash", {"sha256": "0" * 63}), ("nul", {"path": "/a\0b"}),
                               ("extra", {"unexpected": True})):
            value = dict(valid, **changes)
            self.rejects("descriptor-" + name, lambda v=value: self.module.descriptor(v))

    def test_bound_loader_and_declaration(self):
        for name, raw in (("appended", self.source + b'\n'), ("truncated", self.source[:-1]),
                           ("mutable", bytearray(self.source)), ("text", self.source.decode())):
            self.rejects("loader-" + name, lambda r=raw: self.loader.load(r))
        self.rejects("declaration-mismatch", lambda: self.module.verify_retained_r10_failure(
            self.expectation, {}, implementation_source=self.source + b'\n'))
        calls = []
        self.rejects("declaration-before-callback", lambda: self.module.verify_with_reader(
            self.expectation, read_pinned=lambda row: calls.append(row), implementation_source=self.source + b'\n'))
        self.assertEqual(calls, [])
        self.rejects("expectation-before-callback", lambda: self.module.verify_with_reader(
            self.expectation + b'\n', read_pinned=lambda row: calls.append(row), implementation_source=self.source))
        self.assertEqual(calls, [])

    def test_missing_role_set_rejected(self):
        for name, originals in (("empty", {}), ("list", []), ("extra", {"invented": b"x"})):
            self.rejects("roles-" + name, lambda o=originals: self.module.verify_retained_r10_failure(
                self.expectation, o, implementation_source=self.source))


class RealOriginalTests(unittest.TestCase):
    rejects = PortableTests.rejects

    @classmethod
    def setUpClass(cls):
        if FIXTURE is None:
            raise unittest.SkipTest("private exact R10 original archive/controller fixture not supplied")

    def setUp(self):
        PortableTests.setUp(self)
        mapping = json.loads((FIXTURE / "LOCAL-FIXTURE-MAP.json").read_bytes())
        self.originals = {role: (FIXTURE / row["local_fixture_file"]).read_bytes() for role, row in mapping.items()}
        self.index = self.module.strict(self.originals["retained_index"])
        self.inputs = self.module.strict(self.originals["retained_inputs"])
        self.rows = self.module.verify_inventory(self.index, self.inputs)
        self.files = self.module.verify_archive(self.originals["retained_archive"], self.originals["retained_index"], self.index, self.rows)

    def change_doc(self, path, callback):
        files = dict(self.files)
        obj = self.module.strict(files[path])
        callback(obj)
        files[path] = encoded(obj)
        return files

    def test_complete_actual_result_and_no_promotion(self):
        result = self.module.verify_retained_r10_failure(self.expectation, self.originals, implementation_source=self.source)
        self.assertEqual(result["retained_file_count"], 125)
        self.assertEqual(result["archive_members_verified"], 126)
        self.assertEqual(result["original_host_controller"]["exit_code"], 1)
        self.assertEqual(result["original_host_phase_count"], 7)
        self.assertEqual(result["original_actor_rc"], 1)
        for field in ("original_phone_terminal", "original_phone_stage_writes", "global_unknown_effect_count"):
            self.assertIsNone(result[field])
        for field in ("retirement_accepted", "fresh_execution_eligible", "standalone_execution_authorized",
                      "nonce_creation_authorized", "component_qualified", "business_qualified", "production_adopted",
                      "complete_current_phone_scope_verified"):
            self.assertIs(result[field], False)
        self.assertEqual(result["native_case_credit"], 0)

    def test_every_actual_role_is_required_and_byte_pinned(self):
        for role in self.originals:
            missing = dict(self.originals)
            del missing[role]
            self.rejects("missing-real-" + role, lambda v=missing: self.module.verify_retained_r10_failure(
                self.expectation, v, implementation_source=self.source))
            changed = dict(self.originals)
            changed[role] += b'\0'
            self.rejects("altered-real-" + role, lambda v=changed: self.module.verify_retained_r10_failure(
                self.expectation, v, implementation_source=self.source))

    def test_second_callback_must_be_immutable_bytes_and_unchanged(self):
        rows = self.module.strict(self.expectation)["roles"]
        by_path = {row["path"]: self.originals[role] for role, row in rows.items()}
        class EqualityImpostor:
            def __eq__(self, other):
                return True
        for label, replacement in (("mutable", lambda b: bytearray(b)), ("equality-object", lambda b: EqualityImpostor()),
                                    ("changed", lambda b: b + b'\0')):
            count = [0]
            def reader(row):
                count[0] += 1
                raw = by_path[row["path"]]
                return replacement(raw) if count[0] == 14 else raw
            self.rejects("second-provider-" + label, lambda: self.module.verify_with_reader(
                self.expectation, read_pinned=reader, implementation_source=self.source))
            self.assertEqual(count[0], 14)

    def test_unknown_and_failure_flags_cannot_be_promoted_in_semantics(self):
        path = self.module.OUT + "/ROOT-FAILURE.json"
        for key in ("automatic_retry", "new_identity_retry", "send_again", "business_qualified", "component_qualified"):
            changed = self.change_doc(path, lambda v, k=key: v.__setitem__(k, True))
            self.rejects("failure-promote-" + key, lambda v=changed: self.module.verify_failure_semantics(v, self.rows))
        for key in ("model_requests", "policy_changes", "signals_sent_by_coordinator"):
            changed = self.change_doc(path, lambda v, k=key: v.__setitem__(k, False))
            self.rejects("coordinator-bool-" + key, lambda v=changed: self.module.verify_failure_semantics(v, self.rows))

    def test_all_nine_capture_metadata_fields_and_remote_claims(self):
        path = self.module.OUT + "/phone-stage/OUTPUT-CAPTURE.json"
        for key in self.module.META_KEYS:
            changed = self.change_doc(path, lambda v, k=key: v["files"]["stdout"]["metadata"].__setitem__(k, v["files"]["stdout"]["metadata"][k] + 1))
            self.rejects("capture-full9-" + key, lambda v=changed: self.module.verify_failure_semantics(v, self.rows))
        for key, value in (("remote_terminal_or_cleanup_proven", True), ("stdout_eof", False),
                            ("worker_joined", False), ("signals_sent", False)):
            changed = self.change_doc(path, lambda v, k=key, x=value: v.__setitem__(k, x))
            self.rejects("capture-" + key, lambda v=changed: self.module.verify_failure_semantics(v, self.rows))
        changed = self.change_doc(path, lambda v: v["files"]["stdout"]["metadata"].__setitem__("st_nlink", True))
        self.rejects("capture-full9-bool-nlink", lambda: self.module.verify_failure_semantics(changed, self.rows))

    def test_controller_crossbinding_and_typed_terminal(self):
        plan = self.module.strict(self.files[self.module.OUT + "/ROOT-PLAN.original.json"])
        changes = (("worker_exit", "exit_code", 0), ("worker_exit", "exit_code", True),
                   ("worker_exit", "timed_out", True), ("worker_exit", "output_complete", False),
                   ("worker_exit", "output_durable", False), ("worker_exit", "terminal_publication_protocol", True),
                   ("worker_exit_witness", "exit_sha256", "0" * 64), ("worker_request", "launch_nonce", "f" * 32),
                   ("controller_metadata", "idempotency_key", "new-label"))
        for role, key, value in changes:
            originals = dict(self.originals)
            document = self.module.strict(originals[role])
            document[key] = value
            originals[role] = encoded(document)
            self.rejects("controller-" + role + "-" + key + "-" + repr(value),
                         lambda v=originals: self.module.verify_controller(v, plan))
        for key in ("seen", "stored"):
            originals = dict(self.originals)
            terminal = self.module.strict(originals['worker_exit'])
            terminal['log_bytes']['stdout'][key] = False
            originals['worker_exit'] = encoded(terminal)
            witness = self.module.strict(originals['worker_exit_witness'])
            witness['exit_sha256'] = hashlib.sha256(originals['worker_exit']).hexdigest()
            originals['worker_exit_witness'] = encoded(witness)
            self.rejects("controller-log-bool-" + key, lambda v=originals: self.module.verify_controller(v, plan))

    def test_complete_inventory_topology_and_metadata(self):
        index = copy.deepcopy(self.index)
        index["files"].pop()
        self.rejects("inventory-missing-file", lambda: self.module.verify_inventory(index, self.inputs))
        index = copy.deepcopy(self.index)
        root = index["complete_census"]["entries"][self.module.OUT]
        root["children"].append("invented")
        self.rejects("inventory-extra-child", lambda: self.module.verify_inventory(index, self.inputs))
        index = copy.deepcopy(self.index)
        index["files"][0]["metadata"][1] += 1
        self.rejects("inventory-file-full9-mismatch", lambda: self.module.verify_inventory(index, self.inputs))
        index = copy.deepcopy(self.index)
        index["files"][0]["archive_member"] = "../escape"
        self.rejects("inventory-tar-traversal", lambda: self.module.verify_inventory(index, self.inputs))

    def test_material_copy_is_exact_and_not_global_zero_writes(self):
        path = self.module.OUT + "/phone-push-material/stdout.original"
        for name, change in (("actor-bool", lambda v: v.__setitem__('actor_rc', False)),
                             ("wrong-hash", lambda v: v['wrapper'].__setitem__('sha256', '0' * 64)),
                             ("readback-bool", lambda v: v['wrapper']['readback'].__setitem__('rc', False))):
            changed = self.change_doc(path, change)
            self.rejects("material-" + name, lambda v=changed: self.module.verify_material_transfers(v))
        path = self.module.OUT + "/phone-copy-material/stdout.original"
        changed = self.change_doc(path, lambda v: v['wrapper']['phone'].__setitem__('rc', 1))
        self.rejects("copy-failed-phone", lambda: self.module.verify_material_transfers(changed))
        def wrong_target(wrapper):
            row = json.loads(wrapper['wrapper']['phone']['stdout'])
            row['target']['path'] += '-other'
            wrapper['wrapper']['phone']['stdout'] = json.dumps(row)
        changed = self.change_doc(path, wrong_target)
        self.rejects("copy-wrong-target", lambda: self.module.verify_material_transfers(changed))


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, default=BASE)
    parser.add_argument("--fixture", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args()
    BASE = args.base.resolve()
    FIXTURE = args.fixture.resolve() if args.fixture else None
    suite = unittest.TestSuite((unittest.defaultTestLoader.loadTestsFromTestCase(PortableTests),
                               unittest.defaultTestLoader.loadTestsFromTestCase(RealOriginalTests)))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    report = {"schema": "hepta.UNADOPTED.retained-r10-negative-tests.v1", "state": "PASS" if result.wasSuccessful() else "FAIL",
              "tests_run": result.testsRun, "skipped": [(str(t), reason) for t, reason in result.skipped],
              "negative_cases": len(CASES), "case_names": CASES, "private_originals_supplied": FIXTURE is not None,
              "synthetic_portable_cases_are_not_original_execution_evidence": True,
              "implementation_sha256": hashlib.sha256((BASE / 'candidate/retained_r10_failure.py').read_bytes()).hexdigest(),
              "phone_calls": 0, "native_submissions": 0, "runtime_admission": False, "production_adopted": False}
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open('x', encoding='utf-8') as stream:
            stream.write(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + '\n')
    print(json.dumps({k: v for k, v in report.items() if k != 'case_names'}, ensure_ascii=False))
    raise SystemExit(0 if result.wasSuccessful() else 1)
