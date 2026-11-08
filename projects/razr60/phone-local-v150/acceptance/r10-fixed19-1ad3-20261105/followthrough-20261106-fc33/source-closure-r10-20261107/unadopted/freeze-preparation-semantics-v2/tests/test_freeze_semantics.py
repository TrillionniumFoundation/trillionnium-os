"""Explicit synthetic originals test semantic guards; they are not host receipts."""
import argparse
import copy
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath
import stat
import sys
import unittest

BASE = Path(__file__).resolve().parents[1]
SOURCE = (BASE / "candidate/freeze_semantics.py").read_bytes()
spec = importlib.util.spec_from_file_location("freeze_bound_loader", BASE / "candidate/bound_loader.py")
LOADER = importlib.util.module_from_spec(spec); spec.loader.exec_module(LOADER)
M = LOADER.load(SOURCE, SOURCE)
NEGATIVE_CASES = 0
R10_BASE = BASE.parent / "retained-r10-failure-v1"
if not R10_BASE.exists():
    R10_BASE = BASE.parent / "r10-failure-admission-candidate"


def descriptor(name, raw):
    return {"path": name, **M.pin(raw)}


def metadata(size, inode, private=False, directory=False):
    mode = (stat.S_IFDIR | 0o700) if directory else (stat.S_IFREG | (0o600 if private else 0o644))
    return [1, inode, mode, 501, 20, 1, size, 1000000001, 1000000002]


def synthetic_bundle(*, file_edit=None, plan_edit=None, freeze_edit=None, controller_edit=None):
    root = "/synthetic-test-only/new-freeze"
    freezer_path = "/synthetic-test-only/source/freezer.py"
    freezer = b"# SYNTHETIC TEST ONLY: never execute this as a freezer.\n"
    policy_path, policy = "/synthetic-test-only/source/policy.json", b'{"synthetic_policy":true}\n'
    adoption_path, adoption = "/synthetic-test-only/source/adoption.json", b'{"synthetic_adoption":true}\n'
    inputs_raw = {freezer_path: freezer, policy_path: policy, adoption_path: adoption}
    inputs = {name: {**descriptor(name, raw), "metadata": metadata(len(raw), i + 10)}
              for i, (name, raw) in enumerate(inputs_raw.items())}
    files = {"FREEZER-SOURCE.original.py": freezer, "COMBINATION.json": b'{"synthetic_combination":true}\n',
             "SOURCE-PARENT-RECORDS.json": b'[{"synthetic_source_parent":true}]\n'}
    runtime = {}
    for i in range(38):
        name = "source/synthetic_%02d.py" % i
        runtime[name] = ("# SYNTHETIC runtime member %d\n" % i).encode()
        files["runtime/" + name] = runtime[name]
    package = {"schema": "hepta.native-guard.adapter-package.v1",
               "current_combination_sha256": M.pin(files["COMBINATION.json"])["sha256"],
               "source_parent_records": M.strict(files["SOURCE-PARENT-RECORDS.json"]),
               "files": [{"path": name, **M.pin(raw)} for name, raw in runtime.items()]}
    files["runtime/MANIFEST.json"] = M.encoded(package)
    root_members = {"source/run_component_root_once.py": ("PKG = %r\n" % M.pin(files["runtime/MANIFEST.json"])["sha256"]).encode(),
                    "source/synthetic_root_a.py": b"# synthetic a\n", "source/synthetic_root_b.py": b"# synthetic b\n"}
    files.update({"root-chain/" + name: raw for name, raw in root_members.items()})
    root_manifest = {"schema": "hepta.native-guard.root-chain-source-package.v1",
                     "current_combination_sha256": package["current_combination_sha256"],
                     "files": [{"path": name, **M.pin(raw)} for name, raw in root_members.items()]}
    files["root-chain/SOURCE-MANIFEST.json"] = M.encoded(root_manifest)
    shared = {"source/synthetic_shared_%02d.py" % i: ("# synthetic shared %d\n" % i).encode() for i in range(17)}
    files.update({"shared/" + name: raw for name, raw in shared.items()})
    files["shared/SHARED-MATERIALS.json"] = M.encoded({"schema": "hepta.r10.shared-production-materials.v1",
        "files": [{"path": name, **M.pin(raw)} for name, raw in shared.items()]})
    for name in M.ADMISSION_NAMES:
        files["dependencies/admission/" + name + ".py"] = ("# SYNTHETIC inherited %s source; not executed\n" % name).encode()
    files["dependencies/DEPENDENCIES.json"] = b'{"synthetic_dependency_manifest":true}\n'
    checks = {"source_parent_current_credit": False, "historical_failed_count": 9,
              "source_parent_count": 1, "fresh_phone_admission_required": True}
    files["HOST-VALIDATION.json"] = M.encoded(checks)
    if file_edit:
        file_edit(files)
    planned_files = {name: descriptor(root + "/" + name, raw) for name, raw in files.items()}
    plan = {"schema": M.PLAN_SCHEMA, "frozen_root": root, "source": descriptor(freezer_path, freezer),
            "files": planned_files, "actual_input_files": inputs,
            "expected_history": {"historical_failed_count": 9, "source_parent_count": 1},
            "actual_policy": M.pin(policy), "actual_adoption": descriptor(adoption_path, adoption)}
    if plan_edit:
        plan_edit(plan)
    plan_raw = M.encoded(plan)
    f = {"schema": "hepta.fc33.native-bound.actual-host-freeze.v1", "state": "FROZEN_FOR_NEW_NEG01_THEN_NEG02_NOT_QUALIFIED",
         "source": plan["source"], "output": root, "phone_calls": 0, "native_submissions": 0, "new_nonces": 0,
         "full19_qualified": False, "production_ready": False, "automatic_retry": False,
         "rollback_admission_is_separate_required_gate": True, "all_inputs_bookended_before_publication": True,
         "all_output_files_read_back": True, "terminal_record_is_last": True, "files": planned_files,
         "actual_input_files": inputs, "actual_policy": plan["actual_policy"], "actual_adoption": plan["actual_adoption"],
         "result_bytes": 0, "terminal_copies": 2, "payload_bytes": sum(map(len, files.values())),
         "complete_directory_bytes": 0, "maximum_complete_directory_bytes": M.MAX_FREEZE_BYTES,
         "checks": checks, "combination": planned_files["COMBINATION.json"],
         "dependencies": planned_files["dependencies/DEPENDENCIES.json"]}
    for name, key, _ in M.MANIFESTS:
        f[key] = planned_files[name]
    for _ in range(12):
        raw = M.encoded(f)
        if f["result_bytes"] == len(raw) and f["complete_directory_bytes"] == f["payload_bytes"] + 2 * len(raw):
            break
        f["result_bytes"] = len(raw); f["complete_directory_bytes"] = f["payload_bytes"] + 2 * len(raw)
    else:
        raise AssertionError("synthetic accounting failed to converge")
    if freeze_edit:
        freeze_edit(f)
    raw = M.encoded(f); freeze_row = descriptor(root + "/FREEZE-RESULT.json", raw)
    request = {"host": "mac", "executable": "/usr/bin/python3",
               "args": [freezer_path, "--freeze-reviewed-host-runtime", M.pin(freezer)["sha256"]],
               "idempotency_key": "synthetic-only-new-source-freeze-once"}
    summary = {"state": f["state"], "freeze": freeze_row, "phone_calls": 0, "full19_qualified": False,
               **{k: f[k] for k in ("runtime_manifest", "root_chain_manifest", "combination", "complete_directory_bytes")}}
    stdout = M.encoded(summary); stderr = b""
    start = {"reused": False, "job": {**request, "id": "synthetic-test-only-job", "launch_error": None, "launch_state": "launched"}}
    status = {"job_id": "synthetic-test-only-job", "state": "succeeded", "exit_code": 0, "cancelled": False,
              "timed_out": False, "automatic_retry": False, "output_complete": True, "output_durable": True,
              "terminal_publication_confirmed": True, "log_bytes": {}, "log_truncated": {}, "log_synced": {}, "log_errors": {}}
    read = {"job_id": "synthetic-test-only-job"}
    for name, data in (("stdout", stdout), ("stderr", stderr)):
        status["log_bytes"][name] = {"seen": len(data), "stored": len(data)}
        status["log_truncated"][name] = False; status["log_synced"][name] = True; status["log_errors"][name] = None
        read[name] = {"bytes_hex": data.hex(), "offset": 0, "next_offset": len(data), "size": len(data), "eof": True}
    inner = {"request": request, "start": start, "status": status, "read": read}
    if controller_edit:
        controller_edit(inner)
    envelope = lambda x: {"isError": False, "content": [{"type": "text", "text": M.encoded(x).decode()}]}
    carrier = {"schema": "hepta.fc33.actual-runtime-freeze-controller-originals.v1", "request": inner["request"],
               **{k: envelope(inner[k]) for k in ("start", "status", "read")}}
    carrier_raw = M.encoded(carrier)
    contract = {"schema": M.CONTRACT_SCHEMA, "state": "ORIGINALS_SUPPLIED_FOR_OFFLINE_VERIFICATION",
                "frozen_root": root, "freeze": freeze_row, "freezer": descriptor(freezer_path, freezer),
                "controller": descriptor("/synthetic-test-only/source/controller.json", carrier_raw),
                "membership_plan": descriptor("/synthetic-test-only/source/membership-plan.json", plan_raw),
                "controller_request": copy.deepcopy(request)}
    originals = {root + "/" + name: data for name, data in files.items()}
    originals.update(inputs_raw)
    originals.update({freeze_row["path"]: raw, root + "/DERIVATION.json": raw,
                      contract["controller"]["path"]: carrier_raw, contract["membership_plan"]["path"]: plan_raw})
    observations = {"files": {}, "directories": {}}
    for i, (name, data) in enumerate(originals.items()):
        full = inputs[name]["metadata"] if name in inputs else metadata(len(data), 1000 + i, name.startswith(root + "/"))
        observations["files"][name] = {key: list(full) for key in ("before", "after", "named")}
    dirs = {root: set()}
    for member in set(files) | {"FREEZE-RESULT.json", "DERIVATION.json"}:
        parts = PurePosixPath(member).parts; parent = PurePosixPath(root)
        for name in parts[:-1]:
            dirs.setdefault(str(parent), set()).add(name); parent /= name; dirs.setdefault(str(parent), set())
        dirs[str(parent)].add(parts[-1])
    for i, (name, children) in enumerate(dirs.items()):
        full = metadata(100, 5000 + i, directory=True)
        observations["directories"][name] = {"before": list(full), "after": list(full),
            "names_before": sorted(children), "names_after": sorted(children)}
    return [M.encoded(contract), plan_raw, originals, observations]


def verify(bundle):
    return M.verify_freeze_bundle(*bundle, implementation_source=SOURCE)


def repair_accounting(f):
    for _ in range(12):
        raw = M.encoded(f)
        if f["result_bytes"] == len(raw) and f["complete_directory_bytes"] == f["payload_bytes"] + 2 * len(raw):
            return
        f["result_bytes"] = len(raw)
        f["complete_directory_bytes"] = f["payload_bytes"] + 2 * len(raw)
    raise AssertionError("modified synthetic accounting failed to converge")


class FreezeSemanticsTests(unittest.TestCase):
    def reject(self, function, *args, **kwargs):
        global NEGATIVE_CASES
        with self.assertRaises((ValueError, KeyError, TypeError, SyntaxError)):
            function(*args, **kwargs)
        NEGATIVE_CASES += 1

    def test_complete_synthetic_semantics_has_no_runtime_credit(self):
        result = verify(synthetic_bundle())
        self.assertEqual(result["manifest_member_counts"], [38, 3, 17])
        self.assertEqual(len(result["inherited_admission_source_originals"]), 6)
        self.assertEqual(result["controller_result"]["exit_code"], 0)
        self.assertEqual({k: result[k] for k in M.CLAIM_CEILING}, M.CLAIM_CEILING)
        self.assertFalse(result["observations"]["observations_proven_live"])
        self.assertFalse(result["source_build_reproducibility_verified"])

    def test_missing_and_changed_bytes_do_not_pass_self_reported_membership(self):
        for role in ("runtime/source/synthetic_01.py", "root-chain/source/synthetic_root_a.py", "shared/source/synthetic_shared_03.py"):
            bundle = synthetic_bundle(); path = "/synthetic-test-only/new-freeze/" + role
            del bundle[2][path]; self.reject(verify, bundle)
            bundle = synthetic_bundle(); bundle[2][path] += b"# changed"; self.reject(verify, bundle)
        for name in M.ADMISSION_NAMES:
            def edit(p, name=name):
                del p["files"]["dependencies/admission/" + name + ".py"]
            self.reject(verify, synthetic_bundle(plan_edit=edit))

    def test_manifest_cardinality_duplicate_members_and_root_pkg(self):
        for manifest, _, _ in M.MANIFESTS:
            for duplicate in (False, True):
                def edit(files, manifest=manifest, duplicate=duplicate):
                    value = M.strict(files[manifest])
                    if duplicate:
                        value["files"][1] = value["files"][0]
                    else:
                        value["files"].pop()
                    files[manifest] = M.encoded(value)
                self.reject(verify, synthetic_bundle(file_edit=edit))
        self.reject(verify, synthetic_bundle(file_edit=lambda f: f.__setitem__("root-chain/source/run_component_root_once.py", b"PKG='wrong'\n")))

    def test_freeze_qualification_and_accounting_rejections(self):
        cases = [("phone_calls", False), ("native_submissions", 1), ("new_nonces", 1),
                 ("full19_qualified", True), ("production_ready", True), ("automatic_retry", True),
                 ("rollback_admission_is_separate_required_gate", False), ("all_output_files_read_back", False),
                 ("terminal_record_is_last", False), ("terminal_copies", 1), ("terminal_copies", True),
                 ("payload_bytes", 0), ("result_bytes", 0), ("maximum_complete_directory_bytes", 33554433)]
        for key, value in cases:
            self.reject(verify, synthetic_bundle(freeze_edit=lambda f, key=key, value=value: f.__setitem__(key, value)))

    def test_controller_identity_terminal_and_complete_streams(self):
        edits = [lambda d: d["start"].__setitem__("reused", True),
                 lambda d: d["start"]["job"].__setitem__("id", "other-job"),
                 lambda d: d["start"]["job"].__setitem__("launch_state", "launch_unknown"),
                 lambda d: d["read"].__setitem__("job_id", "other-job")]
        for key, value in (("state", "failed"), ("exit_code", False), ("exit_code", 1), ("cancelled", True),
                           ("timed_out", True), ("automatic_retry", True), ("output_complete", False),
                           ("output_durable", False), ("terminal_publication_confirmed", False)):
            edits.append(lambda d, key=key, value=value: d["status"].__setitem__(key, value))
        for stream in ("stdout", "stderr"):
            for key, value in (("offset", 1), ("eof", False), ("size", True)):
                edits.append(lambda d, stream=stream, key=key, value=value: d["read"][stream].__setitem__(key, value))
            for key, value in (("log_truncated", True), ("log_synced", False), ("log_errors", "IO error")):
                edits.append(lambda d, stream=stream, key=key, value=value: d["status"][key].__setitem__(stream, value))
        for edit in edits:
            self.reject(verify, synthetic_bundle(controller_edit=edit))

    def test_full9_nanosecond_identity_membership_and_tree_guards(self):
        for field in range(9):
            bundle = synthetic_bundle(); record = next(iter(bundle[3]["files"].values()))
            record["after"][field] += 1; self.reject(verify, bundle)
        for key in ("names_before", "names_after"):
            bundle = synthetic_bundle(); record = next(iter(bundle[3]["directories"].values()))
            record[key].append("unexpected-member"); self.reject(verify, bundle)
        class EqualityObject:
            def __eq__(self, other):
                return True
        for key in ("names_before", "names_after"):
            bundle = synthetic_bundle(); record = next(iter(bundle[3]["directories"].values()))
            record[key] = [EqualityObject() for _ in record[key]]; self.reject(verify, bundle)
        bundle = synthetic_bundle(); next(iter(bundle[3]["directories"].values()))["after"][8] += 1
        self.reject(verify, bundle)
        bundle = synthetic_bundle(); bundle[3]["files"].pop(next(iter(bundle[3]["files"])))
        self.reject(verify, bundle)

    def test_json_paths_and_source_binding_reject_before_any_io(self):
        for raw in (b'{"x":1,"x":2}', b'{"x":NaN}', b'{"x":1e9999}'):
            self.reject(M.strict, raw)
        for value in ("/x\x00y", "//x", "/x//y", "/x/../y", "relative"):
            self.reject(M.path, value)
        for actual, declared in ((SOURCE + b"\n", SOURCE), (SOURCE, SOURCE + b"\n"), (bytearray(SOURCE), SOURCE)):
            self.reject(LOADER.load, actual, declared)
        bundle = synthetic_bundle()
        self.reject(M.verify_freeze_bundle, *bundle, implementation_source=SOURCE + b"\n")

    def test_impossible_file_directory_overlap_and_dependency_binding(self):
        for parent, child in (("synthetic-leaf", "synthetic-leaf/child"), ("FREEZE-RESULT.json", "FREEZE-RESULT.json/child")):
            def edit(p, parent=parent, child=child):
                if parent not in ("FREEZE-RESULT.json", "DERIVATION.json"):
                    p["files"][parent] = descriptor(p["frozen_root"] + "/" + parent, b"a")
                p["files"][child] = descriptor(p["frozen_root"] + "/" + child, b"b")
            self.reject(verify, synthetic_bundle(plan_edit=edit))
        self.reject(verify, synthetic_bundle(freeze_edit=lambda f: f["dependencies"].__setitem__("sha256", "0" * 64)))

    def test_independent_review_type_alias_and_extra_subtree_counterexamples(self):
        def retype_input(f):
            f["actual_input_files"] = copy.deepcopy(f["actual_input_files"])
            next(iter(f["actual_input_files"].values()))["metadata"][5] = True
            repair_accounting(f)
        def retype_check(f):
            f["checks"] = copy.deepcopy(f["checks"])
            f["checks"]["source_parent_current_credit"] = 0
            repair_accounting(f)
        def retype_descriptor(f):
            f["runtime_manifest"] = copy.deepcopy(f["runtime_manifest"])
            f["runtime_manifest"]["bytes"] = float(f["runtime_manifest"]["bytes"])
            repair_accounting(f)
        for edit in (retype_input, retype_check, retype_descriptor):
            self.reject(verify, synthetic_bundle(freeze_edit=edit))
        for family in ("runtime", "root-chain", "shared"):
            self.reject(verify, synthetic_bundle(file_edit=lambda files, family=family:
                        files.__setitem__(family + "/source/undeclared_extra.py", b"# explicit synthetic undeclared file\n")))

    def test_unbound_and_old_generations_call_no_provider(self):
        bundle = synthetic_bundle(); contract = M.strict(bundle[0]); labels = {"NEG-01": "synthetic-new-neg01", "NEG-02": "synthetic-new-neg02"}
        calls = []
        def reader(row):
            calls.append(row); raise AssertionError("UNBOUND must not read")
        invalid = copy.deepcopy(contract); invalid["state"] = "UNBOUND"
        self.reject(M.verify_new_freeze_with_provider, M.encoded(invalid), bundle[1], labels, [],
                    read_observed=reader, implementation_source=SOURCE)
        for field, old in (("freeze", M.OLD_FREEZE_SHA), ("controller", M.OLD_CONTROLLER_SHA)):
            invalid = copy.deepcopy(contract); invalid[field]["sha256"] = old
            self.reject(M.verify_new_freeze_with_provider, M.encoded(invalid), bundle[1], labels, [],
                        read_observed=reader, implementation_source=SOURCE)
        invalid = copy.deepcopy(contract); invalid["controller_request"]["idempotency_key"] = M.OLD_IDEMPOTENCY_KEY
        self.reject(M.verify_new_freeze_with_provider, M.encoded(invalid), bundle[1], labels, [],
                    read_observed=reader, implementation_source=SOURCE)
        for label in M.OLD_LABELS | {"synthetic-consumed-label"}:
            invalid_labels = dict(labels); invalid_labels["NEG-01"] = label
            self.reject(M.verify_new_freeze_with_provider, bundle[0], bundle[1], invalid_labels, ["synthetic-consumed-label"],
                        read_observed=reader, implementation_source=SOURCE)
        self.assertEqual(calls, [])

    def test_explicit_provider_double_read_and_copy_mutable_metadata(self):
        bundle = synthetic_bundle(); calls = []
        def reader(row):
            calls.append(row["path"])
            return {"raw": bundle[2][row["path"]], **copy.deepcopy(bundle[3]["files"][row["path"]])}
        labels = {"NEG-01": "synthetic-new-neg01", "NEG-02": "synthetic-new-neg02"}
        result = M.verify_new_freeze_with_provider(bundle[0], bundle[1], labels, [], read_observed=reader, implementation_source=SOURCE)
        self.assertEqual(result["provider_calls"], 2 * len(bundle[2]))
        self.assertEqual(result["implementation"], M.pin(SOURCE))
        self.assertEqual(result["contract"], M.pin(bundle[0]))
        self.assertEqual(calls[:len(bundle[2])], calls[len(bundle[2]):])
        self.assertFalse(result["complete_tree_observation_supplied"])
        for kind in ("raw", "metadata"):
            count = [0]
            def corrupt(row):
                value = reader(row); count[0] += 1
                if count[0] > len(bundle[2]):
                    if kind == "raw":
                        value["raw"] = bytearray(value["raw"])
                    else:
                        value["named"][8] += 1
                return value
            self.reject(M.verify_new_freeze_with_provider, bundle[0], bundle[1], labels, [], read_observed=corrupt, implementation_source=SOURCE)

    def test_r10_context_refuses_changed_reader_before_execution(self):
        parent = R10_BASE
        reader = (parent / "candidate/retained_r10_failure.py").read_bytes()
        loader = (parent / "candidate/bound_loader.py").read_bytes()
        for a, b in ((reader + b"\n", loader), (reader, loader + b"\n")):
            self.reject(M.verify_retained_r10_context, b"{}", {}, reader_source=a, loader_source=b, implementation_source=SOURCE)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(); parser.add_argument("--report", type=Path)
    parser.add_argument("--retained-base", type=Path)
    args = parser.parse_args()
    if args.retained_base:
        R10_BASE = args.retained_base
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FreezeSemanticsTests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    report = {"schema": "hepta.UNADOPTED.source-freeze-synthetic-tests.v1", "result": "PASS" if result.wasSuccessful() else "FAIL",
              "tests": result.testsRun, "negative_cases": NEGATIVE_CASES, "implementation": M.pin(SOURCE),
              "synthetic_originals_only": True, "actual_future_freeze_or_controller_attested": False,
              "runtime_admission": False, "new_phone_calls": 0, "new_nonces": 0}
    raw = M.encoded(report)
    if args.report:
        with args.report.open("xb") as stream:
            stream.write(raw)
    print(raw.decode(), end="")
    sys.exit(0 if result.wasSuccessful() else 1)
