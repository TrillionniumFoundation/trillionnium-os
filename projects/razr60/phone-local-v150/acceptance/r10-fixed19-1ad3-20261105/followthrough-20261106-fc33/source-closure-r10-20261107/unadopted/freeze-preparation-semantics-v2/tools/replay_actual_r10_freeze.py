"""Read the fixed retained R10 freeze as historical source facts, without running it.

The generated membership plan is a historical replay adapter derived from one
independently fixed old FREEZE hash. It is not a future reviewed source plan.
Only new private audit files are written. Existing sources, outputs and receipts
are read twice; there is no phone, nonce, reservation, signal or subprocess path.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import time
import traceback

OLD_ROOT = Path("/Users/qianqi/Documents/Codex/2026-10-18/pocket4-razr60-ui/work/stock16-hepta-local-model-Root-v150-r1")
FROZEN = OLD_ROOT / "native-guard-r10-r1-operator-fc33-native-v3-r10"
FREEZE = {"path": str(FROZEN / "FREEZE-RESULT.json"), "bytes": 1613295,
          "sha256": "651b4dd0f4f1c32b1928d58480e1adc3f2fcf104884db44b4eac52a0c625ba6d"}
FREEZER = {"path": str(OLD_ROOT / "followthrough-fc33-runtime-r10-review01/freeze_native_bound_runtime_r10_fc33.py"),
           "bytes": 32010, "sha256": "7db072079c16ca6485d3ea6083eec5adf1054ebe0e6850d6eabf352745603b36"}
CONTROLLER = {"path": str(OLD_ROOT / "followthrough-fc33-runtime-r10-review01/R10-FREEZE-CONTROLLER-ORIGINALS.json"),
              "bytes": 8823, "sha256": "d7a4f0aaa6bfd2852ba5395db3296a0b50abfb16fb6fba7c8661d05d422ad881"}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = args.output
    if output.exists():
        raise ValueError("new audit output required; no overwrite")
    output.mkdir(mode=0o700, parents=False)
    os.umask(0o077)
    source = (args.base / "candidate/freeze_semantics.py").read_bytes()
    loader_path = args.base / "candidate/bound_loader.py"
    spec = importlib.util.spec_from_file_location("actual_freeze_semantics_bound_loader", loader_path)
    loader = importlib.util.module_from_spec(spec); spec.loader.exec_module(loader)
    M = loader.load(source, source)
    count = {"original_file_opens": 0, "original_bytes_read": 0}
    def meta(s):
        return [getattr(s, key) for key in M.FULL9]
    def read(row):
        M.descriptor(row); p = Path(row["path"])
        M.need(p.is_absolute() and p.resolve(strict=True) == p, "canonical actual original required")
        fd = os.open(str(p), os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK)
        count["original_file_opens"] += 1
        try:
            before = os.fstat(fd)
            M.need(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size == row["bytes"],
                   "actual original file identity/size differs")
            with os.fdopen(fd, "rb", closefd=False) as stream:
                raw = stream.read(row["bytes"] + 1)
            count["original_bytes_read"] += len(raw)
            after = os.fstat(fd); named = p.lstat()
            M.need(M.pin(raw) == {k: row[k] for k in ("bytes", "sha256")}
                   and meta(before) == meta(after) == meta(named), "actual bytes/full9 bookends differ")
            return raw, {"before": meta(before), "after": meta(after), "named": meta(named)}
        finally:
            os.close(fd)
    def put(name, raw):
        p = output / name
        with p.open("xb") as stream:
            stream.write(raw)
        return {"path": str(p), **M.pin(raw)}
    began = time.perf_counter(); new_entry_calls = []
    report = {"schema": "hepta.UNADOPTED.actual-retained-R10-source-freeze-replay.v1",
              "implementation": M.pin(source), "loader": M.pin(loader_path.read_bytes()),
              "retained_freeze": FREEZE, "retained_freezer": FREEZER, "retained_controller": CONTROLLER,
              "fixture_kind": "actual existing R10 host files, newly read; historical source facts only",
              "historical_membership_adapter_is_new_generation_review_plan": False,
              "actual_new_generation_freeze_created": False, "new_phone_calls": 0,
              "native_submissions": 0, "new_nonces": 0, "runtime_admission": False,
              "existing_freezer_or_preparer_executed": False, "original_effect_counts_changed": False}
    try:
        frozen_raw, frozen_observation = read(FREEZE)
        f = M.strict(frozen_raw)
        M.need(f["source"] == FREEZER and f["output"] == str(FROZEN), "exact fixed historical source/root tuple required")
        plan = {"schema": M.PLAN_SCHEMA, "frozen_root": str(FROZEN), "source": FREEZER,
                "files": f["files"], "actual_input_files": f["actual_input_files"],
                "actual_policy": f["actual_policy"], "actual_adoption": f["actual_adoption"],
                "expected_history": {"historical_failed_count": 9, "source_parent_count": 1}}
        plan_raw = M.encoded(plan)
        plan_row = put("HISTORICAL-REFERENCE-MEMBERSHIP.json", plan_raw)
        contract = {"schema": M.CONTRACT_SCHEMA, "state": "ORIGINALS_SUPPLIED_FOR_OFFLINE_VERIFICATION",
                    "frozen_root": str(FROZEN), "freeze": FREEZE, "freezer": FREEZER, "controller": CONTROLLER,
                    "membership_plan": plan_row, "controller_request": {"host": "mac", "executable": "/usr/bin/python3",
                    "args": [FREEZER["path"], "--freeze-reviewed-host-runtime", FREEZER["sha256"]],
                    "idempotency_key": M.OLD_IDEMPOTENCY_KEY}}
        contract_raw = M.encoded(contract); contract_row = put("HISTORICAL-REFERENCE-CONTRACT.json", contract_raw)
        def forbidden_provider(row):
            new_entry_calls.append(row)
            raise AssertionError("historical R10 must be refused before provider")
        try:
            M.verify_new_freeze_with_provider(contract_raw, plan_raw,
                {"NEG-01": "synthetic-unused-negative01", "NEG-02": "synthetic-unused-negative02"}, [],
                read_observed=forbidden_provider, implementation_source=source)
        except ValueError as error:
            M.need("old R10" in str(error) and not new_entry_calls, "old-generation guard must reject before provider")
            report["new_generation_entry_refused_before_provider"] = True
            report["new_generation_provider_calls"] = 0
        else:
            raise AssertionError("old R10 was accepted as new generation")
        c, p = M.validate_contract(contract_raw, plan_raw); rows = M.expected_rows(c, p)
        originals = {}; observations = {"files": {}, "directories": {}}
        for name in sorted(rows):
            raw, seen = read(rows[name]); originals[name] = raw; observations["files"][name] = seen
        dirs = [FROZEN]
        while dirs:
            directory = dirs.pop(); before = directory.lstat()
            M.need(directory.resolve(strict=True) == directory and stat.S_ISDIR(before.st_mode), "actual private canonical directory required")
            names = sorted(os.listdir(directory))
            for name in names:
                member = directory / name; s = member.lstat()
                if stat.S_ISDIR(s.st_mode):
                    dirs.append(member)
                else:
                    M.need(stat.S_ISREG(s.st_mode) and s.st_nlink == 1, "no unknown special frozen entry")
            observations["directories"][str(directory)] = {"before": meta(before), "after": meta(directory.lstat()),
                "names_before": names, "names_after": sorted(os.listdir(directory))}
            M.need(len(observations["directories"]) <= 129, "bounded actual directory census required")
        result = M.verify_freeze_bundle(contract_raw, plan_raw, originals, observations, implementation_source=source)
        for name in sorted(rows):
            raw, seen = read(rows[name])
            M.need(raw == originals[name] and seen == observations["files"][name], "complete actual second read differs")
        for name, seen in observations["directories"].items():
            directory = Path(name)
            M.need(meta(directory.lstat()) == seen["after"] and sorted(os.listdir(directory)) == seen["names_after"],
                   "complete final actual directory bookend differs")
        readset = [{"descriptor": rows[name], "metadata": observations["files"][name]["before"]} for name in sorted(rows)]
        report.update(state="PASS", distinct_original_paths=len(rows), frozen_payload_files=len(f["files"]),
                      original_input_files=len(f["actual_input_files"]), all_originals_read_twice=True,
                      actual_full9_and_complete_tree_bookends=True,
                      readset_sha256=M.pin(M.encoded(readset))["sha256"],
                      historical_contract=contract_row, historical_membership=plan_row,
                      result=result, result_sha256=M.pin(M.encoded(result))["sha256"])
    except BaseException as error:
        report.update(state="FAIL", exception_type=type(error).__name__, detail=str(error), traceback=traceback.format_exc(),
                      new_generation_provider_calls=len(new_entry_calls))
    report.update(count)
    report["elapsed_seconds"] = time.perf_counter() - began
    report_row = put("RESULT.json", M.encoded(report))
    print(json.dumps({"state": report["state"], "report": report_row, "detail": report.get("detail"),
                      "elapsed_seconds": report["elapsed_seconds"], "count": count}, sort_keys=True))
    raise SystemExit(0 if report["state"] == "PASS" else 1)


if __name__ == "__main__":
    main()
