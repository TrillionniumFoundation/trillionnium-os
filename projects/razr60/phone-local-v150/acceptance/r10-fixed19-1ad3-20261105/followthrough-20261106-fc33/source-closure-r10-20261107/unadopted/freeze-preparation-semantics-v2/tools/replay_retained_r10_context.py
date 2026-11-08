"""Replay the retained R10 context adapter on explicitly supplied private bytes."""
import argparse
import importlib.util
import json
from pathlib import Path
import time


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--retained-base", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    source = (args.base / "candidate/freeze_semantics.py").read_bytes()
    M = load(args.base / "candidate/bound_loader.py", "exact_freeze_loader").load(source, source)
    retained_source = (args.retained_base / "candidate/retained_r10_failure.py").read_bytes()
    retained_loader = (args.retained_base / "candidate/bound_loader.py").read_bytes()
    expectation = (args.retained_base / "EXPECTED-ORIGINALS.json").read_bytes()
    mapping = json.loads((args.fixture / "LOCAL-FIXTURE-MAP.json").read_bytes())
    originals = {role: (args.fixture / row["local_fixture_file"]).read_bytes() for role, row in mapping.items()}
    before = {role: M.pin(raw) for role, raw in originals.items()}
    start = time.perf_counter()
    value = M.verify_retained_r10_context(expectation, originals, reader_source=retained_source,
        loader_source=retained_loader, implementation_source=source)
    original = load(args.retained_base / "candidate/bound_loader.py", "exact_original_R10_loader").load(retained_source)
    expected = original.verify_retained_r10_failure(expectation, originals, implementation_source=retained_source)
    assert value["verified_retained_R10"] == expected
    assert value["implementation"] == M.pin(source)
    assert value["retained_reader_source"] == M.pin(retained_source)
    assert value["retained_loader_source"] == M.pin(retained_loader)
    assert before == {role: M.pin(raw) for role, raw in originals.items()}
    report = {"schema": "hepta.UNADOPTED.freeze-retained-R10-context-real-replay.v1", "state": "PASS",
              "implementation": M.pin(source), "retained_reader": M.pin(retained_source),
              "retained_loader": M.pin(retained_loader), "expectation_source": M.pin(expectation),
              "original_roles": before, "original_roles_verified": len(before),
              "retained_file_count": expected["retained_file_count"],
              "retained_archive_members": expected["archive_members_verified"],
              "full_nested_result_equal_to_actual_bound_reader": True,
              "result_sha256": M.pin(M.encoded(value))["sha256"],
              "originals_unchanged": True, "original_phone_terminal": None,
              "original_phone_stage_writes": None, "global_unknown_effect_count": None,
              "original_nonce_consumed": True, "new_generation_freshness_or_fences_attested": False,
              "runtime_admission": False, "production_adopted": False, "new_phone_calls": 0,
              "new_nonces": 0, "native_case_credit": 0, "elapsed_seconds": time.perf_counter() - start}
    raw = M.encoded(report)
    with args.report.open("xb") as stream:
        stream.write(raw)
    print(json.dumps({"state": report["state"], "report": str(args.report), "report_pin": M.pin(raw),
                      "retained_file_count": report["retained_file_count"], "elapsed_seconds": report["elapsed_seconds"]}))


if __name__ == "__main__":
    main()
