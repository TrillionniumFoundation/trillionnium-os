"""Replay supplied private originals without executing retained source code."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import platform
import time
import traceback


def sha(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    base = args.base.resolve()
    source = (base / "candidate/retained_r10_failure.py").read_bytes()
    loader_path = base / "candidate/bound_loader.py"
    spec = importlib.util.spec_from_file_location("retained_r10_bound_loader", loader_path)
    loader = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loader)
    module = loader.load(source)
    manifest = (base / "EXPECTED-ORIGINALS.json").read_bytes()
    mapping = json.loads((args.fixture / "LOCAL-FIXTURE-MAP.json").read_bytes())
    originals = {role: (args.fixture / row["local_fixture_file"]).read_bytes() for role, row in mapping.items()}
    before = {role: sha(raw) for role, raw in originals.items()}
    began = time.perf_counter()
    report = {"schema": "hepta.UNADOPTED.retained-r10-private-replay.v1", "implementation": sha(source),
              "bound_loader": sha(loader_path.read_bytes()), "expectation_source": sha(manifest),
              "fixture_originals": before, "fixture_preloaded_immutable_bytes": True,
              "platform": platform.platform(), "python": platform.python_version(),
              "phone_calls": 0, "native_submissions": 0, "runtime_admission": False,
              "production_adopted": False, "private_originals_in_public_report": False}
    try:
        value = module.verify_retained_r10_failure(manifest, originals, implementation_source=source)
        expected_rows = json.loads(manifest)["roles"]
        by_path = {row["path"]: originals[role] for role, row in expected_rows.items()}
        calls = []
        def supplied_reader(row):
            calls.append(row)
            return by_path[row["path"]]
        checked = module.verify_with_reader(manifest, read_pinned=supplied_reader, implementation_source=source)
        assert checked["verified_failure"] == value
        assert len(calls) == checked["provider_calls"] == 26
        after = {role: sha(raw) for role, raw in originals.items()}
        assert after == before
        report.update(state="PASS", result=value, repeated_provider_calls=len(calls),
                      provider_is_preloaded_fixture_not_live_observation=True,
                      complete_result_equal_across_entrypoints=True, supplied_originals_unchanged=True)
    except Exception as error:
        report.update(state="FAIL", exception_type=type(error).__name__, detail=str(error), traceback=traceback.format_exc())
    report["elapsed_seconds"] = time.perf_counter() - began
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as stream:
        stream.write(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + "\n")
    print(json.dumps({"state": report["state"], "report": str(args.report), "implementation": sha(source),
                      "elapsed_seconds": report["elapsed_seconds"], "detail": report.get("detail")}))
    if report["state"] != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
