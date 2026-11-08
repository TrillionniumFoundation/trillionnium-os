"""Verify only the exact public source delivery and its non-admission ceiling."""
import hashlib
import importlib.util
import json
from pathlib import Path, PurePosixPath


def main():
    root = Path(__file__).resolve().parents[1]
    manifest_path = root / "PORTABLE-DELIVERY-MANIFEST-v2.json"
    manifest = json.loads(manifest_path.read_bytes())
    assert manifest["schema"] == "hepta.UNADOPTED.source-freeze-semantics-public-delivery.v2"
    for key in ("runtime_admission", "production_adopted", "fresh_execution_eligible", "actual_new_generation_freeze_created",
                "new_generation_source_plan_authority_verified", "whole_stage_budget_verified", "production_preparer_implemented"):
        assert manifest[key] is False, key
    assert type(manifest["current_native_case_credit"]) is int and manifest["current_native_case_credit"] == 0
    assert len(manifest["files"]) == manifest["file_count"] == len({r["path"] for r in manifest["files"]})
    assert sum(r["bytes"] for r in manifest["files"]) == manifest["total_bytes"]
    for row in manifest["files"]:
        rel = PurePosixPath(row["path"])
        assert not rel.is_absolute() and str(rel) == row["path"] and ".." not in rel.parts and "\x00" not in row["path"]
        raw = (root / row["path"]).read_bytes()
        assert len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"], row["path"]
    source = (root / "candidate/freeze_semantics.py").read_bytes()
    spec = importlib.util.spec_from_file_location("verified_freeze_bound_loader", root / "candidate/bound_loader.py")
    loader = importlib.util.module_from_spec(spec); spec.loader.exec_module(loader)
    module = loader.load(source, source)
    template_raw = (root / "FUTURE-CONTRACT-UNBOUND.json").read_bytes()
    template = module.strict(template_raw)
    assert template["schema"] == module.CONTRACT_SCHEMA and template["state"] == "UNBOUND"
    assert all(value is None for key, value in template.items() if key not in ("schema", "state"))
    calls = []
    try:
        module.verify_new_freeze_with_provider(template_raw, b"{}", {}, [], read_observed=lambda row: calls.append(row), implementation_source=source)
    except ValueError as error:
        assert "UNBOUND" in str(error) and not calls
    else:
        raise AssertionError("unbound contract reached its provider")
    print(json.dumps({"state": "PASS", "public_members": manifest["file_count"], "implementation": module.pin(source),
                      "unbound_provider_calls": len(calls), "runtime_admission": False, "production_adopted": False}, sort_keys=True))


if __name__ == "__main__":
    main()
