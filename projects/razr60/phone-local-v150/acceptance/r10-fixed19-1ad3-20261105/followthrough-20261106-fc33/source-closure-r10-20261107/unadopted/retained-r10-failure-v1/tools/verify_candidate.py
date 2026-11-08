"""Check the sealed public package and the actual source-loader binding."""
import hashlib
import importlib.util
import json
from pathlib import Path

BASE = Path(__file__).resolve().parents[1]
manifest = json.loads((BASE / "PORTABLE-DELIVERY-MANIFEST-v1.json").read_bytes())
assert manifest["production_adopted"] is False and manifest["runtime_admission"] is False
seen = set()
for row in manifest["files"]:
    name = row["path"]
    assert name not in seen and not Path(name).is_absolute() and ".." not in Path(name).parts
    seen.add(name)
    raw = (BASE / name).read_bytes()
    assert len(raw) == row["bytes"] and hashlib.sha256(raw).hexdigest() == row["sha256"], name
assert len(seen) == manifest["file_count"]
loader_path = BASE / "candidate/bound_loader.py"
spec = importlib.util.spec_from_file_location("retained_r10_manifest_bound_loader", loader_path)
loader = importlib.util.module_from_spec(spec)
spec.loader.exec_module(loader)
raw = (BASE / "candidate/retained_r10_failure.py").read_bytes()
module = loader.load(raw)
expectation = (BASE / "EXPECTED-ORIGINALS.json").read_bytes()
assert module.pin(expectation) == module.EXPECTATION_PIN
for name in ("TESTS-REAL-final-r2.json", "TESTS-PORTABLE-final-r2.json", "REAL-REPLAY-final-r2.json"):
    report = json.loads((BASE / "reports" / name).read_bytes())
    assert report["state"] == "PASS" and report["runtime_admission"] is False and report["production_adopted"] is False
    actual = report.get("implementation_sha256") or report["implementation"]["sha256"]
    assert actual == hashlib.sha256(raw).hexdigest(), name
print(json.dumps({"state": "PASS", "file_count": len(seen), "source_sha256": hashlib.sha256(raw).hexdigest(),
                  "private_originals_replayed_by_this_gate": False, "runtime_admission": False}))
