#!/usr/bin/env python3
"""Check exact source delivery membership and SHA256, without executing its code."""
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent
manifest = json.loads((root / "SOURCE-MANIFEST.json").read_text())
expected = {entry["path"]: entry for entry in manifest["files"]}
actual = {str(path.relative_to(root)) for path in root.rglob("*")
          if path.is_file() and path.name != "SOURCE-MANIFEST.json"}
if actual != set(expected):
    raise SystemExit("Membership mismatch: " + repr({"missing": sorted(set(expected) - actual),
                                                   "extra": sorted(actual - set(expected))}))
for relative, entry in expected.items():
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise SystemExit("Not a regular source file: " + relative)
    raw = path.read_bytes()
    if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise SystemExit("Content mismatch: " + relative)
tree = hashlib.sha256("".join(entry["sha256"] + "  " + entry["path"] + "\n"
                             for entry in manifest["files"]).encode()).hexdigest()
if tree != manifest["content_tree_sha256"]:
    raise SystemExit("Manifest tree digest mismatch")
print(json.dumps({"files_verified": len(expected), "content_tree_sha256": tree,
                  "source_code_executed": False, "phone_operations": 0}))
