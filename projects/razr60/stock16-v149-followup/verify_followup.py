#!/usr/bin/env python3
"""Verify the follow-up archive without running production or phone code."""
import hashlib
import json
from pathlib import Path, PurePosixPath


root = Path(__file__).resolve().parent
manifest_path = root / "FOLLOWUP-MANIFEST.json"
if manifest_path.is_symlink():
    raise SystemExit("The manifest must be a regular file")
manifest = json.loads(manifest_path.read_text())
expected = {}
for entry in manifest["files"]:
    relative = entry["path"]
    path = PurePosixPath(relative)
    if (not relative or path.is_absolute() or ".." in path.parts
            or "\\" in relative or "\x00" in relative
            or relative == "FOLLOWUP-MANIFEST.json" or relative in expected):
        raise SystemExit("Unsafe or duplicate manifest path: " + repr(relative))
    expected[relative] = entry

actual = {str(path.relative_to(root)) for path in root.rglob("*")
          if path.is_file() and path != manifest_path}
if actual != set(expected):
    raise SystemExit("Membership mismatch: " + repr({
        "missing": sorted(set(expected) - actual),
        "extra": sorted(actual - set(expected)),
    }))

for relative, entry in expected.items():
    path = root / relative
    if path.is_symlink() or not path.is_file():
        raise SystemExit("Not a regular file: " + relative)
    if any(parent.is_symlink() for parent in path.parents if parent != root):
        raise SystemExit("Symlink in file ancestry: " + relative)
    raw = path.read_bytes()
    if len(raw) != entry["bytes"] or hashlib.sha256(raw).hexdigest() != entry["sha256"]:
        raise SystemExit("Content mismatch: " + relative)

tree = hashlib.sha256("".join(
    entry["sha256"] + "  " + entry["path"] + "\n"
    for entry in manifest["files"]
).encode()).hexdigest()
if tree != manifest["content_tree_sha256"]:
    raise SystemExit("Content tree digest mismatch")

frozen = root.parent / "stock16-v149" / "SOURCE-MANIFEST.json"
if not frozen.is_file() or frozen.is_symlink():
    raise SystemExit("The adjacent stock16-v149 frozen source snapshot is required")
frozen_sha = hashlib.sha256(frozen.read_bytes()).hexdigest()
if frozen_sha != manifest["frozen_source_manifest_sha256"]:
    raise SystemExit("Frozen source manifest binding mismatch")

print(json.dumps({
    "followup_files_verified": len(expected),
    "content_tree_sha256": tree,
    "frozen_source_manifest_sha256": frozen_sha,
    "phone_operations": 0,
    "production_code_executed": False,
}))
