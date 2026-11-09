#!/usr/bin/env python3
"""Verify the complete published source membership and every pinned file hash."""
import hashlib
import json
from pathlib import Path, PurePosixPath
import sys

ROOT=Path(__file__).resolve().parents[1]


def verify(root=ROOT):
    root=Path(root).resolve()
    manifest=json.loads((root/"SOURCE-MANIFEST.json").read_text())
    if manifest.get("schema")!="hepta.local-source.v3":raise RuntimeError("source manifest schema mismatch")
    expected=set()
    for item in manifest["files"]:
        name=item["path"]; relative=PurePosixPath(name)
        if name in expected or relative.is_absolute() or ".." in relative.parts or name=="SOURCE-MANIFEST.json":
            raise RuntimeError("unsafe or duplicate source member")
        expected.add(name)
        path=root/name
        if any(parent.is_symlink() for parent in [path,*path.parents] if parent!=root.parent):
            raise RuntimeError("symlink source member: "+name)
        data=path.read_bytes()
        if len(data)!=item["bytes"] or hashlib.sha256(data).hexdigest()!=item["sha256"]:
            raise RuntimeError("source identity mismatch: "+name)
    actual={str(p.relative_to(root)) for p in root.rglob("*") if p.is_file()
            and p.relative_to(root).parts[0] not in ("out",".git","keys")
            and not ("__pycache__" in p.relative_to(root).parts and p.suffix==".pyc")
            and p!=root/"SOURCE-MANIFEST.json"}
    if actual!=expected:raise RuntimeError("unlisted or missing source members: "+repr(sorted(actual^expected)))
    return {"source_manifest_verified":True,"members":len(expected),"phone_qualified":False}


if __name__=="__main__":
    try:print(json.dumps(verify()))
    except Exception as error:print(str(error),file=sys.stderr);sys.exit(1)
