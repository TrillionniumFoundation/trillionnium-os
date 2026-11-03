#!/usr/bin/env python3
"""Materialize pinned vendored inputs from an already obtained llama.cpp source tree.
No network, phone, credentials, or replacement of differing existing files.
"""
import argparse,hashlib,json,os,shutil,stat
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument("--llama-source",type=Path,required=True)
a=p.parse_args()
base=Path(__file__).resolve().parent
source=a.llama_source.resolve(strict=True)
manifest=json.loads((base/"VENDOR-MANIFEST.json").read_bytes())
assert manifest["upstream_commit"]=="8642541b255bfb5dc39cd351a178be09013a55d6"
verified=[]
for row in manifest["files"]:
    rel=Path(row["path"])
    assert not rel.is_absolute() and ".." not in rel.parts
    upstream=Path("vendor/nlohmann/json.hpp") if row["path"]=="vendor/json.hpp" else rel
    src=source/upstream
    assert src.is_file() and not src.is_symlink()
    raw=src.read_bytes()
    assert len(raw)==row["size"] and hashlib.sha256(raw).hexdigest()==row["sha256"],str(rel)
    dest=base/rel
    if dest.exists():
        assert not dest.is_symlink() and dest.read_bytes()==raw,str(dest)
    else:
        dest.parent.mkdir(parents=True,exist_ok=True)
        fd=os.open(dest,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o644)
        with os.fdopen(fd,"wb") as out:out.write(raw)
    verified.append(row)
print(json.dumps({"status":"PINNED_VENDOR_MATERIALIZED","upstream_commit":manifest["upstream_commit"],
                  "count":len(verified),"phone_operations":0,"network_operations":0}))
