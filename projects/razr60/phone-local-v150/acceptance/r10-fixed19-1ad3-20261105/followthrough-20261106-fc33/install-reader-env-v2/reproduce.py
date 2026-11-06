#!/usr/bin/env python3
"""Verify this source package, then rerun offline controls in a fresh directory."""
import argparse,hashlib,json,os,runpy,subprocess,sys
from pathlib import Path
ROOT=Path(__file__).resolve().parent
def pin(b):return {"bytes":len(b),"sha256":hashlib.sha256(b).hexdigest()}
def need(x,m):
    if not x:raise ValueError(m)
def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument("--out",type=Path,required=True);a=p.parse_args()
    need(a.out.is_absolute(),"fresh absolute output required")
    manifest=json.loads((ROOT/"PACKAGE-MANIFEST.json").read_bytes())
    selected={}
    for row in manifest["files"]:
        if row["path"].startswith(("source/","references/")) or(row["path"].startswith("validation/")and row["path"].endswith(".py")) or row["path"]=="CANDIDATE-MANIFEST.json":
            name=Path(row["path"]);need(not name.is_absolute()and ".."not in name.parts,"relative retained path")
            raw=(ROOT/name).read_bytes();need(pin(raw)=={k:row[k]for k in ("bytes","sha256")},"retained pin differs "+str(name));selected[name]=raw
    b=runpy.run_path(str(ROOT/"build_candidate.py"))
    facts=json.loads(selected[Path("CANDIDATE-MANIFEST.json")])
    d=json.loads(selected[Path("references/ENVIRONMENT-V2-DERIVATION.original.json")])
    edits=[(r["before"],r["after"])for r in d["reader_changes"]]
    merged=selected[Path("source/verify_install_start_ready_UNBOUND.py")]
    need(b["change"](selected[Path("references/verify_install_start_ready.type-c42ada.py")],edits)==merged,"typed-to-merged inverse")
    need(b["change"](selected[Path("references/verify_install_start_ready.environment-66fe.py")],b["DATA"]["type_changes"])==merged,"environment-to-merged inverse")
    need(pin(merged)==facts["selected"]["reader"],"selected reader")
    a.out.mkdir(mode=0o700)
    for name,raw in selected.items():
        dest=a.out/name;dest.parent.mkdir(mode=0o700,parents=True,exist_ok=True)
        with dest.open("xb")as f:f.write(raw);f.flush();os.fsync(f.fileno())
    run=subprocess.run([sys.executable,"-I","-B",str(a.out/"validation/run_all_merged_controls.py")],capture_output=True,timeout=90)
    sys.stdout.buffer.write(run.stdout);sys.stderr.buffer.write(run.stderr);raise SystemExit(run.returncode)
if __name__=="__main__":main()
