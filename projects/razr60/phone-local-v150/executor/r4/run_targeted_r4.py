#!/usr/bin/env python3
"""Build and run only the r4 restart-of-unknown regression in a new Linux output directory."""
import argparse,hashlib,json,os,shutil,subprocess,sys
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument("--out",type=Path,required=True)
p.add_argument("--cc",default="gcc")
p.add_argument("--cxx",default="g++")
a=p.parse_args()
assert sys.platform=="linux","Linux host fixture only; this is not an Android binary"
base=Path(__file__).resolve().parent
out=a.out.resolve();out.mkdir(parents=True,exist_ok=False)
for name in ["phone_tool_sidecar.cpp","tool_client.py","targeted_r4_fixture.py"]:
    shutil.copyfile(base/name,out/name)
manifest=json.loads((base/"VENDOR-MANIFEST.json").read_bytes())
for row in manifest["files"]:
    src=base/row["path"];raw=src.read_bytes()
    assert len(raw)==row["size"] and hashlib.sha256(raw).hexdigest()==row["sha256"],row["path"]
    dst=out/row["path"];dst.parent.mkdir(parents=True,exist_ok=True);dst.write_bytes(raw)
commands=[
[a.cc,"-O2","-c",str(out/"vendor/hash/sha256/sha256.c"),"-I"+str(out/"vendor/hash"),"-o",str(out/"sha256.o")],
[a.cxx,"-std=c++17","-O2","-pthread","-DHEPTA_TESTING=1","-I"+str(out/"vendor"),
 str(out/"phone_tool_sidecar.cpp"),str(out/"vendor/hash/hash.cpp"),str(out/"sha256.o"),
 "-o",str(out/"sidecar-native-fixture")],
[sys.executable,"-B",str(out/"targeted_r4_fixture.py")],
]
results=[]
for i,cmd in enumerate(commands):
    result=subprocess.run(cmd,capture_output=True,timeout=120 if i<2 else 30)
    (out/("step-%d.stdout"%i)).write_bytes(result.stdout)
    (out/("step-%d.stderr"%i)).write_bytes(result.stderr)
    results.append({"argv":cmd,"returncode":result.returncode})
    if result.returncode:break
summary={"status":"PASS" if len(results)==3 and all(x["returncode"]==0 for x in results) else "FAIL",
         "scope":"Linux synthetic r4 sealed-unknown restart only","phone_operations":0,
         "native_r5_task_or_tool_protocol":False,"model_requests":0,"steps":results}
(out/"REPRODUCTION-RESULT.json").write_text(json.dumps(summary,indent=2)+"\n")
print(json.dumps(summary))
raise SystemExit(0 if summary["status"]=="PASS" else 1)
