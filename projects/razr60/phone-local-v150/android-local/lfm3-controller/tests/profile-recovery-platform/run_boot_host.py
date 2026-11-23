#!/usr/bin/env python3
"""Host-only pure Java owner tests; never invokes Android tools or default cmd."""
from pathlib import Path
import argparse, hashlib, json, subprocess, time
p=argparse.ArgumentParser()
p.add_argument("--out", required=True)
p.add_argument("--source-root",type=Path,default=Path(__file__).resolve().parents[2])
p.add_argument("--jdk-bin",type=Path,required=True,help="Host JDK bin containing javac/java")
p.add_argument("--compile-only",action="store_true",help="Packaging compile only; no Java test execution")
a=p.parse_args()
root=a.source_root.resolve();tests=Path(__file__).resolve().parent
out=Path(a.out).resolve()
out.mkdir(parents=True,exist_ok=False)
classes=out/"classes";classes.mkdir()
jdk=a.jdk_bin.resolve()
sources=[root/"src/org/trillionnium/hepta/background/ProfileRecoveryBootCount.java",tests/"ProfileRecoveryBootCountHostTest.java"]
def sha(path): return hashlib.sha256(path.read_bytes()).hexdigest()
result={"schema":"hepta.boot-count-owner-host-run.v1","phone_contacted":False,"android_runtime":False,"tests_executed":not a.compile_only,
        "sources":[{"path":str(s),"sha256":sha(s)} for s in sources],"commands":[]}
commands=[
    ("compile",[str(jdk/"javac"),"--release","8","-Xlint:all,-options","-Werror","-proc:none","-d",str(classes)]+[str(s) for s in sources],30),
    ("test",[str(jdk/"java"),"-cp",str(classes),"org.trillionnium.hepta.background.ProfileRecoveryBootCountHostTest"],15)]
if a.compile_only:commands=commands[:1]
for name,cmd,limit in commands:
    begun=time.monotonic()
    run=subprocess.run(cmd,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=limit,check=False)
    (out/(name+".stdout")).write_bytes(run.stdout);(out/(name+".stderr")).write_bytes(run.stderr)
    result["commands"].append({"stage":name,"argv":cmd,"exit_code":run.returncode,"elapsed_s":round(time.monotonic()-begun,6),
       "stdout_sha256":sha(out/(name+".stdout")),"stderr_sha256":sha(out/(name+".stderr"))})
    if run.returncode:
        result["passed"]=False;break
    if name=="test":result["test"]=json.loads(run.stdout)
else:result["passed"]=True
receipt=out/"RESULT.json";receipt.write_text(json.dumps(result,indent=2,ensure_ascii=False)+"\n")
print(json.dumps({"result":str(receipt),"sha256":sha(receipt),"passed":result["passed"],"test":result.get("test")}))
raise SystemExit(0 if result["passed"] else 1)
