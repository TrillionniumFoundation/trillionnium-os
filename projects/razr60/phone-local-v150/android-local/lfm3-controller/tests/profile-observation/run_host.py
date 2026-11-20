#!/usr/bin/env python3
"""Host-only exact production value/complete-census tests and verbatim cleanup predicate projection."""
import argparse, hashlib, json, os, pathlib, subprocess
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def body(text,start):
 at=text.index(start);brace=text.index("{",at);depth=0
 for end in range(brace,len(text)):
  if text[end]=="{":depth+=1
  elif text[end]=="}":
   depth-=1
   if depth==0:return text[at:end+1]
 raise RuntimeError("unclosed exact production method")
p=argparse.ArgumentParser();p.add_argument("--source",required=True,type=pathlib.Path);p.add_argument("--output",required=True,type=pathlib.Path);p.add_argument("--java-home",required=True,type=pathlib.Path);a=p.parse_args()
s=a.source.resolve();o=a.output.resolve();j=a.java_home.resolve()
if o.exists() or s==o or s in o.parents:raise RuntimeError("fresh output outside source required")
o.mkdir(parents=True);classes=o/"classes";classes.mkdir()
local=s/"src/org/trillionnium/hepta/local";background=s/"src/org/trillionnium/hepta/background"
session=(local/"NativeAppSession.java").read_text()
parts=[body(session,"    static boolean profileCleanupBound("),body(session,"    private static boolean profileNumber(")]
projection=o/"ProfileCleanupProjection.java"
projection.write_text("package org.trillionnium.hepta.local;\nimport java.util.*;\nimport org.trillionnium.hepta.background.*;\n/** Exact production method only; no Controller/Session lifecycle/Android qualification. */\nfinal class ProfileCleanupProjection {\n"+"\n".join(parts)+"\n}\n")
inputs=[background/(name+".java") for name in ("ProfileIdentity","ProfileTarget","WindowOwnership")]
inputs += [local/(name+".java") for name in ("NativeAppEvidence","NativeActionSnapshotCheck","ObservedChildText","ObservedScrollActions","ObservedImeEnter")]
inputs += [s/"tests/native-action-integration/NativeActionSnapshotCheckHostTest.java",s/"tests/profile-observation/ProfileObservationHostTest.java",projection]
pins={str(x):sha(x) for x in inputs}
env=dict(os.environ);env["PATH"]=str(j/"bin")+":"+env.get("PATH","")
for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(key,None)
report={"schema":"hepta.profile-observation-host-validation.v1","all_pass":False,"phone_operations":0,"android_runtime":False,"business_verified":False,"input_sha256":pins,"session_source_sha256":sha(local/"NativeAppSession.java"),"cleanup_projection_sha256":[hashlib.sha256(x.encode()).hexdigest() for x in parts],"stages":[]}
def run(name,argv):
 r=subprocess.run(list(map(str,argv)),capture_output=True,env=env,timeout=120)
 (o/(name+".stdout")).write_bytes(r.stdout);(o/(name+".stderr")).write_bytes(r.stderr)
 report["stages"].append({"name":name,"exit_code":r.returncode,"stdout_sha256":hashlib.sha256(r.stdout).hexdigest(),"stderr_sha256":hashlib.sha256(r.stderr).hexdigest()})
 if r.returncode:raise RuntimeError(name+": "+r.stderr.decode(errors="replace")[-6000:]+r.stdout.decode(errors="replace")[-6000:])
try:
 run("compile",[j/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror","-d",classes,*inputs])
 run("legacy-complete-census",[j/"bin/java","-cp",classes,"org.trillionnium.hepta.local.NativeActionSnapshotCheckHostTest",o/"LEGACY-CASES.json"])
 run("profile-identity-cleanup",[j/"bin/java","-cp",classes,"org.trillionnium.hepta.local.ProfileObservationHostTest",o/"PROFILE-CASES.json"])
 if any(sha(x)!=pins[str(x)] for x in inputs):raise RuntimeError("compile input changed")
 report["all_pass"]=True;report["legacy"]=json.loads((o/"LEGACY-CASES.json").read_text());report["profile"]=json.loads((o/"PROFILE-CASES.json").read_text())
except Exception as e:
 report["error"]=str(e);raise
finally:
 (o/"HOST-VALIDATION.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
 print(json.dumps({"all_pass":report["all_pass"],"error":report.get("error"),"output":str(o),"phone_operations":0},ensure_ascii=False))
