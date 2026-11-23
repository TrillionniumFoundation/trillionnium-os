#!/usr/bin/env python3
"""Exact SDK36 public-Parcel consumer; controlled host IO does NOT qualify Android's serializer/UID."""
import argparse,pathlib,hashlib,json,subprocess,os
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def body(s,start):
 a=s.index(start);b=s.index("{",a);depth=0
 for i in range(b,len(s)):
  if s[i]=="{":depth+=1
  elif s[i]=="}":
   depth-=1
   if depth==0:return s[a:i+1]
 raise RuntimeError("unclosed method")
p=argparse.ArgumentParser();p.add_argument("--source",type=pathlib.Path,required=True);p.add_argument("--output",type=pathlib.Path,required=True);p.add_argument("--java-home",type=pathlib.Path,required=True);a=p.parse_args()
s=a.source.resolve();o=a.output.resolve();j=a.java_home.resolve()
if o.exists() or s==o or s in o.parents:raise RuntimeError("fresh output outside source")
o.mkdir(parents=True);(o/"classes").mkdir();source=s/"src/org/trillionnium/hepta/local/HeptaAccessibilityService.java";raw=source.read_text()
parts=[body(raw,"    private static final class ProfileOwnershipViolation"),body(raw,"    static int actualProfileAccessibilityTaskId(")]
projection=o/"ProfileTaskReader.java";projection.write_text("package org.trillionnium.hepta.local;\nimport android.os.Parcel;import android.graphics.Region;import android.graphics.Rect;import android.view.accessibility.AccessibilityWindowInfo;\nfinal class ProfileTaskReader {\n"+"\n".join(parts)+"\n}\n")
own=s/"tests/profile-observation";inputs=sorted((own/"fixtures").rglob("*.java"))+[own/"ParcelReaderHostTest.java",projection]
env=dict(os.environ)
for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
report={"schema":"hepta.profile-public-parcel-host-validation.v1","all_pass":False,"phone_operations":0,"android_runtime":False,"actual_framework_serialization_tested":False,"production_source_sha256":sha(source),"production_method_sha256":[hashlib.sha256(x.encode()).hexdigest() for x in parts],"input_sha256":{str(p):sha(p) for p in inputs},"stages":[]}
def run(name,argv):
 r=subprocess.run(list(map(str,argv)),capture_output=True,env=env,timeout=60)
 (o/(name+".stdout")).write_bytes(r.stdout);(o/(name+".stderr")).write_bytes(r.stderr);report["stages"].append({"name":name,"exit_code":r.returncode})
 if r.returncode:raise RuntimeError(r.stderr.decode(errors="replace")[-6000:]+r.stdout.decode(errors="replace")[-6000:])
try:
 run("compile",[j/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror","-d",o/"classes",*inputs])
 run("cases",[j/"bin/java","-cp",o/"classes","org.trillionnium.hepta.local.ParcelReaderHostTest",o/"CASES.json"])
 report["cases"]=json.loads((o/"CASES.json").read_text());report["all_pass"]=True
except Exception as e:report["error"]=str(e);raise
finally:
 (o/"HOST-VALIDATION.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
 print(json.dumps({"all_pass":report["all_pass"],"error":report.get("error"),"phone_operations":0,"output":str(o)},ensure_ascii=False))
