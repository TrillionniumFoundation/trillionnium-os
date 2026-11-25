#!/usr/bin/env python3
"""Portable filled-history regression over real production classes; no Phone."""
import argparse, hashlib, json, os, stat, subprocess, sys, time
from pathlib import Path
sys.dont_write_bytecode=True
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
FIXTURE_SHA="80da80631b77f606f93b412faafd2915a13d2d6dfeeeb57398db05e8cb2525ff"
NAMES=("ObservationCaptureEvidence","NativeCtripFormObservation","NativeActionSnapshotCheck",
 "NativeXiaomiSearchInputObservation","ObservedChildText","ObservedTargetLabels","ObservedScrollActions","ObservedImeEnter")
def ref(p):
 p=Path(p).resolve();s=p.stat();b=p.read_bytes();z=p.stat()
 if (s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise RuntimeError("input changed: "+str(p))
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),mode=stat.S_IMODE(s.st_mode))
def main():
 ap=argparse.ArgumentParser(description=__doc__)
 for key in ("source","output","java-home","json-jar"):ap.add_argument("--"+key,type=Path,required=True)
 a=ap.parse_args();source,out,jdk,jar=[getattr(a,k).resolve() for k in ("source","output","java_home","json_jar")]
 if out.exists() or source==out or source in out.parents:raise RuntimeError("fresh output outside source required")
 out.mkdir(parents=True,mode=0o700);test=source/"tests/native-xiaomi-filled-history"
 fixture=source/"tests/native-xiaomi-query-stability/real-censuses.json"
 paths=[source/("src/org/trillionnium/hepta/local/"+n+".java")for n in NAMES]
 paths += [source/"tests/native-xiaomi-query-stability/NativeXiaomiQueryStabilityHostTest.java",
           source/"tests/native-xiaomi-history-prefix-portable/NativeXiaomiHistoryPrefixPortableTest.java",
           test/"NativeXiaomiFilledHistoryHostTest.java"]
 inputs=paths+[fixture,Path(__file__).resolve(),test/"README.md"]
 tools=[jdk/"bin/java",jdk/"bin/javac",jdk/"lib/modules",jdk/"lib/ct.sym",jar]
 report=dict(schema="hepta.xiaomi-filled-history-public-host-run.v1",all_pass=False,source=str(source),stages=[],
  input_before=[ref(p)for p in inputs],tools_before=[ref(p)for p in tools],phone_operations=0,android_execution=False,
  new_private_device_census_used=False,all_new_history_scenes_synthetic=True,business_success_claimed=False)
 try:
  if ref(jar)["sha256"]!=JSON_SHA or ref(jar)["bytes"]!=78332:raise RuntimeError("fixed org.json required")
  if ref(fixture)["sha256"]!=FIXTURE_SHA:raise RuntimeError("existing public filled fixture must remain exact")
  if any(ref(p)["mode"]!=0o644 for p in [test/"NativeXiaomiFilledHistoryHostTest.java",Path(__file__).resolve(),test/"README.md"]):raise RuntimeError("new source modes must be canonical 0644")
  env=dict(os.environ);env.update(JAVA_HOME=str(jdk),PATH=str(jdk/"bin")+":/usr/bin:/bin",PYTHONDONTWRITEBYTECODE="1")
  for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
  def run(name,argv):
   started=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=180)
   stdout=out/(name+".stdout");stderr=out/(name+".stderr");stdout.write_bytes(p.stdout);stderr.write_bytes(p.stderr)
   report["stages"].append(dict(name=name,argv=list(map(str,argv)),exit_code=p.returncode,elapsed_seconds=time.monotonic()-started,stdout=ref(stdout),stderr=ref(stderr)))
   if p.returncode:raise RuntimeError(name+" failed; original output retained")
  run("jdk-version",[jdk/"bin/javac","-version"])
  if not (out/"jdk-version.stdout").read_text().strip().startswith("javac 17.") and not (out/"jdk-version.stderr").read_text().strip().startswith("javac 17."):raise RuntimeError("JDK17 required")
  classes=out/"classes";classes.mkdir()
  run("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror","-cp",jar,"-d",classes,*paths])
  for name,cls in [("filled-history","NativeXiaomiFilledHistoryHostTest"),("original-filled","NativeXiaomiQueryStabilityHostTest")]:
   dest=out/(name+"-CASES.json")
   run(name,[jdk/"bin/java","-ea","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local."+cls,fixture,dest])
   v=json.loads(dest.read_bytes());names=v["case_names"]
   if not(v["all_pass"] and len(names)==len(set(names))==v["cases"]==len(v["results"]) and all(x["passed"]for x in v["results"])):raise RuntimeError("complete case accounting")
   report[name]=dict(file=ref(dest),cases=v["cases"],assertions=v["assertions"],all_pass=True)
  report["all_pass"]=True
 except Exception as e:report["error"]=type(e).__name__+": "+str(e)
 finally:
  report["input_after"]=[ref(p)for p in inputs];report["tools_after"]=[ref(p)for p in tools]
  report["inputs_unchanged"]=report["input_before"]==report["input_after"];report["tools_unchanged"]=report["tools_before"]==report["tools_after"]
  report["all_pass"] &= report["inputs_unchanged"] and report["tools_unchanged"]
  dest=out/"RESULT.json";dest.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
  print(json.dumps(dict(all_pass=report["all_pass"],error=report.get("error"),result=ref(dest),new=report.get("filled-history"),original=report.get("original-filled"))))
 return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
