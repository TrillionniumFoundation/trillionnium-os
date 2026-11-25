#!/usr/bin/env python3
"""Portable pure-host regression; uses only the existing public pinned fixture."""
import argparse,hashlib,json,os,stat,subprocess,time
from pathlib import Path
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
FIXTURE_SHA="a7680b4a53cc702c98da44439543984a933e67e0193e774df23ff07a8c569644"
NAMES=("ObservationCaptureEvidence","NativeCtripFormObservation","NativeActionSnapshotCheck",
 "NativeXiaomiSearchInputObservation","ObservedChildText","ObservedTargetLabels","ObservedScrollActions","ObservedImeEnter")
def ref(p):
 p=Path(p).resolve();s=p.stat();b=p.read_bytes();z=p.stat()
 if (s.st_size,s.st_mtime_ns,s.st_ctime_ns)!=(z.st_size,z.st_mtime_ns,z.st_ctime_ns):raise RuntimeError("input changed: "+str(p))
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),mode=stat.S_IMODE(s.st_mode))
def main():
 ap=argparse.ArgumentParser()
 for k in ("source","output","java-home","json-jar"):ap.add_argument("--"+k,type=Path,required=True)
 a=ap.parse_args();source,out,jdk,jar=[getattr(a,k).resolve() for k in ("source","output","java_home","json_jar")]
 if out.exists() or source in out.parents:raise RuntimeError("fresh output outside source required")
 out.mkdir(parents=True,mode=0o700)
 test=source/"tests/native-xiaomi-history-prefix-portable"
 fixture=source/"tests/native-xiaomi-search-input/real-censuses.json"
 paths=[source/"src/org/trillionnium/hepta/local"/(n+".java") for n in NAMES]+[test/"NativeXiaomiHistoryPrefixPortableTest.java"]
 inputs=paths+[fixture,Path(__file__).resolve()];tools=[jdk/"bin/java",jdk/"bin/javac",jdk/"lib/modules",jdk/"lib/ct.sym",jar]
 report=dict(schema="hepta.xiaomi-history-prefix-portable-run.v1",all_pass=False,source=str(source),stages=[],
  input_before=[ref(p) for p in inputs],tools_before=[ref(p) for p in tools],all_history_scenes_synthetic=True,
  new_private_device_census_used=False,phone_operations=0,android_execution=False,business_success_claimed=False)
 try:
  if ref(fixture)["sha256"]!=FIXTURE_SHA or ref(jar)["sha256"]!=JSON_SHA:raise RuntimeError("original public fixture/dependency pin required")
  for p in [Path(__file__).resolve(),paths[-1]]:
   if ref(p)["mode"]!=0o644:raise RuntimeError("canonical 0644 source mode required")
  env=dict(os.environ);env.update(JAVA_HOME=str(jdk),PATH=str(jdk/"bin")+":/usr/bin:/bin",PYTHONDONTWRITEBYTECODE="1")
  for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
  classes=out/"classes";classes.mkdir()
  commands=[("jdk-version",[jdk/"bin/javac","-version"]),
   ("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror","-cp",jar,"-d",classes,*paths]),
   ("cases",[jdk/"bin/java","-ea","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeXiaomiHistoryPrefixPortableTest",fixture,out/"CASES.json"])]
  for name,argv in commands:
   start=time.monotonic();p=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=180)
   stdout=out/(name+".stdout");stderr=out/(name+".stderr");stdout.write_bytes(p.stdout);stderr.write_bytes(p.stderr)
   report["stages"].append(dict(name=name,argv=list(map(str,argv)),exit_code=p.returncode,elapsed_seconds=time.monotonic()-start,stdout=ref(stdout),stderr=ref(stderr)))
   if p.returncode:raise RuntimeError(name+" failed; original stdout/stderr retained")
  c=json.loads((out/"CASES.json").read_bytes())
  if not(c["all_pass"] and c["cases"]==len(c["results"])==len(c["case_names"])==len(set(c["case_names"])) and all(r["passed"] for r in c["results"])):raise RuntimeError("complete named case accounting")
  report["all_pass"]=True;report["cases"]=c;report["case_file"]=ref(out/"CASES.json")
 except Exception as e:report["error"]=type(e).__name__+": "+str(e)
 finally:
  report["input_after"]=[ref(p) for p in inputs];report["tools_after"]=[ref(p) for p in tools]
  report["inputs_unchanged"]=report["input_before"]==report["input_after"];report["tools_unchanged"]=report["tools_before"]==report["tools_after"]
  report["all_pass"]&=report["inputs_unchanged"] and report["tools_unchanged"]
  result=out/"RESULT.json";result.write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
  print(json.dumps(dict(all_pass=report["all_pass"],error=report.get("error"),result=ref(result),cases=report.get("cases",{}).get("cases"),assertions=report.get("cases",{}).get("assertions"))))
 return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
