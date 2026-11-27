#!/usr/bin/env python3
"""Whole ce5 Request on current source and strict whole-fd3 behavior counterfactual.
Host-only: complete original byte files; no Phone tools, sockets or App effects.
"""
import argparse,hashlib,json,os,stat,subprocess,sys,time
from pathlib import Path
sys.dont_write_bytecode=True
def ref(p):
 p=Path(p).resolve(strict=True);b=p.read_bytes()
 return dict(path=str(p),bytes=len(b),sha256=hashlib.sha256(b).hexdigest(),mode=stat.S_IMODE(p.stat().st_mode))
def write(p,v):
 with Path(p).open("xb") as f:f.write((json.dumps(v,ensure_ascii=False,sort_keys=True,indent=2)+"\n").encode())
def inventory(root):
 r={}
 for p in sorted(root.rglob("*")):
  if any(v in (".git","__pycache__") for v in p.relative_to(root).parts):continue
  if p.is_symlink():raise RuntimeError("symlink in fixed source")
  if p.is_file():
   v=ref(p);v.pop("path");r[p.relative_to(root).as_posix()]=v
 return r
def stage(name,argv,out,cwd,env):
 started=time.monotonic()
 try:
  p=subprocess.run(argv,cwd=cwd,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=120)
  code,so,se,error=p.returncode,p.stdout,p.stderr,None
 except Exception as e:code,so,se,error=None,b"",repr(e).encode(),repr(e)
 for leaf,data in ((name+".stdout",so),(name+".stderr",se)):
  with (out/leaf).open("xb") as f:f.write(data)
 row=dict(name=name,argv=argv,cwd=str(cwd),exit_code=code,error=error,elapsed_seconds=time.monotonic()-started,stdout=ref(out/(name+".stdout")),stderr=ref(out/(name+".stderr")))
 print(json.dumps({"stage":name,"exit_code":code,"stdout":row["stdout"],"stderr":row["stderr"]}),flush=True)
 return row
def compiled_sources(classes,source,explicit):
 found={}
 exact={}
 for p in explicit:
  import re
  package=re.search(r"(?m)^package ([a-zA-Z0-9_.]+);",p.read_text()).group(1)
  exact[package.replace(".","/")+"/"+p.name]=p
 for p in sorted(classes.rglob("*.class")):
  rel=p.relative_to(classes).as_posix().split("$")[0]
  if rel.endswith(".class"):rel=rel[:-6]
  rel+=".java";q=exact.get(rel,source/"src"/rel)
  if not q.is_file():raise RuntimeError("compiled-source origin missing: "+rel)
  found[str(q)]=ref(q)
 return list(found.values())
def main():
 ap=argparse.ArgumentParser()
 for k in ("source","baseline-source","manifest","original-paths","output","java-home","json-jar"):ap.add_argument("--"+k,required=True,type=Path)
 a=ap.parse_args();source=a.source.resolve();baseline=a.baseline_source.resolve();out=a.output.absolute();out.mkdir(mode=0o700)
 paths=json.loads(a.original_paths.read_bytes());external={k:ref(v) for k,v in paths.items()}
 external["manifest"]=ref(a.manifest);external["paths"]=ref(a.original_paths)
 before=inventory(source);oldbefore=inventory(baseline)
 write(out/"SOURCE-BEFORE.json",before);write(out/"BASELINE-BEFORE.json",oldbefore)
 jdk=a.java_home.resolve();jar=a.json_jar.resolve()
 if ref(jar)["sha256"]!="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed":raise RuntimeError("org.json pin mismatch")
 tool_paths=[jdk/"bin/javac",jdk/"bin/java",jdk/"lib/modules",jdk/"lib/ct.sym",jar,Path(sys.executable),Path(__file__)]
 tools=[ref(p) for p in tool_paths]
 env={k:v for k,v in os.environ.items() if k not in ("JAVA_TOOL_OPTIONS","_JAVA_OPTIONS","JDK_JAVA_OPTIONS","CLASSPATH","PYTHONPATH","PYTHONHOME")}
 env["PYTHONDONTWRITEBYTECODE"]="1"
 stages=[];inputs={};passed=False;error=None
 newtest=source/"tests/public-profile-closing-recovery/PublicProfileClosingRecoveryHostTest.java"
 try:
  for label,root in (("current",source),("whole-fd3",baseline)):
   d=out/label;d.mkdir(mode=0o700);classes=d/"classes";classes.mkdir(mode=0o700)
   explicit=[root/"tests/public-profile-business-recovery/PublicProfileBusinessRecoveryHostTest.java",newtest]
   command=[str(jdk/"bin/javac"),"-J-Xmx512m","--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-proc:none","-cp",str(jar),"-sourcepath",str(root/"src"),"-d",str(classes)]+[str(p) for p in explicit]
   c=stage(label+"-strict",command,d,root,env);stages.append(c)
   if c["exit_code"]!=0:raise RuntimeError(label+" strict compile failed")
   inputs[label]=compiled_sources(classes,root,explicit);write(d/"COMPILER-INPUTS.json",inputs[label])
   run=[str(jdk/"bin/java"),"-Xmx512m","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.background.PublicProfileClosingRecoveryHostTest",str(a.manifest.resolve()),str(a.original_paths.resolve()),str(d/"CASES.json")]
   result=stage(label+"-cases",run,d,root,env);stages.append(result)
   if label=="current":
    if result["exit_code"]!=0:raise RuntimeError("current actual Request/cases failed")
    counts=json.loads((d/"CASES.json").read_bytes())
    if counts["status"]!="PASS" or any(x["status"]!="PASS" for x in counts["rows"]):raise RuntimeError("current case report failed")
   else:
    text=(d/(label+"-cases.stderr")).read_text()
    counts=json.loads((d/"CASES.json").read_bytes())
    if result["exit_code"]!=1 or "AssertionError: actual_ce5_complete_CLOSING_history_must_admit_only_retained_recovery: BUSINESS_LEASE_STATE" not in text:raise RuntimeError("whole fd3 did not fail at actual semantic origin assertion")
    if counts["cases"]!=1 or counts["rows"][0]["name"]!="actual_ce5_complete_originals_enter_retained_request_without_rewriting_failure" or counts["rows"][0]["status"]!="FAIL":raise RuntimeError("counterfactual failure was not first behavior")
  passed=True
 except Exception as e:error=repr(e)
 after=inventory(source);oldafter=inventory(baseline);tools_after=[ref(p) for p in tool_paths]
 external_after={k:ref(v) for k,v in paths.items()};external_after["manifest"]=ref(a.manifest);external_after["paths"]=ref(a.original_paths)
 write(out/"SOURCE-AFTER.json",after);write(out/"BASELINE-AFTER.json",oldafter)
 passed=passed and before==after and oldbefore==oldafter and tools==tools_after and external==external_after
 report=dict(schema="hepta.ce5.closing-recovery-focused.v1",all_pass=passed,error=error,source=str(source),baseline_source=str(baseline),
  source_before=ref(out/"SOURCE-BEFORE.json"),source_after=ref(out/"SOURCE-AFTER.json"),source_unchanged=before==after,
  baseline_before=ref(out/"BASELINE-BEFORE.json"),baseline_after=ref(out/"BASELINE-AFTER.json"),baseline_unchanged=oldbefore==oldafter,
  tools_before=tools,tools_after=tools_after,tools_unchanged=tools==tools_after,external_before=external,external_after=external_after,external_unchanged=external==external_after,
  stages=stages,complete_compile_inputs=inputs,actual_original_bytes_rewritten=False,phone_operations=0,model_runs=0,android_runtime_tested=False,
  socket_or_cleanup_key_read=False,current_absence_proved=False)
 write(out/"RESULT.json",report);print(json.dumps({"all_pass":passed,"error":error,"result":ref(out/"RESULT.json")}),flush=True)
 return 0 if passed else 1
if __name__=="__main__":raise SystemExit(main())
