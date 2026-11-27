#!/usr/bin/env python3
"""Actual complete BackgroundSession.close with unchanged original host IO fixture."""
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
sys.dont_write_bytecode=True
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def main():
 ap=argparse.ArgumentParser()
 for k in ("source","baseline-source","output","java-home"):ap.add_argument("--"+k,required=True,type=Path)
 a=ap.parse_args();src=a.source.resolve();base=a.baseline_source.resolve();out=a.output.absolute();out.mkdir(mode=0o700)
 common=load("closing_current_reporting",src/"tests/public-profile-closing-recovery/run_host.py")
 before=common.inventory(src);old_before=common.inventory(base)
 common.write(out/"SOURCE-BEFORE.json",before);common.write(out/"BASELINE-BEFORE.json",old_before)
 java=Path(__file__).with_name("ClosingBackgroundSessionHostTest.java").resolve()
 toolpaths=[a.java_home/"bin/javac",a.java_home/"bin/java",a.java_home/"lib/modules",a.java_home/"lib/ct.sym",Path(sys.executable),Path(__file__),java,src/"tests/public-profile-closing-recovery/run_host.py"]
 tools=[common.ref(p) for p in toolpaths]
 env={k:v for k,v in os.environ.items() if k not in ("JAVA_TOOL_OPTIONS","_JAVA_OPTIONS","JDK_JAVA_OPTIONS","CLASSPATH","PYTHONPATH","PYTHONHOME")};env["PYTHONDONTWRITEBYTECODE"]="1"
 stages=[];closures={};error=None;passed=False
 try:
  for label,source in (("current",src),("whole-fd3",base)):
   d=out/label;d.mkdir(mode=0o700)
   helper=source/"tests/background-session/prepare_fixture.py"
   generator=load("closing_background_"+label.replace("-","_"),helper)
   files,derivation=generator.prepare(source,d/"fixture")
   legacy=source/"tests/native-app/legacy-boundary/prepare_search_pure.py"
   files=load("closing_legacy_"+label.replace("-","_"),legacy).add(source,files)
   files+= [source/"tests/background-session/BackgroundSessionHostTest.java",java]
   files=list(dict.fromkeys(files))
   records=[common.ref(p) for p in files]
   if not any(p.resolve()==(source/"src/org/trillionnium/hepta/local/BackgroundSession.java").resolve() for p in files):
    raise RuntimeError("actual whole BackgroundSession missing from compiler inputs")
   classes=d/"classes";classes.mkdir(mode=0o700)
   compile=[str(a.java_home/"bin/javac"),"-J-Xmx512m","--release","8","-encoding","UTF-8","-Xlint:all,-options","-Werror","-proc:none","-d",str(classes)]+list(map(str,files))
   c=common.stage(label+"-strict",compile,d,source,env);stages.append(c)
   closures[label]=dict(inputs_before=records,generators=[common.ref(helper),common.ref(legacy)],derivation=derivation)
   if c["exit_code"]!=0:raise RuntimeError(label+" strict compile failed")
   run=[str(a.java_home/"bin/java"),"-Xmx512m","-cp",str(classes),"org.trillionnium.hepta.local.ClosingBackgroundSessionHostTest",str(d/"CASES.json")]
   r=common.stage(label+"-cases",run,d,source,env);stages.append(r)
   records_after=[common.ref(p) for p in files];closures[label]["inputs_after"]=records_after
   if records_after!=records:raise RuntimeError(label+" compiled input changed")
   result=json.loads((d/"CASES.json").read_bytes())
   if label=="current":
    if r["exit_code"]!=0 or result["status"]!="PASS":raise RuntimeError("current close cases failed")
   else:
    stderr=Path(r["stderr"]["path"]).read_text()
    if r["exit_code"]!=1 or "AssertionError: actual_nonexception_CLOSING_close_must_save_UNKNOWN" not in stderr or result["cases"]!=1:
     raise RuntimeError("whole fd3 did not reject first actual close behavior")
  passed=True
 except Exception as e:error=repr(e)
 after=common.inventory(src);old_after=common.inventory(base);tools_after=[common.ref(p) for p in toolpaths]
 common.write(out/"SOURCE-AFTER.json",after);common.write(out/"BASELINE-AFTER.json",old_after)
 passed=passed and before==after and old_before==old_after and tools==tools_after
 report=dict(schema="hepta.ce5.closing-lifecycle-host.v1",all_pass=passed,error=error,stages=stages,closures=closures,
  source=str(src),baseline_source=str(base),source_before=common.ref(out/"SOURCE-BEFORE.json"),source_after=common.ref(out/"SOURCE-AFTER.json"),
  baseline_before=common.ref(out/"BASELINE-BEFORE.json"),baseline_after=common.ref(out/"BASELINE-AFTER.json"),
  source_unchanged=before==after,baseline_unchanged=old_before==old_after,tools_before=tools,tools_after=tools_after,tools_unchanged=tools==tools_after,
  complete_actual_BackgroundSession=True,Android_io_is_host_boundary=True,actual_retained_socket=False,phone_operations=0)
 common.write(out/"RESULT.json",report);print(json.dumps({"all_pass":passed,"error":error,"result":common.ref(out/"RESULT.json")}),flush=True)
 return 0 if passed else 1
if __name__=="__main__":raise SystemExit(main())
