#!/usr/bin/env python3
"""Compile the actual complete-census reader predicate; execute synthetic boundaries."""
import argparse,hashlib,importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
PKG=Path("src/org/trillionnium/hepta/local")
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
    ap=argparse.ArgumentParser()
    for key in ("source","output","java-home","json-jar"):ap.add_argument("--"+key,required=True,type=Path)
    a=ap.parse_args();source=a.source.resolve();out=a.output.absolute();out.mkdir(parents=True,exist_ok=False)
    h=load(source/"tests/observation-diagnostics/run_host.py","ctrip_form_host_helpers")
    java=a.java_home.resolve()/"bin/java";javac=a.java_home.resolve()/"bin/javac";jar=a.json_jar.resolve()
    tools=[java,javac,java.parent.parent/"lib/modules",java.parent.parent/"lib/ct.sym",jar]
    if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed":raise RuntimeError("JSON pin")
    names=['ObservationCaptureEvidence.java', "NativeCtripFormObservation.java","NativeXiaomiSearchInputObservation.java","NativeActionSnapshotCheck.java","ObservedChildText.java","ObservedTargetLabels.java","ObservedScrollActions.java","ObservedImeEnter.java"]
    paths=[source/PKG/n for n in names]+[source/"tests/native-action-integration/NativeActionSnapshotCheckHostTest.java",HERE/"FormPairHostTest.java",HERE/"ActualCtripRegionHostTest.java"]
    inputs=paths+[Path(__file__).resolve(),source/"tests/observation-diagnostics/run_host.py",HERE/"form-region-nodes.json"]
    before=[h.meta(p) for p in inputs];tool_before=[h.meta(p) for p in tools]
    result={"schema":"hepta.ctrip-form-observation-pure-run.v1","all_pass":False,"stages":[],"input_before":before,"tools_before":tool_before,
        "android_execution":False,"phone_operations":0,"model_executed":False,"business_completion_verified":False}
    try:
        classes=out/"classes";classes.mkdir()
        result["stages"].append(h.stage("compile",[str(javac),"--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror","-cp",str(jar),"-d",str(classes)]+list(map(str,paths)),out))
        if result["stages"][-1]["exit_code"]!=0:raise RuntimeError("compile failed")
        result["stages"].append(h.stage("cases",[str(java),"-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.FormPairHostTest",str(out/"CASES.json")],out))
        if result["stages"][-1]["exit_code"]!=0:raise RuntimeError("cases failed")
        case=json.loads((out/"CASES.json").read_text())
        if case["all_pass"] is not True or case["cases"]!=len(case["case_names"]) or len(set(case["case_names"]))!=case["cases"]:raise RuntimeError("case accounting")
        result["stages"].append(h.stage("actual-region-cases",[str(java),"-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.ActualCtripRegionHostTest",str(HERE/"form-region-nodes.json"),str(out/"REGION-CASES.json")],out))
        if result["stages"][-1]["exit_code"]!=0:raise RuntimeError("actual region cases failed")
        region=json.loads((out/"REGION-CASES.json").read_text())
        if region["all_pass"] is not True or region["cases"]!=len(region["case_names"]):raise RuntimeError("region case accounting")
        result.update(all_pass=True,cases=case,cases_file=h.meta(out/"CASES.json"),region_cases=region,region_cases_file=h.meta(out/"REGION-CASES.json"))
    except Exception as e:result["error"]={"type":type(e).__name__,"message":str(e)}
    finally:
        result["input_after"]=[h.meta(p) for p in inputs];result["tools_after"]=[h.meta(p) for p in tools]
        result["inputs_unchanged"]=before==result["input_after"];result["tools_unchanged"]=tool_before==result["tools_after"]
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"] and result["tools_unchanged"]
        h.save(out/"RESULT.json",result)
    print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"result":h.meta(out/"RESULT.json")}))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
