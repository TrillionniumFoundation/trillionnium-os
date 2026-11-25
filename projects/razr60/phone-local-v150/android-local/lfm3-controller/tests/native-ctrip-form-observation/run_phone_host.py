#!/usr/bin/env python3
"""Compile and execute the complete production PhoneObservation pixel constructor."""
import argparse,importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent
PKG=Path("src/org/trillionnium/hepta/local")
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
    ap=argparse.ArgumentParser()
    for key in ("source","output","java-home","json-jar","evidence-cases"):ap.add_argument("--"+key,required=True,type=Path)
    a=ap.parse_args();s=a.source.resolve();out=a.output.absolute();out.mkdir(parents=True,exist_ok=False)
    h=load(s/"tests/observation-diagnostics/run_host.py","form_phone_helper")
    j=a.java_home.resolve();jar=a.json_jar.resolve()
    names=["PhoneObservation","ObservationCaptureEvidence","ObservationState","ObservedWindowMetadata","ImeVisibility","ObservedChildText","ObservedTargetLabels","ObservedScrollActions","ObservedImeEnter","NativeActionSnapshotCheck","NativeCtripFormObservation","NativeXiaomiSearchInputObservation"]
    paths=[s/PKG/(n+".java") for n in names]
    paths += [s/"src/org/trillionnium/hepta/background"/(n+".java") for n in ("ProfileIdentity","ProfileTarget","WindowOwnership")]
    paths += [s/"tests/qualification-scope/fixtures/android/graphics/Rect.java",HERE/"FormCapturePhoneHostTest.java"]
    inputs=paths+[Path(__file__).resolve(),a.evidence_cases.resolve(),s/"tests/observation-diagnostics/run_host.py"]
    tools=[j/"bin/javac",j/"bin/java",j/"lib/modules",j/"lib/ct.sym",jar]
    if jar.stat().st_size!=78332 or h.sha(jar.read_bytes())!="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed":raise RuntimeError("JSON pin")
    before=[h.meta(p) for p in inputs];tb=[h.meta(p) for p in tools]
    result={"schema":"hepta.ctrip-form-actual-phone-consumer-run.v1","all_pass":False,"input_before":before,"tools_before":tb,"stages":[],"phone_operations":0}
    try:
        classes=out/"classes";classes.mkdir()
        commands=[("compile",[str(j/"bin/javac"),"--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror","-cp",str(jar),"-d",str(classes)]+list(map(str,paths))),
                  ("cases",[str(j/"bin/java"),"-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.FormCapturePhoneHostTest",str(a.evidence_cases.resolve()),str(out/"CASES.json")])]
        for name,argv in commands:
            stage=h.stage(name,argv,out);result["stages"].append(stage)
            if stage["exit_code"]:raise RuntimeError(name+" failed")
        cases=json.loads((out/"CASES.json").read_text())
        if cases["all_pass"] is not True or cases["cases"]!=len(cases["case_names"]):raise RuntimeError("case accounting")
        result.update(all_pass=True,cases=cases,cases_file=h.meta(out/"CASES.json"))
    except Exception as e:result["error"]={"type":type(e).__name__,"message":str(e)}
    finally:
        result["input_after"]=[h.meta(p) for p in inputs];result["tools_after"]=[h.meta(p) for p in tools]
        result["inputs_unchanged"]=before==result["input_after"];result["tools_unchanged"]=tb==result["tools_after"]
        result["all_pass"]=result["all_pass"] and result["inputs_unchanged"] and result["tools_unchanged"];h.save(out/"RESULT.json",result)
    print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"result":h.meta(out/"RESULT.json")}))
    return 0 if result["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
