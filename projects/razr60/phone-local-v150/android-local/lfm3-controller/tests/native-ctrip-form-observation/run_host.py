#!/usr/bin/env python3
"""Run both independent complete-census and actual observer contract checks."""
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
def meta(path):
    raw=path.read_bytes();return {"path":str(path),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def main():
    ap=argparse.ArgumentParser()
    for key in ("source","output","java-home","json-jar"):ap.add_argument("--"+key,required=True,type=Path)
    a=ap.parse_args();source=a.source.resolve();out=a.output.absolute();out.mkdir(parents=True,exist_ok=False)
    h=load(source/"tests/observation-diagnostics/run_host.py","ctrip_form_combined_helpers")
    scripts=[HERE/"run_pure_host.py",HERE/"run_observer_host.py",HERE/"run_phone_host.py"];before=[meta(p) for p in scripts+[Path(__file__).resolve()]]
    report={"schema":"hepta.ctrip-form-observation-host.v1","all_pass":False,"stages":[],"source_root":str(source),"scripts_before":before,
        "phone_execution":False,"android_execution":False,"model_executed":False,"business_completion_verified":False}
    try:
        for name,script in zip(("pure","observer","phone"),scripts):
            child=out/name
            argv=[sys.executable,"-B",str(script),"--source",str(source),"--output",str(child),"--java-home",str(a.java_home),"--json-jar",str(a.json_jar)]
            if name=="phone":argv += ["--evidence-cases",str(out/"observer/CASES.json")]
            stage=h.stage(name,argv,out);report["stages"].append(stage)
            if stage["exit_code"]!=0:raise RuntimeError("contract gate failed: "+name)
            result=json.loads((child/"RESULT.json").read_text())
            if result.get("all_pass") is not True:raise RuntimeError("actual child result refused: "+name)
            report[name]={"result":meta(child/"RESULT.json"),"schema":result.get("schema"),"all_pass":True}
        report["all_pass"]=True
    except Exception as e:report["error"]={"type":type(e).__name__,"message":str(e)}
    finally:
        report["scripts_after"]=[meta(p) for p in scripts+[Path(__file__).resolve()]]
        report["scripts_unchanged"]=before==report["scripts_after"];report["all_pass"] &= report["scripts_unchanged"]
        h.save(out/"RESULT.json",report)
    print(json.dumps({"all_pass":report["all_pass"],"error":report.get("error"),"result":meta(out/"RESULT.json")}))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
