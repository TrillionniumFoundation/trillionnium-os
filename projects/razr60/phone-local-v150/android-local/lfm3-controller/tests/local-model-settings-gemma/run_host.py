#!/usr/bin/env python3
"""Gemma text selection through actual owner-button and settings bodies; host boundaries only."""
import argparse,hashlib,json,os,subprocess,time
from pathlib import Path
def sha(raw): return hashlib.sha256(raw).hexdigest()
def need(value,message):
    if not value: raise RuntimeError(message)
def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for key in ("source","output","java-home","json-jar"): parser.add_argument("--"+key,type=Path,required=True)
    args=parser.parse_args()
    need(all(x.is_absolute() for x in vars(args).values()),"absolute paths required")
    source=args.source.resolve(strict=True);out=args.output
    need(source!=out and source not in out.parents,"output outside source required")
    out.mkdir(parents=True,exist_ok=False)
    inputs={};stages=[];result={"schema":"hepta.local-model-settings-gemma-host-gate.v1","all_pass":False,
        "phone_operations":0,"native_model_executed":False,"positive_backend_qualified":False,
        "actual_owner_button_methods":True,"positive_weight_verification_is_host_boundary":True,"stages":stages}
    def take(path):
        raw=path.read_bytes();inputs[str(path)]={"bytes":len(raw),"sha256":sha(raw)};return raw
    def run(name,argv):
        started=time.monotonic();child=subprocess.run(list(map(str,argv)),cwd=out,capture_output=True,timeout=240)
        (out/(name+".stdout")).write_bytes(child.stdout);(out/(name+".stderr")).write_bytes(child.stderr)
        stages.append({"name":name,"argv":list(map(str,argv)),"exit_code":child.returncode,"elapsed_seconds":time.monotonic()-started})
        need(child.returncode==0,name+" failed");return child.stdout
    try:
        take(Path(__file__).resolve())
        take(source/"tests/local-model-settings-visual/VisualSettingsHostTest.java")
        take(source/"src/org/trillionnium/hepta/local/MainActivity.java")
        take(source/"src/org/trillionnium/hepta/local/RuntimeConfigTransaction.java")
        take(source/"src/org/trillionnium/hepta/local/LocalModelImportAsset.java")
        original=source/"tests/local-model-settings-qwen/run_host.py";take(original)
        run("existing-settings",["/usr/bin/python3","-B",original,"--source",source,"--output",out/"existing-settings",
            "--java-home",args.java_home,"--json-jar",args.json_jar])
        base=json.loads((out/"existing-settings/RESULT.json").read_text())
        need(base["all_pass"] and base["inputs_unchanged"],"existing settings cases must pass")
        need(base["cases"]["cases"]==5,"all existing Qwen cases retained after the complete visual and base settings gates")
        for path in base["source_inputs"]: take(Path(path))
        run("gemma-cases",[args.java_home/"bin/java","-Dhepta.fixture.host_uid="+str(os.getuid()),"-cp",
            str(out/"existing-settings/existing-settings/classes")+os.pathsep+str(args.json_jar),
            "org.trillionnium.hepta.local.VisualSettingsHostTest",out/"gemma-cases","--gemma-text"])
        raw=(out/"gemma-cases/RESULT.json").read_bytes();cases=json.loads(raw)
        expected=["ordinary-gemma-e2b-text-choice-npu","ordinary-gemma-e2b-text-choice-gpu",
            "ordinary-gemma-e4b-text-choice-npu","ordinary-gemma-e4b-text-choice-gpu",
            "gemma-exact-pins-and-configuration-only-receipts","gemma-entry-retains-closed-text-allowlist",
            "gemma-e2b-real-engine-memory-and-size-refusals","gemma-e4b-real-engine-memory-and-size-refusals"]
        need(cases["passed"] and cases["schema"]=="hepta.local-model-settings-gemma-cases.v1","Gemma cases failed")
        need(cases["cases"]==8 and [r["name"] for r in cases["case_results"]]==expected,"complete exact Gemma cases")
        need(all(r["passed"] for r in cases["case_results"]),"one Gemma case failed")
        need(sum(r["assertions"] for r in cases["case_results"])==cases["assertions"],"assertion accounting differs")
        need(cases["phone_operations"]==0 and not cases["native_model_executed"] and not cases["positive_backend_qualified"],"host scope differs")
        result.update(all_pass=True,cases=cases,case_result={"path":str(out/"gemma-cases/RESULT.json"),"bytes":len(raw),"sha256":sha(raw)},
            original_settings_result=str(out/"existing-settings/RESULT.json"))
    except Exception as error: result["error"]=type(error).__name__+": "+str(error)
    result["source_inputs"]=inputs
    result["inputs_unchanged"]=all(sha(Path(path).read_bytes())==r["sha256"] for path,r in inputs.items())
    result["all_pass"]=result["all_pass"] and result["inputs_unchanged"]
    raw=(json.dumps(result,ensure_ascii=False,indent=2)+"\n").encode();(out/"RESULT.json").write_bytes(raw)
    print(json.dumps({"all_pass":result["all_pass"],"error":result.get("error"),"result":str(out/"RESULT.json"),"sha256":sha(raw)}))
    return 0 if result["all_pass"] else 1
if __name__=="__main__": raise SystemExit(main())
