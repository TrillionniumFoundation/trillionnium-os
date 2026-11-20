#!/usr/bin/env python3
"""Real Java-8 profile/result contracts plus independent pinned-template rendering."""
import argparse,hashlib,json,subprocess,sys
from pathlib import Path

def pin(path):
    data=path.read_bytes()
    return {"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--java-home",type=Path,required=True)
    args=parser.parse_args();source=args.source.resolve();out=args.output.resolve();jdk=args.java_home.resolve()
    if source==out or source in out.parents:raise ValueError("new output outside source required")
    out.mkdir(parents=True,exist_ok=False);classes=out/"classes";classes.mkdir()
    pkg=source/"src/org/trillionnium/hepta/local";here=source/"tests/lfm3-vl-profile";fixtures=source/"tests/vlm-contract/fixtures"
    sources=[pkg/(name+".java") for name in ["ModelProfile","LocalRuntimeConfig","VlmPins","VlmResultContract","MobiMindContract","MobiMindPins"]]
    sources += [source/"tests/vlm-contract/VlmResultContractHostTest.java",here/"Lfm3VlProfileHostTest.java"]
    gui=fixtures/"gui-owl-chat-template.jinja";vl=fixtures/"lfm3-vl-chat-template.jinja"
    paths=sources+[gui,vl,fixtures/"LFM3-VL-PROVENANCE.json",here/"check_template.py",Path(__file__).resolve(),jdk/"bin/javac",jdk/"bin/java",jdk/"lib/ct.sym"]
    before={str(p):pin(p) for p in paths}
    report={"schema":"hepta.lfm3vl.host-gate.v1","all_pass":False,"java_release":8,"commands":[],"input_pins":before,
            "phone_operations":0,"android_runtime":False,"model_inference":False,"native_receipts_synthetic":True,"actions_dispatched":False}
    commands=[
        ("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror","-d",classes,*sources]),
        ("existing-gui-contract",[jdk/"bin/java","-cp",classes,"org.trillionnium.hepta.local.VlmResultContractHostTest",gui,out/"GUI-TESTS.json"]),
        ("lfm3vl-profile-contract",[jdk/"bin/java","-cp",classes,"org.trillionnium.hepta.local.Lfm3VlProfileHostTest",gui,vl,out/"LFM3-VL-TESTS.json"]),
        ("lfm3vl-template",[sys.executable,"-B",here/"check_template.py","--template",vl,"--output",out/"template"]),
    ]
    try:
        for name,argv in commands:
            result=subprocess.run([str(a) for a in argv],capture_output=True,timeout=90)
            (out/(name+".stdout")).write_bytes(result.stdout);(out/(name+".stderr")).write_bytes(result.stderr)
            report["commands"].append({"name":name,"argv":[str(a) for a in argv],"exit_code":result.returncode})
            if result.returncode:raise RuntimeError(name+" failed: "+result.stderr.decode("utf-8","replace")[-5000:])
        gui_report=json.loads((out/"GUI-TESTS.json").read_text());vl_report=json.loads((out/"LFM3-VL-TESTS.json").read_text())
        template_report=json.loads((out/"template/RESULT.json").read_text())
        assert gui_report["all_pass"] is True and gui_report["case_count"]==318
        assert vl_report["all_pass"] is True and vl_report["assertions"]>=40
        assert template_report["all_pass"] is True and template_report["case_count"]==5
        report.update(all_pass=True,existing_gui_cases=318,lfm3vl_assertions=vl_report["assertions"],template_cases=5)
    except Exception as error:report["error"]=type(error).__name__+": "+str(error)
    report["inputs_unchanged"]=before=={str(p):pin(p) for p in paths};report["all_pass"] &= report["inputs_unchanged"]
    (out/"RESULT.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({k:report.get(k) for k in ["all_pass","java_release","existing_gui_cases","lfm3vl_assertions","template_cases","inputs_unchanged","error"]}))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
