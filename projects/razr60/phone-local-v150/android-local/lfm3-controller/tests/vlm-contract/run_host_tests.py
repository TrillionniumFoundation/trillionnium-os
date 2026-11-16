#!/usr/bin/env python3
"""Run the full pinned VLM contract cases against actual production Java/native sources."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

def pin(path):
    data=path.read_bytes()
    return {"path":str(path),"bytes":len(data),"sha256":hashlib.sha256(data).hexdigest()}

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--java-home",type=Path,required=True)
    args=parser.parse_args()
    source,out,jdk=args.source.resolve(),args.output.resolve(),args.java_home.resolve()/"bin"
    out.mkdir(parents=True,exist_ok=False)
    here=source/"tests/vlm-contract";support=source/"src/org/trillionnium/hepta/local"
    template=here/"fixtures/gui-owl-chat-template.jinja"
    native=source/"native/vlm-worker/native/vlm-worker.cpp"
    protocol=source/"native/vlm-worker/PROTOCOL.md"
    sources=[support/"VlmResultContract.java",here/"VlmResultContractHostTest.java",
             support/"MobiMindContract.java",support/"MobiMindPins.java"]
    inputs=sources+[template,native,protocol,Path(__file__).resolve()]
    before={str(path):pin(path) for path in inputs}
    report={"schema":"hepta.vlm.result-contract.host-gate.v1","all_pass":False,
            "java_release":8,"input_pins":before,"commands":[],"phone_operations":0,
            "android_runtime":False,"model_inference":False,"actions_dispatched":False,
            "business_completion_verified":False}
    try:
        classes=out/"classes";classes.mkdir()
        commands=[("compile",[str(jdk/"javac"),"--release","8","-d",str(classes)]+[str(p) for p in sources]),
                  ("contract",[str(jdk/"java"),"-cp",str(classes),
                    "org.trillionnium.hepta.local.VlmResultContractHostTest",str(template),str(out/"TESTS.json")])]
        for name,argv in commands:
            result=subprocess.run(argv,capture_output=True,timeout=60)
            (out/(name+".stdout")).write_bytes(result.stdout);(out/(name+".stderr")).write_bytes(result.stderr)
            report["commands"].append({"name":name,"argv":argv,"exit_code":result.returncode})
            if result.returncode:raise RuntimeError(name+" failed: "+result.stderr.decode("utf-8","replace")[-4000:])
        tests=json.loads((out/"TESTS.json").read_text())
        cpp=native.read_text();start=cpp.index("common_json receipt={{");end=cpp.index("std::string raw,error=",start)
        native_keys=set(re.findall(r'\{"([a-z0-9_]+)"\s*,',cpp[start:end]))
        native_keys.update(re.findall(r'receipt\["([a-z0-9_]+)"\]',cpp))
        contract_keys=set(tests["required_receipt_fields"])
        report.update(case_count=tests["case_count"],native_receipt_field_count=len(native_keys),
                      contract_receipt_field_count=len(contract_keys),fields_only_native=sorted(native_keys-contract_keys),
                      fields_only_contract=sorted(contract_keys-native_keys),tests=pin(out/"TESTS.json"))
        assert tests["all_pass"] is True and tests["case_count"]==318,"full original 318-case gate required"
        assert native_keys==contract_keys and len(native_keys)==88,"native and Java receipt fields differ"
        report["all_pass"]=True
    except Exception as error:
        report["error"]=type(error).__name__+": "+str(error)
    finally:
        report["inputs_unchanged"]=before=={str(path):pin(path) for path in inputs}
        report["all_pass"]=report["all_pass"] and report["inputs_unchanged"]
        (out/"RESULT.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({k:report.get(k) for k in ("all_pass","case_count","java_release","native_receipt_field_count","inputs_unchanged","error")}))
    return 0 if report["all_pass"] else 1

if __name__=="__main__":raise SystemExit(main())
