#!/usr/bin/env python3
"""Actual full Controller prompt + produced GBNF regression; host only."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import traceback

def sha(raw):return hashlib.sha256(raw).hexdigest()
def ref(path):
    raw=Path(path).read_bytes()
    return {"path":str(path),"bytes":len(raw),"sha256":sha(raw)}
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def inventory(source):
    return {str(p.relative_to(source)):{"bytes":p.stat().st_size,"sha256":sha(p.read_bytes()),"mode":p.stat().st_mode&0o777}
            for p in sorted(source.rglob("*")) if p.is_file()}
def main():
    p=argparse.ArgumentParser()
    p.add_argument("--source",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True)
    p.add_argument("--baseline-source",type=Path)
    p.add_argument("--java-home",type=Path)
    a=p.parse_args()
    source=a.source.resolve();out=a.output.resolve();out.mkdir(parents=True,exist_ok=False)
    java=str(a.java_home/"bin/java") if a.java_home else os.environ.get("HEPTA_TEST_JAVA") or shutil.which("java")
    javac=str(a.java_home/"bin/javac") if a.java_home else os.environ.get("HEPTA_TEST_JAVAC") or shutil.which("javac")
    if not java:raise RuntimeError("existing JDK required; never install one")
    compiler=[javac] if javac and Path(javac).exists() else [java,"-m","jdk.compiler/com.sun.tools.javac.Main"]
    env=dict(os.environ,PYTHONDONTWRITEBYTECODE="1",HEPTA_TEST_JAVA=java)
    if javac:env["HEPTA_TEST_JAVAC"]=javac
    env["PATH"]=str(Path(java).parent)+os.pathsep+env.get("PATH","")
    before=inventory(source);base=a.baseline_source.resolve() if a.baseline_source else None
    baseline_before=inventory(base) if base else None
    report={"schema":"hepta.case05-lfm25-compact-grammar-targeted.v1","all_pass":False,
            "source":str(source),"baseline_source":str(base) if base else None,"stages":[],
            "source_inputs_unchanged":False,"baseline_source_unchanged":False if base else None,
            "phone_operations":0,"native_inference":False,"business_completion_verified":False}
    (out/"SOURCE-INPUTS.json").write_text(json.dumps(before,indent=2,sort_keys=True)+"\n")
    if base:(out/"BASELINE-INPUTS.json").write_text(json.dumps(baseline_before,indent=2,sort_keys=True)+"\n")
    def run(name,argv,limit=120):
        start=time.monotonic();cp=subprocess.run([str(x) for x in argv],capture_output=True,env=env,timeout=limit)
        stdout=out/(name+".stdout");stderr=out/(name+".stderr")
        stdout.write_bytes(cp.stdout);stderr.write_bytes(cp.stderr)
        row={"name":name,"argv":[str(x) for x in argv],"exit_code":cp.returncode,
             "elapsed_seconds":time.monotonic()-start,"stdout":ref(stdout),"stderr":ref(stderr),"passed":cp.returncode==0}
        report["stages"].append(row);print(json.dumps({"stage":name,"exit_code":cp.returncode}),flush=True)
        if cp.returncode:raise RuntimeError(name+" failed; original output retained")
    def export(which,src,mode):
        where=out/which;where.mkdir()
        prep=module(src/"tests/exact-admission/prepare_fixture.py","actual_prompt_"+which)
        files,extraction=prep.prepare(src,where/"fixture")
        files+=sorted((src/"tests/exact-admission").rglob("*.java"))
        files+=[source/"tests/moe-compact-grammar/CompactGrammarHostTest.java"]
        pins=[ref(f) for f in files]
        (where/"COMPILE-INPUTS.json").write_text(json.dumps(pins,indent=2)+"\n")
        classes=where/"classes";classes.mkdir()
        run(which+"-compile",compiler+["--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-d",classes,*files])
        generated=where/"generated"
        run(which+"-actual-controller",[java,"-cp",classes,"org.trillionnium.hepta.local.CompactGrammarHostTest",
                generated,mode,source/"tests/moe-compact-grammar/fixtures/case05-partial.txt"])
        for pin in pins:
            if ref(Path(pin["path"]))!=pin:raise RuntimeError("compile input changed")
        return generated
    try:
        # This is the unchanged original test method plus the append-only
        # integrated compact gate. All prior commands and assertions still run.
        run("original-integrated-exact-admission",[sys.executable,"-B",source/"tools/test_exact_admission.py"])
        candidate=export("candidate",source,"candidate")
        previous=export("frozen-baseline",base,"baseline-export") if base else None
        argv=[sys.executable,"-B",source/"tests/moe-compact-grammar/test_compact_grammar.py",
              "--source",source,"--generated",candidate,"--raw",source/"tests/moe-compact-grammar/fixtures/case05-partial.txt"]
        if previous:argv+=["--baseline",previous]
        run("actual-gbnf-consumer",argv)
        run("original-owner-grammar",[sys.executable,"-B",source/"tests/owner-grammar/run_host_tests.py",
            "--source",source,"--output",out/"owner-grammar","--release8"])
        report["all_pass"]=True
    except Exception as error:
        report["error"]=str(error);(out/"ERROR.txt").write_text(traceback.format_exc())
    report["source_inputs_unchanged"]=inventory(source)==before
    report["baseline_source_unchanged"]=inventory(base)==baseline_before if base else None
    report["all_pass"]=report["all_pass"] and report["source_inputs_unchanged"] and (base is None or report["baseline_source_unchanged"])
    report["source_input_receipt"]=ref(out/"SOURCE-INPUTS.json")
    if base:report["baseline_input_receipt"]=ref(out/"BASELINE-INPUTS.json")
    (out/"RESULT.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"all_pass":report["all_pass"],"result":ref(out/"RESULT.json")}),flush=True)
    return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
