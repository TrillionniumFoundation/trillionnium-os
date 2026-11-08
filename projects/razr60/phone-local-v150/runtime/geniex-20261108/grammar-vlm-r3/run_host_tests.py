#!/usr/bin/env python3
"""Run actual upstream and candidate method bodies with fake dependencies."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
import time

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--output",type=Path,required=True)
    args=ap.parse_args()
    root=Path(__file__).resolve().parent
    out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
    report={"scope":"host_fake_dependencies_actual_generate_and_finalizer_no_model_claim","cases":[]}
    report["compiler"]=subprocess.run(["g++","--version"],capture_output=True,text=True,check=True).stdout
    with tempfile.TemporaryDirectory(prefix="hepta-vlm-r3-") as temp:
        for name,expected in [("upstream",1),("candidate",0)]:
            exe=Path(temp)/name
            cmd=["g++","-std=c++20","-O2","-Wall","-Wextra","-Wpedantic","-Werror",
                 "-Wno-unused-function","-I",str(root/"tests"),"-I",str(root/name),
                 str(root/"tests/pipeline_error_test.cpp"),"-o",str(exe)]
            built=subprocess.run(cmd,capture_output=True,timeout=60)
            (out/(name+"-compile.stdout")).write_bytes(built.stdout)
            (out/(name+"-compile.stderr")).write_bytes(built.stderr)
            if built.returncode:raise RuntimeError(built.stderr.decode(errors="replace"))
            started=time.monotonic()
            result=subprocess.run([str(exe)],capture_output=True,timeout=10)
            (out/(name+".stdout")).write_bytes(result.stdout)
            (out/(name+".stderr")).write_bytes(result.stderr)
            rows=[json.loads(line) for line in result.stdout.splitlines()]
            if result.returncode!=expected:raise RuntimeError(name+" unexpected exit")
            summary=rows[-1]
            assert summary==({"passed":12,"failed":4} if name=="upstream" else {"passed":16,"failed":0})
            report["cases"].append({"source":name,"expected_exit":expected,"actual_exit":result.returncode,
                                   "seconds":time.monotonic()-started,"tests":rows,
                                   "method_sha256":hashlib.sha256((root/name/"pipeline_generate.inc").read_bytes()).hexdigest()})
    report["all_expected_results_observed"]=True
    (out/"HOST-TESTS.json").write_text(json.dumps(report,indent=2)+"\n")
    print(json.dumps({"report":str(out/"HOST-TESTS.json"),"sha256":hashlib.sha256((out/"HOST-TESTS.json").read_bytes()).hexdigest(),"candidate_tests":16,"upstream_expected_failures":4}))
if __name__=="__main__":main()
