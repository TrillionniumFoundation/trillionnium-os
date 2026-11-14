#!/usr/bin/env python3
"""Offline pure owner-goal tests. No Android/provider/task or phone qualification."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

EXPECTED_NAMES = ["generic_flight_is_bound_to_explicit_ctrip","same_owner_different_explicit_package_different_contract","explicit_ctrip_app_matches_selection","explicit_csair_app_matches_selection","leap_day_valid","task_date_is_separate_required_fact","product_model_and_span_exact","product_native_app_literal","product_brand_case_preserves_owner","tool_ceiling_is_immutable_and_not_a_web_tool","recognition_evidence_never_claims_provider_or_completion","binding_rejects_rewritten_owner_and_foreign_package","no_implicit_package","unknown_package","helper_never_native","browser_never_native","explicit_app_mismatch","explicit_website_not_rewritten","date_year_missing","relative_date_not_inferred","invalid_date","year_zero","passengers_missing","additional_passengers","child_count_not_ignored","return_trip_not_inferred","same_city","multiple_city_alternative","multiple_city_conjunction","city_action_payload","extra_purchase_goal","extra_tool_clause_not_silently_removed","leading_space_not_trimmed","trailing_space_not_trimmed","newline_not_removed","nul_not_removed","unpaired_surrogate","prompt_delimiter","product_wrong_app","flight_wrong_app","different_model_not_substituted","ambiguous_product_variant","product_website_not_rewritten","product_purchase_not_price","product_multi_goal","empty_owner","null_owner"]
SOURCE_REL = "src/org/trillionnium/hepta/local/NativeAppGoal.java"
TEST_REL = "tests/native-app-goal/NativeAppGoalHostTest.java"

def info(path):
    p=Path(path)
    if p.is_symlink() or not p.is_file(): raise RuntimeError("regular direct input required: "+str(p))
    raw=p.read_bytes()
    return {"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def write(path, raw):
    with Path(path).open("xb") as f:
        f.write(raw); f.flush(); os.fsync(f.fileno())
    if Path(path).read_bytes()!=raw: raise RuntimeError("readback differs")

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    parser.add_argument("--java-home",type=Path,required=True)
    args=parser.parse_args()
    source=args.source.resolve(strict=True); java_home=args.java_home.resolve(strict=True)
    out=args.output.absolute();out.mkdir(parents=True,exist_ok=False)
    classes=out/"classes";classes.mkdir()
    java=java_home/"bin/java";javac=java_home/"bin/javac"
    paths=[source/SOURCE_REL,source/TEST_REL,Path(__file__).resolve(),java,javac]
    before=[info(p) for p in paths]
    steps=[];result={"schema":"hepta.native-app-goal-host-gate.v1","all_pass":False,
                    "input_before":before,"steps":steps,"provider_tested":False,"phone_tested":False}
    failed=None
    try:
        commands=[
          ("javac",[str(javac),"--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror",
                    "-d",str(classes),str(source/SOURCE_REL),str(source/TEST_REL)]),
          ("java",[str(java),"-Xmx256m","-cp",str(classes),"org.trillionnium.hepta.local.NativeAppGoalHostTest"])]
        for label,argv in commands:
            started=time.time_ns();a=out/(label+".stdout");b=out/(label+".stderr")
            with a.open("xb") as stdout,b.open("xb") as stderr:
                process=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=stdout,stderr=stderr,timeout=60,check=False)
                stdout.flush();stderr.flush();os.fsync(stdout.fileno());os.fsync(stderr.fileno())
            step={"name":label,"argv":argv,"exit_code":process.returncode,"started_unix_ns":started,
                  "elapsed_ms":(time.time_ns()-started)//1000000,"stdout":info(a),"stderr":info(b)}
            steps.append(step)
            if process.returncode!=0:raise RuntimeError(label+" failed")
        cases=json.loads((out/"java.stdout").read_text(encoding="utf-8"))
        if cases.get("schema")!="hepta.native-app-goal-host.v1" or cases.get("all_pass") is not True:
            raise RuntimeError("actual case result schema/pass differs")
        if cases.get("case_names")!=EXPECTED_NAMES or cases.get("cases")!=len(EXPECTED_NAMES) or len(set(EXPECTED_NAMES))!=len(EXPECTED_NAMES):
            raise RuntimeError("case identity differs")
        if type(cases.get("assertions")) is not int or cases["assertions"]<len(EXPECTED_NAMES):
            raise RuntimeError("assertion count invalid")
        raw=(json.dumps(cases,ensure_ascii=False,indent=2)+"\n").encode()
        write(out/"CASES.json",raw);result["cases"]=cases;result["case_receipt"]=info(out/"CASES.json")
        result["all_pass"]=True
    except BaseException as error:
        failed=error;result["error"]=type(error).__name__+": "+str(error)
    finally:
        after=[info(p) for p in paths];result["input_after"]=after;result["inputs_unchanged"]=before==after
        if before!=after:result["all_pass"]=False;result["error"]="inputs changed"
        raw=(json.dumps(result,ensure_ascii=False,indent=2)+"\n").encode()
        write(out/"RESULT.json",raw)
        print(json.dumps({"all_pass":result["all_pass"],"inputs_unchanged":result["inputs_unchanged"],
                          "result":info(out/"RESULT.json"),"cases":result.get("cases")},ensure_ascii=False))
    if failed is not None or not result["all_pass"]:return 1
    return 0

if __name__=="__main__":
    sys.exit(main())
