#!/usr/bin/env python3
"""Actual Session/Offer/Attempt and GBNF host focus; no phone or model."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.dont_write_bytecode=True
EXPECTED_CASES=['actual_background_native_session_offer_chain', 'real_offer_emits_separate_grammar_and_actual_parsers', 'owner_click_deny_cannot_be_bypassed_by_derived_search_intent', 'same_authorization_value_different_actual_gate_is_rejected', 'same_value_different_selection_cannot_bind_background', 'second_session_and_controller_cannot_replace_bound_session', 'foreign_actual_offer_cannot_move_to_another_session', 'foreign_planning_binding_cannot_mint_an_offer', 'unpublished_planning_never_enters_offer', 'aged_planning_never_refreshes_offer_clock', 'one_offer_only_per_actual_session', 'retired_gate_rejects_existing_offer_grammar', 'retired_session_rejects_existing_offer_grammar', 'expired_session_rejects_new_reservation', 'wrong_observation_or_role_intent_is_rejected', 'typed_navigation_deadline_cannot_exceed_24_seconds', 'reservation_consumes_offer_before_any_effect', 'journal_failure_does_not_restore_offer_or_retry', 'claim_without_current_complete_cd_is_rejected', 'actual_installed_verifier_is_rechecked', 'current_cd_is_bound_to_original_offer_and_identity', 'current_cd_cannot_precede_attempt', 'changed_current_search_role_is_rejected', 'current_complete_cd_allows_one_claim_only', 'second_revalidation_cannot_replace_original_cd', 'closed_or_retired_attempt_never_becomes_live_again', 'late_attempt_cannot_claim_or_extend_deadline', 'unclaimed_outcome_cannot_create_navigation_proof', 'retired_callback_and_missing_effect_return_are_rejected', 'effect_receipt_requires_current_same_run_identity', 'accepted_effect_still_requires_new_provider_observation', 'provider_frame_before_effect_cannot_close_navigation', 'incomplete_provider_frame_cannot_close_navigation', 'recorded_8436_login_exposes_only_return_without_query', 'recorded_8436_login_rejects_missing_phone_return_and_foreign', 'returned_home_after_wide_search_stops_price_and_budget', 'later_login_or_changed_page_cannot_inherit_wide_home_message', 'fresh_input_after_explicit_login_return_allows_query', 'fresh_actual_provider_contract_handoff_is_navigation_only']

def sha(raw):
    return hashlib.sha256(raw).hexdigest()

def record(path):
    p=Path(path).resolve();raw=p.read_bytes()
    return {"path":str(p),"bytes":len(raw),"sha256":sha(raw)}

def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","java-home","json-jar"):
        parser.add_argument("--"+name,type=Path,required=True)
    args=parser.parse_args();source=args.source.resolve();out=args.output.resolve();jdk=args.java_home.resolve();jar=args.json_jar.resolve()
    if out.exists() or source in out.parents:
        raise RuntimeError("fresh separate output required")
    out.mkdir(mode=0o700,parents=True)
    closure_path=source/"tests/native-search-planning/host_closure.py"
    closure=module(closure_path,"actual_native_search_session_closure")
    if sha(jar.read_bytes())!=closure.JSON_SHA:
        raise RuntimeError("actual pinned org.json jar required")
    host=source/"tests/native-search-session/NativeSearchSessionHostTest.java"
    grammar_host=source/"tests/native-search-grammar/NativeSearchGrammarHostTest.java"
    grammar_test=source/"tests/native-search-grammar/test_native_search_grammar.py"
    recognizer=source/"tests/action-grammar/gbnf_recognizer.py"
    planning_contract=source/"tests/native-search-planning/NativeSearchPlanningContractHostTest.java"
    paths,provenance=closure.prepare(source,out/"closure",(host,grammar_host,planning_contract))
    original_paths=list(dict.fromkeys([Path(e["path"]) for e in provenance["production_inputs"]]+
                                      [Path(__file__).resolve(),host.with_name("8436-retained-login.json"),source/"tests/native-search-producer/6bea-search-icon-censuses.json",grammar_test,recognizer]))
    originals=[record(p) for p in original_paths]
    tools=[jdk/"bin/javac",jdk/"bin/java",jdk/"lib/modules",jar]
    tools_before=[record(p) for p in tools]
    report={"schema":"hepta.native-search-session-focus.v1","all_pass":False,"source":str(source),"scope":"host_only",
            "closure":provenance,"source_inputs_before":originals,"tools_before":tools_before,"stages":[],
            "phone_actions":0,"android_producer_tested":False,"native_grammar_engine_tested":False,
            "model_inference_tested":False,"business_verified":False,"started_host_wall_ms":int(time.time()*1000)}
    env=dict(os.environ);env["PATH"]=str(jdk/"bin")+":/usr/bin:/bin";env["PYTHONDONTWRITEBYTECODE"]="1"
    for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):
        env.pop(key,None)
    classes=out/"classes";classes.mkdir()
    commands=[
      ("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror",
                  "-classpath",jar,"-d",classes,*paths]),
      ("session",[jdk/"bin/java","-Dhepta.test.recordedLogin="+str(host.with_name("8436-retained-login.json")),"-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.NativeSearchSessionHostTest",
                  out/"CASES.json",out/"work",out/"grammar"]),
      ("grammar",[sys.executable,"-B",grammar_test,"--fixtures",out/"grammar","--recognizer",recognizer,"--out",out/"gbnf"])]
    try:
        for name,argv in commands:
            started=time.monotonic();completed=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=120,check=False)
            (out/(name+".stdout")).write_bytes(completed.stdout);(out/(name+".stderr")).write_bytes(completed.stderr)
            report["stages"].append({"name":name,"argv":list(map(str,argv)),"exit_code":completed.returncode,
                    "elapsed_seconds":time.monotonic()-started,"stdout_sha256":sha(completed.stdout),"stderr_sha256":sha(completed.stderr)})
            if completed.returncode:
                raise RuntimeError("stage failed: "+name)
        cases=json.loads((out/"CASES.json").read_text())
        if not(cases["all_pass"] is True and cases["cases"]==len(EXPECTED_CASES) and cases["case_names"]==EXPECTED_CASES):
            raise RuntimeError("exact declared Session case matrix differs")
        grammar=json.loads((out/"gbnf/RESULT.json").read_text())
        if not grammar["all_pass"]:
            raise RuntimeError("actual emitted GBNF failed independent recognition")
        planning=json.loads((out/"PLANNING-CONTRACT.json").read_text())
        if not(planning["all_pass"] is True and planning["cases"]==31):
            raise RuntimeError("actual planning contract probe matrix differs")
        report["planning_contract"]={"result":record(out/"PLANNING-CONTRACT.json"),"cases":planning["cases"],"assertions":planning["assertions"]}
        report["cases"]=cases
        report["grammar"]={"result":record(out/"gbnf/RESULT.json"),"vectors":grammar["vectors"],
                            "java_fixture":grammar["java_fixture"],"inputs_unchanged":grammar["input_bytes_unchanged"]}
        report["all_pass"]=True
    except Exception as error:
        report["error"]=type(error).__name__+": "+str(error)
        if (out/"CASES.json").is_file():
            report["cases"]=json.loads((out/"CASES.json").read_text())
    finally:
        report["source_inputs_after"]=[record(p) for p in original_paths]
        report["source_inputs_unchanged"]=report["source_inputs_after"]==originals
        report["tools_after"]=[record(p) for p in tools]
        report["tools_unchanged"]=report["tools_after"]==tools_before
        report["all_pass"]=report["all_pass"] and report["source_inputs_unchanged"] and report["tools_unchanged"]
        report["finished_host_wall_ms"]=int(time.time()*1000)
        (out/"RESULT.json").write_text(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
    print(json.dumps({"all_pass":report["all_pass"],"error":report.get("error"),"cases":report.get("cases",{}).get("cases"),
                      "assertions":report.get("cases",{}).get("assertions"),"grammar_vectors":report.get("grammar",{}).get("vectors"),
                      "result":str(out/"RESULT.json")}))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":
    raise SystemExit(main())
