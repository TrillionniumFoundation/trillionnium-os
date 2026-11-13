#!/usr/bin/env python3
"""Run the actual explicit native route, preserved helper admission, and UI/session/controller entries.
Android/package/display/model endpoints are explicit host fakes; no phone, SDK or App effects.
"""
import argparse,ast,hashlib,importlib.util,json,os,subprocess,time
from pathlib import Path

EXPECTED_PURE=["natural_flight_preserves_explicit_ctrip_while_legacy_resolver_selected_helper","same_flight_owner_csair_has_distinct_native_package_and_goal_contract","xiaomi_native_price_preserves_owner_and_explicit_package","old_website_owner_with_native_selection_stays_native_without_provider","native_unrecognized_owner_and_tool_clauses_keep_original_restrictions","unknown_native_app_is_singleton_not_a_generic_success_capability","explicit_notes_keeps_notes_create_without_switching_to_helper","flight_owner_in_explicit_notes_does_not_switch_package","explicit_helper_flight_keeps_entire_original_public_authorization","explicit_helper_shopping_keeps_original_public_authorization","explicit_helper_does_not_accept_unknown_or_notes_goal","original_ui_selection_is_frozen_and_effective_scope_is_singleton","same_actual_selection_and_target_objects_survive_repeated_admission","replacement_selection_with_same_target_is_rejected","equal_looking_recreated_target_and_selection_are_rejected","owner_rewrite_or_other_original_owner_is_rejected","native_authorization_hash_binds_selected_app_and_original_scope","helper_same_public_hash_still_requires_original_private_selection","bound_authorization_cannot_be_rebound","legacy_selection_cannot_enter_new_explicit_admission","mutable_binding_is_rejected_if_target_changes_during_binding","selected_package_must_be_valid_and_in_original_scope","native_route_validation_does_not_grant_web_constructor_admission","helper_constructor_rejects_wrong_task_retired_authority_and_null_completion","helper_constructor_preserves_complete_original_public_auth_comparison","foreground_or_absent_selection_cannot_auto_create_web_session","find_before_open_and_original_no_open_clauses_remain_effective","completion_entry_cannot_omit_or_replace_bound_selection","legacy_completion_entry_remains_unbound_only","actual_background_session_evidence_retains_target_outside_unchanged_selection_wire"]
EXPECTED_ENTRY=["actual_ui_to_session_preserves_native_target_and_original_owner","actual_ui_null_native_goal_does_not_fallback_to_helper","actual_ui_refuses_stale_saved_app_selection_before_schedule","actual_ui_original_no_open_clause_refuses_background_bootstrap","actual_schedule_rejects_replacement_selection_before_journal_or_controller","actual_controller_start_rejects_replacement_selection_before_lease","actual_full_controller_native_flight_never_creates_web_session","actual_full_controller_unknown_native_goal_never_creates_web_session"]
PRESERVED_OWNER_PARSE_SHA256="56fc6f5e4e252a4876301571a3e19ec13edad3c279c129c54b703add5c17370c"
JSON_SHA256="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"

def sha(raw):return hashlib.sha256(raw).hexdigest()
def require(ok,message):
    if not ok:raise RuntimeError(message)
def module(path,name):
    spec=importlib.util.spec_from_file_location(name,path);value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
def write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    with path.open("xb") as f:f.write(data)
def snapshot(source):
    return {str(p.relative_to(source)):{"bytes":p.stat().st_size,"sha256":sha(p.read_bytes())}
            for p in sorted(source.rglob("*")) if p.is_file() and "__pycache__" not in p.parts}
def check_cases(path,schema,names):
    value=json.loads(path.read_text())
    require(value.get("schema")==schema and value.get("all_pass") is True,"typed case result absent")
    require(value.get("cases")==len(names) and value.get("case_names")==names,"case identity/count changed")
    require(type(value.get("assertions")) is int and value["assertions"]>0,"assertion receipt absent")
    require(value.get("phone_operations")==0 and value.get("android_runtime") is False
            and value.get("provider_or_business_verified") is False,"host boundary incorrectly classified")
    return value

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--source",required=True,type=Path);ap.add_argument("--output",required=True,type=Path)
    ap.add_argument("--java-home",required=True,type=Path);ap.add_argument("--json-jar",required=True,type=Path)
    args=ap.parse_args();source=args.source.resolve();out=args.output.resolve();jdk=args.java_home.resolve();jar=args.json_jar.resolve()
    require(source.is_dir() and not out.exists() and source not in out.parents,"fresh output outside source required")
    require((jdk/"bin/javac").is_file() and (jdk/"bin/java").is_file(),"existing full JDK required")
    require(jar.is_file() and jar.stat().st_size==78332 and sha(jar.read_bytes())==JSON_SHA256,"fixed org.json dependency differs")
    out.mkdir(parents=True,mode=0o700)
    before=snapshot(source);env=dict(os.environ);env["PATH"]=str(jdk/"bin")+":"+env.get("PATH","");env["PYTHONDONTWRITEBYTECODE"]="1"
    for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(key,None)
    record={"schema":"hepta.native-app-routing-host-gate.v1","all_pass":False,"inputs_before":before,"stages":[],
            "phone_operations":0,"model_inference":False,"android_runtime":False,"provider_or_business_verified":False}
    def run(name,argv,timeout=90):
        started=time.monotonic();r=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=timeout)
        write(out/(name+".stdout"),r.stdout);write(out/(name+".stderr"),r.stderr)
        record["stages"].append({"name":name,"argv":list(map(str,argv)),"exit_code":r.returncode,"seconds":time.monotonic()-started,
                                  "stdout_sha256":sha(r.stdout),"stderr_sha256":sha(r.stderr)})
        if r.returncode:
            print(r.stdout.decode("utf-8","replace")[-12000:]);print(r.stderr.decode("utf-8","replace")[-12000:])
            raise RuntimeError("actual host stage failed: "+name)
    try:
        query=module(source/"tests/web-flight/run_query_host_tests.py","native_route_query_closure")
        bg=module(source/"tests/background-session/prepare_fixture.py","native_route_background_fixture")
        pkg=source/"src/org/trillionnium/hepta/local"
        owner_parse=query.java_block((pkg/"TaskAuthorization.java").read_bytes(),"public static TaskAuthorization parse(String owner)")
        require(sha(owner_parse.encode())==PRESERVED_OWNER_PARSE_SHA256,"original complete OWNER parser body changed")
        bgfiles,bgrecord=bg.prepare(source,out/"pure-fixture")
        # Use the fixed real org.json jar in this pure gate. Android IO fakes remain explicit.
        bgfiles=[p for p in bgfiles if not (p.parent.name=="json" and p.parent.parent.name=="org")]
        pure=[source/p for p in query.PURE_PATHS if p!="tests/web-flight/WebFlightQueryHostTest.java"]+bgfiles
        web_raw=(pkg/"WebFlightSession.java").read_bytes();web=web_raw.decode()
        signatures=["static void validateSelection(String owner,BackgroundSession.Selection selection)",
                    "static void requireWebSelection(String owner,BackgroundSession.Selection selection)",
                    "private static void need(boolean condition,String reason)"]
        parts=[query.java_block(web_raw,s) for s in signatures]
        constructor="    WebFlightSession(HeptaAccessibilityService service,String task,String owner,TaskAuthorization.Gate authorization,"
        require(web.count(constructor)==1,"actual Web constructor not unique")
        i=web.index(constructor);opening=web.index("{",i);end=web.index("        this.service=service;",opening)
        prefix=web[opening+1:end]
        require(prefix.count("WebEvidenceBinding.canonical")==2 and "requireWebSelection" in prefix,
                "complete constructor authority comparison is not in extraction")
        projection=("package org.trillionnium.hepta.local;\nimport java.time.LocalDate;\nimport java.util.Collections;\n"
                    "import org.json.JSONObject;\nimport org.trillionnium.hepta.local.web.WebFlightGoal;\n"
                    "import org.trillionnium.hepta.local.web.WebShoppingGoal;\nimport org.trillionnium.hepta.webprotocol.*;\n"
                    "/** Exact constructor prefix through public/private OWNER admission; stops before Android helper identity/IO. */\n"
                    "final class RouteWebAdmissionProjection {\n"+"\n".join(parts)+"\n"
                    " static WebTaskPurpose admit(String task,String owner,TaskAuthorization.Gate authorization,"
                    "BackgroundSession background,TaskCompletionGate completion)throws Exception{\n"
                    "  WebTaskPurpose purpose;WebFlightGoal goal;\n"+prefix+"  return purpose;\n }\n}\n")
        pp=out/"pure-fixture/RouteWebAdmissionProjection.java";write(pp,projection.encode())
        pure += [pp,source/"tests/native-app-routing/NativeAppRoutingPureHostTest.java"]
        pure=list(dict.fromkeys(Path(p).resolve() for p in pure));pure_classes=out/"pure-classes";pure_classes.mkdir()
        extraction={"schema":"hepta.native-app-routing-extraction.v1",
                    "preserved_owner_parse_sha256":sha(owner_parse.encode()),
                    "web_constructor_prefix":{"source_sha256":sha(web_raw),"bytes":len(prefix.encode()),"sha256":sha(prefix.encode())},
                    "web_methods":[{"signature":s,"sha256":sha(v.encode()),"bytes":len(v.encode())} for s,v in zip(signatures,parts)],
                    "actual_full_background_fixture":bgrecord,
                    "pure_compile_inputs":[str(p) for p in pure]}
        run("pure-compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror",
                            "-classpath",jar,"-d",pure_classes,*pure])
        pure_result=out/"PURE-CASES.json"
        run("pure-cases",[jdk/"bin/java","-cp",str(pure_classes)+os.pathsep+str(jar),
                          "org.trillionnium.hepta.local.NativeAppRoutingPureHostTest",pure_result,out/"pure-cases-private-files"])
        pure_cases=check_cases(pure_result,"hepta.native-app-routing-pure-host.v1",EXPECTED_PURE)
        scope=module(source/"tests/qualification-scope/prepare_fixture.py","native_route_scope_fixture")
        entry,scope_record=scope.prepare(source,out/"entry-fixture")
        native_entry=module(source/"tests/native-app-routing/prepare_native_entry.py","native_route_actual_entry_io")
        entry,native_boundary=native_entry.prepare(source,out/"entry-fixture",entry)
        scope_record["actual_native_entry_io"]=native_boundary
        # Only this generated host IO fixture is made subclassable, so the new tests
        # can supply selected-package/current-choice inputs. Actual UI methods are unchanged.
        ui_path=out/"entry-fixture/ScopeUiFixture.java";ui_before=ui_path.read_bytes()
        ui_marker=b"public final class ScopeUiFixture extends Activity {"
        require(ui_before.count(ui_marker)==1,"one exact final host UI declaration required")
        ui_after=ui_before.replace(ui_marker,b"public class ScopeUiFixture extends Activity {",1)
        ui_path.write_bytes(ui_after)
        scope_record["native_route_ui_io_boundary_adapter"]={"input_sha256":sha(ui_before),"output_sha256":sha(ui_after),
            "change":"generated host declaration final removed only; actual extracted production methods unchanged",
            "selected_package_and_installed_choice":"explicit deterministic host IO; not Android installation evidence"}
        entry += [source/"tests/native-app-routing/NativeAppRoutingEntryHostTest.java"]
        entry=list(dict.fromkeys(Path(p).resolve() for p in entry));entry_classes=out/"entry-classes";entry_classes.mkdir()
        extraction["entry_extraction"]=scope_record;extraction["entry_compile_inputs"]=[str(p) for p in entry]
        write(out/"EXTRACTION.json",(json.dumps(extraction,indent=2)+"\n").encode())
        run("entry-compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all,-options","-Werror",
                             "-d",entry_classes,*entry])
        run("entry-cases",[jdk/"bin/java","-cp",entry_classes,
                           "org.trillionnium.hepta.local.NativeAppRoutingEntryHostTest",out/"entry-cases"],90)
        entry_cases=check_cases(out/"entry-cases/CASES.json","hepta.native-app-routing-entry-host.v1",EXPECTED_ENTRY)
        cases={"schema":"hepta.native-app-routing-host.v1","all_pass":True,"cases":pure_cases["cases"]+entry_cases["cases"],
               "assertions":pure_cases["assertions"]+entry_cases["assertions"],"case_names":EXPECTED_PURE+EXPECTED_ENTRY,
               "pure":pure_cases,"entry":entry_cases,"phone_operations":0,"android_runtime":False,"provider_or_business_verified":False}
        write(out/"CASES.json",(json.dumps(cases,ensure_ascii=False,indent=2)+"\n").encode())
        record["cases"]=cases;record["all_pass"]=True
    except Exception as error:
        record["failure"]={"class":type(error).__name__,"message":str(error)}
    finally:
        after=snapshot(source);record["inputs_unchanged"]=before==after
        record["all_pass"]=record["all_pass"] and record["inputs_unchanged"]
        if before!=after:record["changed_inputs"]=[p for p in sorted(set(before)|set(after)) if before.get(p)!=after.get(p)]
        raw=(json.dumps(record,ensure_ascii=False,indent=2)+"\n").encode();write(out/"RESULT.json",raw)
        print(json.dumps({"all_pass":record["all_pass"],"cases":record.get("cases",{}).get("cases"),
                          "assertions":record.get("cases",{}).get("assertions"),"result":str(out/"RESULT.json"),
                          "result_sha256":sha(raw),"failure":record.get("failure")}))
    return 0 if record["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
