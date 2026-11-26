#!/usr/bin/env python3
"""Finite pure-value manual capture protocol and unchanged budget-preview gate.
The Android Service/Controller/files layer requires its separate real SDK compile.
No page route, input permission, model result or Phone operation is constructed.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import time

sys.dont_write_bytecode = True

def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def record(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {"path":str(path),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest(),
            "mode":format(stat.S_IMODE(path.stat().st_mode),"04o")}

def check_record(expected):
    if record(expected["path"]) != expected:
        raise RuntimeError("complete input differs: "+expected["path"])

def write_json(path, value):
    path.write_text(json.dumps(value,sort_keys=True,ensure_ascii=False,indent=2)+"\n")
    path.chmod(0o644)

def inventory(source):
    return [dict(relative=p.relative_to(source).as_posix(),**record(p))
            for p in sorted(source.rglob("*")) if p.is_file()]

def check_inventory(source, expected):
    current=inventory(source)
    if current != expected:
        raise RuntimeError("source file bytes, membership or modes changed")

def prepare(source, out, jdk, jar):
    if out.exists() or source in out.parents:
        raise RuntimeError("fresh separate prepared output required")
    out.mkdir(parents=True)
    before=inventory(source)
    write_json(out/"SOURCE-BEFORE.json",before)
    shared=load(source/"tests/native-search-planning/host_closure.py","manual_original_session_closure")
    query=load(source/"tests/web-flight/run_query_host_tests.py","manual_original_java_extractor")
    if record(jar)["sha256"] != shared.JSON_SHA:
        raise RuntimeError("original fixed JSON library required")
    local=source/"src/org/trillionnium/hepta/local"
    new_case=source/"tests/order-preview-manual-fixture/NativeOrderPreviewManualHostTest.java"
    old_case=source/"tests/native-xiaomi-budget-preview/NativeXiaomiBudgetPreviewHostTest.java"
    xml=source/"tests/native-app-fixtures/NativeXmlFixture.java"
    login=load(source/"tests/native-xiaomi-login/run_host.py","manual_original_login_fixture")
    utility=load(source/"tests/native-xiaomi-home-loading/run_host.py","manual_original_login_fixture_io")
    portable=out/"login-fixture"
    login.fixture(source,portable,utility)
    extras=(new_case,old_case,xml,portable/"SyntheticXiaomiNativeLoginFixture.java",
            local/"NativeOrderPreviewManual.java",local/"WebEvidenceJson.java",
            source/"src/org/trillionnium/hepta/webprotocol/WebEvidenceProtocol.java")
    paths, provenance=shared.prepare(source,out/"closure",extras)
    actual=local/"LocalTaskController.java"
    port=next(p for p in paths if p.name=="LocalTaskController.java")
    body=query.java_block(actual.read_bytes(),"static final class OutcomeExplanation")
    presentation=out/"presentation/LocalTaskController.java"
    presentation.parent.mkdir()
    original=port.read_text().rstrip()
    if not original.endswith("}") or original.count("final class LocalTaskController")!=1:
        raise RuntimeError("original controller fixture boundary differs")
    presentation.write_text(original[:-1].replace("final class LocalTaskController",
        "import org.json.JSONObject;\nfinal class LocalTaskController")+"\n"+body+"\n}\n")
    paths=[presentation if p==port else p for p in paths]
    if len(paths)!=len(set(p.resolve() for p in paths)):
        raise RuntimeError("duplicate explicit compile path")
    fixtures=source/"tests/native-xiaomi-product/fixtures"
    original_files=json.loads((fixtures/"PROVENANCE.json").read_bytes())["files"]
    fixtures_used=[r for r in original_files if r["name"] in ("suggestions","results","detail")]
    if len(fixtures_used)!=3 or any(record(source/r["fixture_path"])["sha256"]!=r["sha256"] for r in fixtures_used):
        raise RuntimeError("original public XML fixtures differ")
    generator_paths=[
        Path(__file__).resolve(),source/"tests/native-search-planning/host_closure.py",
        source/"tests/web-flight/run_query_host_tests.py",source/"tests/background-session/prepare_fixture.py",
        source/"tests/native-xiaomi-login/run_host.py",source/"tests/native-xiaomi-home-loading/run_host.py",
        source/"tests/native-xiaomi-budget-preview/run_host.py",fixtures/"PROVENANCE.json"]
    compiled=[record(p) for p in paths]
    tools=[record(p) for p in (jdk/"bin/java",jdk/"bin/javac",jdk/"release",
                               jdk/"lib/modules",jdk/"lib/server/libjvm.so",jar)]
    originals=[record(p) for p in dict.fromkeys([actual,*generator_paths,*[source/r["fixture_path"] for r in fixtures_used]])]
    check_inventory(source,before)
    metadata={
        "schema":"hepta.order-preview.manual-fixture-host-prepared.v1",
        "source":str(source),"output":str(out),"java_home":str(jdk),"json_jar":str(jar),
        "source_inventory":record(out/"SOURCE-BEFORE.json"),
        "actual_compile_inputs":compiled,"tools":tools,"originals":originals,
        "shared_closure":provenance,"original_xml_fixtures":fixtures_used,
        "original_budget_case":record(old_case),"new_protocol_case":record(new_case),
        "outcome_explanation_sha256":hashlib.sha256(body.encode()).hexdigest(),
        "fixture_root":str(fixtures),"planned_cases":{"manual_protocol":27,"original_budget_preview":11},
        "expected_stages":["strict_compile","manual_protocol","original_budget_preview"],
        "scope":"Actual pure classes and complete Session; original refusing Android IO ports. Separate real SDK compile is required for capture implementation.",
        "phone_actions":0,"page_route_bound":False,"android_capture_executed":False,"business_success":False}
    write_json(out/"PREPARED.json",metadata)
    print(json.dumps({"prepared":record(out/"PREPARED.json"),"compile_input_count":len(compiled),"java_executions":0},sort_keys=True))
    return 0

def execute_prepared(source,out,jdk,jar):
    prepared=out/"PREPARED.json"
    q=json.loads(prepared.read_bytes())
    if q.get("schema")!="hepta.order-preview.manual-fixture-host-prepared.v1" or any(q[k]!=str(v) for k,v in (("source",source),("output",out),("java_home",jdk),("json_jar",jar))):
        raise RuntimeError("exact prepared source/output/tools required")
    if (out/"RESULT.json").exists() or (out/"classes").exists():
        raise RuntimeError("prepared execution is single use")
    check_record(q["source_inventory"])
    before=json.loads(Path(q["source_inventory"]["path"]).read_bytes())
    check_inventory(source,before)
    inputs=[*q["actual_compile_inputs"],*q["tools"],*q["originals"],record(prepared)]
    for item in inputs:check_record(item)
    result={"schema":"hepta.order-preview.manual-fixture-host-result.v1","all_pass":False,
        "prepared":record(prepared),"source":str(source),"stages":[],
        "actual_compile_inputs":q["actual_compile_inputs"],"tools":q["tools"],"originals":q["originals"],
        "source_inventory":q["source_inventory"],"case_reports":{},
        "source_and_inputs_unchanged":False,"phone_actions":0,"page_route_bound":False,
        "android_capture_executed":False,"business_success":False,
        "scope":q["scope"],"started_unix_ns":time.time_ns()}
    classes=out/"classes";classes.mkdir()
    empty_sourcepath=out/"empty-sourcepath";empty_sourcepath.mkdir()
    env={**os.environ,"PATH":str(jdk/"bin")+":/usr/bin:/bin"}
    for k in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(k,None)
    stages=[
        ("strict_compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none",
           "-implicit:none","-sourcepath",empty_sourcepath,"-Xlint:all,-options","-Werror",
           "-cp",jar,"-d",classes,*[x["path"] for x in q["actual_compile_inputs"]]]),
        ("manual_protocol",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),
           "org.trillionnium.hepta.local.NativeOrderPreviewManualHostTest",out/"MANUAL-CASES.json"]),
        ("original_budget_preview",[jdk/"bin/java","-cp",str(classes)+os.pathsep+str(jar),
           "org.trillionnium.hepta.local.NativeXiaomiBudgetPreviewHostTest",q["fixture_root"],
           out/"budget-work",out/"BUDGET-CASES.json"])]
    try:
        for name,args in stages:
            argv=list(map(str,args));started=time.time_ns()
            p=subprocess.run(argv,capture_output=True,cwd=out,env=env,timeout=120,check=False)
            stdout=out/(name+".stdout");stderr=out/(name+".stderr")
            stdout.write_bytes(p.stdout);stderr.write_bytes(p.stderr)
            row={"name":name,"argv":argv,"exit_code":p.returncode,"started_unix_ns":started,
                 "finished_unix_ns":time.time_ns(),"stdout":record(stdout),"stderr":record(stderr)}
            result["stages"].append(row);write_json(out/(name+"-STAGE.json"),row)
            if p.returncode!=0:raise RuntimeError(name+" failed")
            if name!="strict_compile":
                leaf,count=("MANUAL-CASES.json",27) if name=="manual_protocol" else ("BUDGET-CASES.json",11)
                report=json.loads((out/leaf).read_bytes())
                if report.get("all_pass") is not True or report.get("cases")!=count:
                    raise RuntimeError(name+" original assertion or case count differs")
                result["case_reports"][name]={"report":record(out/leaf),"cases":report["cases"],"assertions":report["assertions"]}
        result["all_pass"]=True
    except Exception as failure:
        result["error"]=str(failure)
    finally:
        result["finished_unix_ns"]=time.time_ns()
        try:
            check_inventory(source,before)
            for item in inputs:check_record(item)
            result["source_and_inputs_unchanged"]=True
        except Exception as changed:
            result["all_pass"]=False;result["input_error"]=str(changed)
        result["not_executed_stages"]=[name for name,_ in stages if name not in {r["name"] for r in result["stages"]}]
        write_json(out/"RESULT.json",result)
    print(json.dumps({k:result[k] for k in ("all_pass","stages","case_reports","not_executed_stages","source_and_inputs_unchanged")},sort_keys=True))
    return 0 if result["all_pass"] else 1

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ("source","output","java-home","json-jar"):parser.add_argument("--"+name,type=Path,required=True)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--prepare-only",action="store_true")
    group.add_argument("--execute-prepared",action="store_true")
    args=parser.parse_args()
    source,out,jdk,jar=[p.resolve() for p in (args.source,args.output,args.java_home,args.json_jar)]
    return prepare(source,out,jdk,jar) if args.prepare_only else execute_prepared(source,out,jdk,jar)

if __name__=="__main__":
    raise SystemExit(main())
