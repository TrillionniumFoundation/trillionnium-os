#!/usr/bin/env python3
"""Actual extracted Service type/guard/final-census with recorded history nodes.

Reuses the unmodified existing input bridge's explicit Android IO. The actual
production Session and Service methods remain complete and verbatim. No phone.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
sys.dont_write_bytecode = True
PKG = Path("src/org/trillionnium/hepta/local")
TEST = Path("tests/native-xiaomi-search-history")
EXPECTED_CASES = [
  "recorded_history_step_02_actual_type_single_original_NodeRef",
  "recorded_history_step_03_actual_type_single_original_NodeRef",
  "recorded_history_step_04_actual_type_single_original_NodeRef",
  "history_equal_tree_still_checks_final_census",
  "history_heading_change_before_effect_refused",
  "history_item_label_change_before_effect_refused",
  "history_child_change_before_effect_refused",
  "history_capability_change_before_effect_refused",
  "history_target_change_before_effect_refused",
  "history_original_NodeRef_replacement_refused",
  "history_original_deadline_refused",
  "history_owner_loss_refused"
]
INPUT_BRIDGE_SHA = "786c24f721ba99dd5b54b51157048be85fa74daaeaa60968e1c0612cbbdbcb7d"
INPUT_FRAGMENT_SHA = "e2129e54d877a2795d131fb001a8096fbb91e54dc366e5999b8470a55372d741"

def load(path, name):
    spec=importlib.util.spec_from_file_location(name,path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);return module

def need(value, why):
    if not value: raise RuntimeError(why)

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("source","recorded-dir","output","java-home","json-jar"):
        p.add_argument("--"+key,type=Path,required=True)
    a=p.parse_args()
    source,recordings,out,jdk,jar=[getattr(a,key).absolute() for key in ("source","recorded_dir","output","java_home","json_jar")]
    need(not out.exists() and source not in out.parents,"fresh output outside source")
    out.mkdir(parents=True,mode=0o700)
    pure=load(source/TEST/"run_host.py","history_exact_recordings")
    ref=pure.ref; read=pure.read
    base=load(source/"tests/native-action-integration/run_host.py","history_action_source")
    bridge_path=source/"tests/native-xiaomi-search-input-bridge/run_host.py"
    fragment_path=source/"tests/native-xiaomi-search-input-bridge/InputActionCases.fragment"
    need(ref(bridge_path)["sha256"]==INPUT_BRIDGE_SHA and ref(fragment_path)["sha256"]==INPUT_FRAGMENT_SHA,
         "original complete input bridge and Android IO ports must stay exact")
    bridge=load(bridge_path,"history_input_ports")
    before=base.inventory(source)
    tools=[jdk/"bin/java",jdk/"bin/javac",jdk/"lib/modules",jdk/"lib/ct.sym",jar]
    report=dict(schema="hepta.xiaomi-search-history-actual-service-host.v1",all_pass=False,stages=[],
                source=str(source),source_before=before,tools_before=[ref(x) for x in tools],
                actual_production_session=True,actual_service_methods_verbatim=True,
                explicit_existing_android_io_ports=True,original_device_action_replayed=False,
                phone_operations=0,android_execution=False,model_executed=False,business_completion_verified=False)
    env=dict(os.environ,JAVA_HOME=str(jdk),PATH=str(jdk/"bin")+":/usr/bin:/bin",PYTHONDONTWRITEBYTECODE="1")
    for key in ("JAVA_TOOL_OPTIONS","JDK_JAVA_OPTIONS","_JAVA_OPTIONS","CLASSPATH"):env.pop(key,None)
    def stage(name,argv):
        started=time.monotonic()
        r=subprocess.run(list(map(str,argv)),cwd=out,env=env,capture_output=True,timeout=240)
        so,se=out/(name+".stdout"),out/(name+".stderr")
        with so.open("xb") as f:f.write(r.stdout)
        with se.open("xb") as f:f.write(r.stderr)
        report["stages"].append(dict(name=name,argv=list(map(str,argv)),exit_code=r.returncode,
                                    elapsed_seconds=time.monotonic()-started,stdout=ref(so),stderr=ref(se)))
        need(r.returncode==0,name+" failed; original output retained")
    try:
        need(ref(jar)["sha256"]==pure.JSON_SHA and ref(jar)["bytes"]==78332,"original JSON runtime")
        fixture,refs=pure.recorded_fixture(recordings)
        fixture_path=out/"RECORDED-PAIRS.json"
        with fixture_path.open("x") as f:f.write(json.dumps(fixture,ensure_ascii=False,indent=2)+"\n")
        report["recorded_inputs"],report["recorded_fixture"]=refs,ref(fixture_path)
        gen=out/"generated";gen.mkdir()
        extracted=bridge.generate(source,gen,base)
        target=gen/"NativeActionBridgeHost.java"
        original=read(target).decode("utf-8")
        extra=read(source/TEST/"HistoryInputCases.fragment").decode("utf-8")
        need(original.rstrip().endswith("}"),"complete existing generated class")
        adapted=original.rstrip()[:-1]+"\n"+extra+"\n}\n"
        target.write_text(adapted,encoding="utf-8")
        extractor=load(source/"tests/observation-diagnostics/run_host.py","history_verbatim_checker")
        service=read(source/PKG/"HeptaAccessibilityService.java").decode("utf-8")
        selected=extractor.section(service,"            NodeRef reference=graph.refs.get(action.nodeId);","            boolean accepted;")
        typed=extractor.section(service,'                if(!node.isEditable()||!hasAction(node,AccessibilityNodeInfo.ACTION_SET_TEXT))',
                                '            }else if("submit".equals(action.action)){')
        need(selected in adapted and typed in adapted and original.rstrip()[:-1] in adapted,
             "complete original generated body and actual production input bodies preserved")
        paths,boundary=base.sources(source,out)
        main=gen/"HistoryInputBridgeMain.java"
        main.write_text('''package org.trillionnium.hepta.local;
final class HistoryInputBridgeMain {public static void main(String[] a)throws Exception{
 NativeActionBridgeHost.historyInputCases(java.nio.file.Paths.get(a[0]),java.nio.file.Paths.get(a[1]));
 IntegrationChecks.finish(java.nio.file.Paths.get(a[2]),"hepta.search-history-actual-input-cases.v1",
 "Actual complete Session and verbatim Service input, original NodeRef, final census and one claim; existing explicit host Android IO; no phone or business qualification.");
}}\n''',encoding="utf-8")
        paths.append(main)
        need((source/PKG/"NativeAppSession.java").resolve() in paths,"actual complete production Session compiled")
        report["compile_inputs"]=[ref(x) for x in paths]
        report["background_fixture"]=boundary
        report["extraction"]=dict(original=extracted,actual_type_body_sha256=hashlib.sha256(typed.encode()).hexdigest(),
                                  actual_original_reference_body_sha256=hashlib.sha256(selected.encode()).hexdigest(),
                                  generated=ref(target),fragment=ref(source/TEST/"HistoryInputCases.fragment"),
                                  service=ref(source/PKG/"HeptaAccessibilityService.java"),session=ref(source/PKG/"NativeAppSession.java"))
        classes=out/"classes";classes.mkdir()
        stage("jdk-version",[jdk/"bin/javac","-version"])
        need(((out/"jdk-version.stdout").read_bytes()+(out/"jdk-version.stderr").read_bytes()).decode().strip().startswith("javac 17."),"JDK17 required")
        stage("compile",[jdk/"bin/javac","--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror","-cp",jar,"-d",classes,*paths])
        cases_path=out/"CASES.json"
        stage("cases",[jdk/"bin/java","-ea","-cp",str(classes)+os.pathsep+str(jar),"org.trillionnium.hepta.local.HistoryInputBridgeMain",
                       source,fixture_path,cases_path])
        cases=json.loads(read(cases_path))
        need(cases.get("all_pass") is True and cases["schema"]=="hepta.search-history-actual-input-cases.v1"
             and cases["case_names"]==EXPECTED_CASES and cases["cases"]==len(EXPECTED_CASES)==len(set(cases["case_names"]))
             and cases["case_assertions"]==[9,9,9,2,3,3,3,3,3,2,3,3]
             and cases["assertions"]==sum(cases["case_assertions"])==52,
             "all exact Service cases and original IntegrationChecks accounting required")
        report["cases"],report["case_file"]=cases,ref(cases_path)
        report["all_pass"]=True
    except Exception as error:
        report["error"]=type(error).__name__+": "+str(error)
    finally:
        report["source_after"]=base.inventory(source)
        report["source_unchanged"]=before==report["source_after"]
        report["tools_after"]=[ref(x) for x in tools]
        report["tools_unchanged"]=report["tools_before"]==report["tools_after"]
        report["all_pass"]=report["all_pass"] and report["source_unchanged"] and report["tools_unchanged"]
        result=out/"RESULT.json"
        with result.open("x") as f:f.write(json.dumps(report,ensure_ascii=False,indent=2)+"\n")
        print(json.dumps(dict(all_pass=report["all_pass"],error=report.get("error"),result=ref(result),case_file=report.get("case_file"))))
    return 0 if report["all_pass"] else 1

if __name__=="__main__":raise SystemExit(main())
