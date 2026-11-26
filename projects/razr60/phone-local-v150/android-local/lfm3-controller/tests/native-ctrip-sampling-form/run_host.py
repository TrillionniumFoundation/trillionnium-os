#!/usr/bin/env python3
"""Actual pre-capture Ctrip sampling with the established Android IO fixture.
The baseline source is used only to generate the already protected fixture.
Its complete observer section is then replaced by current production source.
No production body, comparator, gate, deadline or existing scenario is stubbed.
"""
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path
sys.dont_write_bytecode=True
PKG=Path("src/org/trillionnium/hepta/local")
TEST=Path("tests/native-ctrip-sampling-form")
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
BASE_SERVICE_SHA="3208f0203a56b446a4d5f54fd26896c6a8a423bc0742e7a42b52458e42a0070c"
BASE_GATE_SHA="426100c4f31e825c9e0f0c556c8c89d23aa45a40593978cb5fd8d5946a4beeb8"
def need(v,msg):
    if not v:raise RuntimeError(msg)
def sha(raw):return hashlib.sha256(raw).hexdigest()
def load(path,name):
    spec=importlib.util.spec_from_file_location(name,path);mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod
def main():
    ap=argparse.ArgumentParser()
    for name in ("source","fixture-baseline","output","java-home","json-jar"):ap.add_argument("--"+name,type=Path,required=True)
    ap.add_argument("--only",default="")
    ap.add_argument("--skip-existing-cases",action="store_true")
    a=ap.parse_args();source=a.source.resolve();baseline=a.fixture_baseline.resolve();out=a.output.absolute()
    need(not out.exists() and source not in out.parents and baseline not in out.parents,"new output outside source trees")
    need(sha((baseline/PKG/"HeptaAccessibilityService.java").read_bytes())==BASE_SERVICE_SHA,"exact 0a8 fixture baseline service")
    need(sha((baseline/PKG/"ObservationStabilityGate.java").read_bytes())==BASE_GATE_SHA,"exact 0a8 fixture baseline gate")
    helper=load(baseline/"tests/observation-diagnostics/run_host.py","sampling_diagnostic_helpers")
    observer=load(baseline/"tests/native-ctrip-form-observation/run_observer_host.py","sampling_observer_fixture")
    jdk=a.java_home.resolve();jar=a.json_jar.resolve();tools=[jdk/"bin/java",jdk/"bin/javac",jdk/"lib/modules",jdk/"lib/ct.sym",jar]
    need(all(p.is_file() for p in tools),"complete JDK17 toolchain")
    need(jar.stat().st_size==78332 and sha(jar.read_bytes())==JSON_SHA,"pinned JSON jar")
    inputs=[source/PKG/n for n in observer.JAVA+observer.READ]+[source/observer.PROFILE/n for n in observer.PROFILE_NAMES]
    inputs += [source/"tests/native-action-integration/NativeActionSnapshotCheckHostTest.java",
        source/"tests/native-ctrip-form-observation/FormPairHostTest.java",
        source/"tests/native-ctrip-form-observation/ObserverIntegrationHostTest.java",
        source/"tests/native-ctrip-form-observation/form-region-nodes.json",source/TEST/"SamplingFormCases.fragment",source/TEST/"run_host.py"]
    inputs += helper.png_sources(source)
    before=[helper.meta(p) for p in inputs];tool_before=[helper.meta(p) for p in tools]
    out.mkdir(parents=True,mode=0o700)
    report={"schema":"hepta.ctrip-sampling-form-host.v1","all_pass":False,"source":str(source),
        "fixture_baseline":str(baseline),"inputs_before":before,"tools_before":tool_before,
        "stages":[],"phone_operations":0,"android_execution":False,"model_executed":False,
        "business_completion_verified":False,"only_case":a.only,
        "boundary":"Current full observer section, raw snapshot adapter, pure comparator and Gate execute verbatim. Android census/window/pixel/clock and Session permit are explicit host IO ports; existing observer scenarios are retained."}
    try:
        generated=out/"generated";generated.mkdir()
        extraction=observer.generate(baseline,generated,helper)
        host=generated/"ObserverPipelineHost.java";original=host.read_text()
        old_service=(baseline/PKG/"HeptaAccessibilityService.java").read_text()
        new_service=(source/PKG/"HeptaAccessibilityService.java").read_text()
        anchor="    /** Each observation owns";end="    synchronized void bindQualificationScope("
        old_section=helper.section(old_service,anchor,end);new_section=helper.section(new_service,anchor,end)
        old_compiled,old_calendar=helper.calendar_observer_legacy_parts(old_service,{"observation":old_section})
        new_compiled,new_calendar=helper.calendar_observer_legacy_parts(new_service,{"observation":new_section})
        need(new_calendar["calendar_only_excluded_sha256"]==old_calendar["calendar_only_excluded_sha256"],"unchanged unrelated calendar type boundary")
        old_body=old_compiled["observation"];new_body=new_compiled["observation"]
        need(original.count(old_body)==1,"one complete protected baseline observer section")
        current=original.replace(old_body,new_body,1)
        cases=(source/TEST/"SamplingFormCases.fragment").read_text()
        marker="    public static void main(String[] args)throws Exception{ObserverIntegrationHostTest.main(args);}"
        need(current.count(marker)==1,"one unchanged existing observer entry point")
        current=current.replace(marker,cases+"\n"+marker,1)
        inverse=current.replace(cases+"\n"+marker,marker,1).replace(new_body,old_body,1)
        need(inverse==original,"old fixture and all existing cases are byte-identical outside actual production replacement")
        exact={}
        for name,method in {
            "sample_worker":"    private void sampleObservation(",
            "accept_sample_actual":"    private void acceptSample(final ObservationRequest request,Graph graph,String error,long events,long unknownEvents,CtripFormSampleRead formRead){",
            "sample_snapshot":"    private CtripFormSampleRead readCtripFormSample(",
            "candidate_current":"    private boolean ctripFormSampleCurrent(",
            "sample_type":"    private static final class CtripFormSample {",
            "sample_owner":"    private boolean ctripFormSamplingOwner(",
            "sample_events":"    private void noteObservationEvent(int displayId,int windowId,String packageName,boolean contentType,int sdkEventType){",
            "capture":"    private void captureObservation(",
            "capture_worker":"    private void processScreenshot(",
            "capture_accept":"    private void acceptScreenshot(",
            "history":"    private void persistCtripFormHistory(",
            "snapshot_adapter":"    private NativeActionSnapshotCheck.Snapshot nativeCtripFormSnapshot(",
        }.items():
            value=helper.body(new_service,method)
            need(current.count(value)==1,"actual production body present once: "+name)
            exact[name]={"sha256":sha(value.encode()),"bytes":len(value.encode())}
        host.write_text(current)
        entry=generated/"CtripSamplingFormHostTest.java"
        entry.write_text("package org.trillionnium.hepta.local;\npublic final class CtripSamplingFormHostTest {public static void main(String[] args)throws Exception {ObserverPipelineHost.samplingFormMain(args);}}\n")
        extraction.update({"schema":"hepta.ctrip-sampling-form-extraction.v1","current_source_service":helper.meta(source/PKG/"HeptaAccessibilityService.java"),
            "baseline_source_service":helper.meta(baseline/PKG/"HeptaAccessibilityService.java"),
            "complete_current_observer_section_sha256":sha(new_section.encode()),"compiled_current_observer_section_sha256":sha(new_body.encode()),
            "actual_sampling_bodies":exact,"unrelated_fixture_inverse_equal":True,"calendar_type_boundary":new_calendar,
            "production_sampling_methods_executed_verbatim":True,"sample_graph_is_explicit_android_io_port":True,"test_file":helper.meta(source/TEST/"SamplingFormCases.fragment")})
        helper.save(out/"EXTRACTION.json",extraction)
        classes=out/"classes";classes.mkdir()
        compiled=[source/PKG/n for n in observer.JAVA]+[source/observer.PROFILE/n for n in observer.PROFILE_NAMES]
        compiled += [source/"tests/native-action-integration/NativeActionSnapshotCheckHostTest.java",
            source/"tests/native-ctrip-form-observation/FormPairHostTest.java",
            source/"tests/native-ctrip-form-observation/ObserverIntegrationHostTest.java",host,entry]
        compiled += helper.png_sources(source)
        report["compile_inputs_before"]=[helper.meta(p) for p in compiled]
        cmd=[str(jdk/"bin/javac"),"--release","8","-encoding","UTF-8","-Xlint:all","-Werror","-cp",str(jar),"-d",str(classes),*map(str,compiled)]
        stage=helper.stage("compile",cmd,out);report["stages"].append(stage);need(stage["exit_code"]==0,"current sampling compilation")
        java=[str(jdk/"bin/java"),"-Dhepta.ctrip.form.fixture="+str(source/"tests/native-ctrip-form-observation/form-region-nodes.json"),
            "-Dhepta.ctrip.sampling.only="+a.only,"-cp",str(classes)+os.pathsep+str(jar)]
        if not a.skip_existing_cases:
            stage=helper.stage("existing-observer-cases",java+["org.trillionnium.hepta.local.ObserverIntegrationHostTest",str(out/"EXISTING-CASES.json")],out)
            report["stages"].append(stage);need(stage["exit_code"]==0,"all existing observer scenarios")
            report["existing_cases"]=json.loads((out/"EXISTING-CASES.json").read_text())
        stage=helper.stage("sampling-form-cases",java+["org.trillionnium.hepta.local.CtripSamplingFormHostTest",str(out/"SAMPLING-CASES.json")],out)
        report["stages"].append(stage)
        if (out/"SAMPLING-CASES.json").is_file():report["sampling_cases"]=json.loads((out/"SAMPLING-CASES.json").read_text())
        need(stage["exit_code"]==0 and report["sampling_cases"]["all_pass"],"all actual pre-capture sampling scenarios")
        report["compile_inputs_after"]=[helper.meta(p) for p in compiled]
        need(report["compile_inputs_before"]==report["compile_inputs_after"],"compiled inputs unchanged")
        report["all_pass"]=True
    except Exception as error:
        report["error"]={"type":type(error).__name__,"message":str(error)}
    finally:
        report["inputs_after"]=[helper.meta(p) for p in inputs];report["tools_after"]=[helper.meta(p) for p in tools]
        report["inputs_unchanged"]=report["inputs_after"]==before;report["tools_unchanged"]=report["tools_after"]==tool_before
        report["all_pass"]=report["all_pass"] and report["inputs_unchanged"] and report["tools_unchanged"]
        helper.save(out/"RESULT.json",report)
    print(json.dumps({"all_pass":report["all_pass"],"error":report.get("error"),"result":str(out/"RESULT.json")}))
    return 0 if report["all_pass"] else 1
if __name__=="__main__":raise SystemExit(main())
