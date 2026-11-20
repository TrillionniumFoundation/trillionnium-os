#!/usr/bin/env python3
"""Actual production Node extraction + real exploratory XML. No Android execution."""
import argparse, hashlib, json, os, subprocess, sys, time
from pathlib import Path
import xml.etree.ElementTree as ET

FIXTURE_SHA="e7f34d9e8225de7792ccd43481e83c6eef809496262b65018e2bfa4b629fe1f6"
REFERENCE_SHA="9dc1033ffc989b2a957e0999bb40d5c48d97117d89150a173141ae7cc7eff8d0"
JSON_SHA="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
NAMES=["legacy_unknown_is_not_observed_false","all_false_are_observed_explicit_values",
       "selected_true_is_preserved","checked_true_is_separate_from_selected","partial_unknown_tuples_are_rejected",
       "selection_facts_do_not_create_action_capability","changing_only_selection_changes_serialized_facts",
       "fixture_is_root_exploration_not_agent_evidence","actual_ctrip_single_trip_flag_retained",
       "actual_passengers_remain_text_facts_not_selection_inference"]
DEPS=["ObservedChildText.java","ObservedScrollActions.java","ObservedImeEnter.java","ObservedTargetLabels.java"]
LOCAL=Path("src/org/trillionnium/hepta/local")
TEST=Path("tests/native-app-facts")

def info(p):
    p=Path(p)
    if p.is_symlink() or not p.is_file():raise RuntimeError("direct regular input required: "+str(p))
    raw=p.read_bytes();return {"path":str(p),"bytes":len(raw),"sha256":hashlib.sha256(raw).hexdigest()}

def write(p,raw):
    p=Path(p);p.parent.mkdir(parents=True,exist_ok=True)
    with p.open("xb") as f:f.write(raw);f.flush();os.fsync(f.fileno())
    if p.read_bytes()!=raw:raise RuntimeError("readback differs")
    return info(p)

def extract_node(text):
    anchor="    public static final class Node {"
    if text.count(anchor)!=1:raise RuntimeError("unique actual Node class required")
    start=text.index(anchor);at=text.index("{",start);depth=0;mode="normal";quote=None;escaped=False
    while at<len(text):
        c=text[at];n=text[at+1] if at+1<len(text) else ""
        if mode=="line":
            if c=="\n":mode="normal"
        elif mode=="block":
            if c=="*" and n=="/":mode="normal";at+=1
        elif quote is not None:
            if escaped:escaped=False
            elif c=="\\":escaped=True
            elif c==quote:quote=None
        elif c=="/" and n=="/":mode="line";at+=1
        elif c=="/" and n=="*":mode="block";at+=1
        elif c in ("'",'"'):quote=c
        elif c=="{":depth+=1
        elif c=="}":
            depth-=1
            if depth==0:return text[start:at+1]
        at+=1
    raise RuntimeError("unterminated actual Node class")

def main():
    ap=argparse.ArgumentParser()
    for name in ("source","output","java-home","json-jar"):ap.add_argument("--"+name,type=Path,required=True)
    ap.add_argument("--dependency-source",type=Path,help="Only for explicit isolated overlay tests; default is complete current source")
    a=ap.parse_args();source=a.source.resolve(strict=True);deps=(a.dependency_source or a.source).resolve(strict=True)
    out=a.output.absolute();out.mkdir(parents=True,exist_ok=False)
    jhome=a.java_home.resolve(strict=True);java=jhome/"bin/java";javac=jhome/"bin/javac";jar=a.json_jar.resolve(strict=True)
    fixture=source/TEST/"fixtures/ctrip-869-flight-form.xml"
    reference=source/TEST/"reference/PhoneObservation-v64.java"
    paths=[source/LOCAL/"PhoneObservation.java",source/LOCAL/"HeptaAccessibilityService.java",
           *[deps/LOCAL/n for n in DEPS],source/TEST/"NativeSelectionFactsHostTest.java",
           source/TEST/"LegacyNodeSerialization.java",source/TEST/"stubs/android/graphics/Rect.java",
           fixture,reference,Path(__file__).resolve(),java,javac,jar]
    before=[info(p) for p in paths];steps=[]
    result={"schema":"hepta.native-selection-facts-host-gate.v1","all_pass":False,"input_before":before,
            "steps":steps,"dependency_source":str(deps),"isolated_overlay":deps!=source,
            "android_service_executed":False,"live_task_qualification":False}
    failed=None
    try:
        if info(jar)["sha256"]!=JSON_SHA or info(jar)["bytes"]!=78332:raise RuntimeError("fixed JSON jar differs")
        if info(fixture)["sha256"]!=FIXTURE_SHA or info(reference)["sha256"]!=REFERENCE_SHA:raise RuntimeError("historical original differs")
        tree=ET.fromstring(fixture.read_bytes());tabs=[];passengers={}
        for n in tree.iter("node"):
            if n.get("content-desc") in ("单程","往返","多程"):
                if any(n.get(k) not in ("true","false") for k in ("selected","checked","checkable")):raise RuntimeError("actual selection flags absent")
                tabs.append({"content_desc":n.get("content-desc"),"selected":n.get("selected")=="true",
                             "checked":n.get("checked")=="true","checkable":n.get("checkable")=="true"})
            rid=n.get("resource-id","").rsplit("/",1)[-1]
            if rid in ("tv_adult_count","tv_child_count","tv_baby_count"):
                if rid in passengers:raise RuntimeError("passenger role not unique")
                passengers[rid]=n.get("text")
        adapted={"schema":"hepta.root-exploration-selection-fixture.v1","xml_sha256":FIXTURE_SHA,
                 "hepta_task_authority":False,"node_refs_authentic":False,"trip_tabs":tabs,"passengers":passengers}
        adapter=write(out/"EXPLORATION-ADAPTER.json",(json.dumps(adapted,ensure_ascii=False,indent=2)+"\n").encode())
        result["fixture_adapter"]=adapter
        generated={}
        for label,path in (("current",source/LOCAL/"PhoneObservation.java"),("previous_v64",reference)):
            node=extract_node(path.read_text())
            package='package org.trillionnium.hepta.local;\nimport android.graphics.Rect;\nimport org.json.*;\n'
            generated[label]=write(out/label/"generated/org/trillionnium/hepta/local/PhoneObservation.java",
                                   (package+"public final class PhoneObservation {\n"+node+"\n}\n").encode())
            result.setdefault("actual_node_projections",{})[label]={"source":info(path),"span_sha256":hashlib.sha256(node.encode()).hexdigest(),"generated":generated[label]}
        def execute(name,argv):
            start=time.time_ns();stdout=out/(name+".stdout");stderr=out/(name+".stderr")
            with stdout.open("xb") as f,stderr.open("xb") as e:
                r=subprocess.run(argv,stdin=subprocess.DEVNULL,stdout=f,stderr=e,timeout=60,check=False)
                f.flush();e.flush();os.fsync(f.fileno());os.fsync(e.fileno())
            steps.append({"name":name,"argv":argv,"exit_code":r.returncode,"elapsed_ms":(time.time_ns()-start)//1000000,
                          "stdout":info(stdout),"stderr":info(stderr)})
            if r.returncode:raise RuntimeError(name+" failed")
        for label in ("current","previous_v64"):
            classes=out/label/"classes";classes.mkdir()
            files=[generated[label]["path"],str(source/TEST/"stubs/android/graphics/Rect.java"),
                   *[str(deps/LOCAL/n) for n in DEPS],str(source/TEST/"LegacyNodeSerialization.java")]
            if label=="current":files.append(str(source/TEST/"NativeSelectionFactsHostTest.java"))
            execute(label+"-javac",[str(javac),"--release","8","-encoding","UTF-8","-proc:none","-Xlint:all","-Werror",
                                   "-cp",str(jar),"-d",str(classes),*files])
            execute(label+"-legacy",[str(java),"-Xmx256m","-cp",str(classes)+os.pathsep+str(jar),
                                    "org.trillionnium.hepta.local.LegacyNodeSerialization"])
        if (out/"current-legacy.stdout").read_bytes()!=(out/"previous_v64-legacy.stdout").read_bytes():
            raise RuntimeError("actual legacy JSON changed")
        result["previous_v64_legacy_json_byte_identical"]=True
        execute("current-cases",[str(java),"-Xmx256m","-cp",str(out/"current/classes")+os.pathsep+str(jar),
                                 "org.trillionnium.hepta.local.NativeSelectionFactsHostTest",adapter["path"]])
        cases=json.loads((out/"current-cases.stdout").read_text())
        if cases.get("schema")!="hepta.native-selection-facts-host.v1" or cases.get("all_pass") is not True or cases.get("case_names")!=NAMES or cases.get("cases")!=len(NAMES):
            raise RuntimeError("case identity differs")
        result["cases"]=cases
        result["case_receipt"]=write(out/"CASES.json",(json.dumps(cases,ensure_ascii=False,indent=2)+"\n").encode())
        result["all_pass"]=True
    except BaseException as e:
        failed=e;result["error"]=type(e).__name__+": "+str(e)
    finally:
        after=[info(p) for p in paths];result["input_after"]=after;result["inputs_unchanged"]=before==after
        if before!=after:result["all_pass"]=False;result["error"]="inputs changed"
        saved=write(out/"RESULT.json",(json.dumps(result,ensure_ascii=False,indent=2)+"\n").encode())
        print(json.dumps({"result":saved,"all_pass":result["all_pass"],"inputs_unchanged":result["inputs_unchanged"],
                          "cases":result.get("cases"),"legacy_byte_identical":result.get("previous_v64_legacy_json_byte_identical")},ensure_ascii=False))
    return 0 if failed is None and result["all_pass"] else 1
if __name__=="__main__":sys.exit(main())
